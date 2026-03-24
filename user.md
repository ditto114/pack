# 유저리스트 정규화 로직

## 개요

`web/static/js/userlist.js`는 캡쳐된 패킷의 UTF-8 텍스트에서 접속 유저 정보(닉네임, 맵, 프로필 코드)를 추출합니다. 패킷 데이터는 정규화되지 않은 바이너리 혼합 텍스트이므로, 전처리(새니타이징) 후 정규식 기반으로 파싱합니다.

## 지원하는 패킷 포맷

두 가지 필드 순서를 모두 지원합니다.

| 포맷 | 필드 순서 | 예시 파일 |
|------|-----------|-----------|
| A | Exp → Name → Created → MapOnline → Map → CharOnline → Profile → Attacks | ex1.txt, ex2.txt |
| B | Map → Profile → MapOnline → CharOnline → ChannelOnline → Job → Exp → Created → Captcha → Buffs → Name → Attacks → Level | ex3.txt |

두 포맷의 공통점: **`Attacks` 키워드가 각 유저 블록의 끝에 위치**합니다.

## 처리 흐름

```
패킷 수신 → 새니타이징 → 버퍼 누적 → Attacks 분할 → 세그먼트별 파싱 → 중복 제거 → 렌더링
```

### 1단계: 새니타이징

```javascript
text.replace(/[^\uAC00-\uD7A3a-zA-Z0-9\s\n\r]/g, '-')
```

한글(가~힣), 영문, 숫자, 공백/개행을 제외한 모든 문자를 대시(`-`)로 치환합니다. 바이너리 노이즈(널 바이트, 제어문자 등)가 대시로 통일되어 이후 정규식에서 구분자 역할을 합니다.

### 2단계: 버퍼 누적

패킷은 조각 단위로 수신되므로, 유저 블록이 여러 패킷에 걸쳐 분할될 수 있습니다. 새니타이징된 텍스트를 버퍼에 누적하여 완전한 블록을 구성합니다.

- 버퍼 상한: 64KB (초과 시 뒷부분만 보존)

### 3단계: Attacks 분할

```javascript
const parts = buffer.split('Attacks');
buffer = parts.pop(); // 마지막 미완성 세그먼트는 버퍼에 보존
```

`Attacks` 키워드를 기준으로 분할하면 각 조각이 한 유저의 데이터를 포함합니다. 마지막 조각은 아직 `Attacks`가 도착하지 않은 미완성 데이터일 수 있으므로 버퍼에 남겨둡니다.

### 4단계: 세그먼트별 파싱

각 세그먼트에서 **필드 순서에 무관하게** 세 가지 정보를 독립 추출합니다.

#### 프로필 코드 (필수)

```javascript
/Profile[-\s]+([A-Za-z0-9]{5,6})(?![A-Za-z0-9])/
```

- `Profile` 키워드 뒤 구분자(대시/공백) 이후 5~6자리 영숫자 코드를 캡쳐
- 뒤에 추가 영숫자가 오지 않는지 부정 전방탐색으로 확인
- **프로필 코드가 없으면 유저 블록이 아닌 것으로 판단하여 건너뜀**

매칭 예시:
```
Profile------3PKJP--    → 3PKJP
Profile------O1f9vD--   → O1f9vD
```

#### 닉네임

```javascript
/(?<!Channel)Name[-\s]+([\uAC00-\uD7A3a-zA-Z0-9]+)/
```

- `Name` 키워드 앞에 `Channel`이 오지 않는지 부정 후방탐색으로 확인 (`ChannelName` 오탐 방지)
- 구분자 이후 한글/영문/숫자로 구성된 연속 토큰을 캡쳐

매칭 예시:
```
Name------zzl기------      → zzl기
Name--  ---활쟹이-         → 활쟹이
Name------김김영영빔빔--   → 김김영영빔빔
```

#### 맵 이름

```javascript
/Map(?!Online)[-\s]+([\s\S]+?)[-\s]{4,}(?:Profile|Cha)/
```

- `Map` 뒤에 `Online`이 오지 않는지 부정 전방탐색으로 확인 (`MapOnline` 오탐 방지)
- 구분자 이후 다음 키워드(`Profile` 또는 `CharOnline`의 `Cha`) 앞까지의 텍스트를 게으른(lazy) 방식으로 캡쳐
- 포맷 A에서는 `Map`과 `CharOnline` 사이, 포맷 B에서는 `Map`과 `Profile` 사이의 텍스트가 대상
- 키워드 앞 구분자가 4자 이상(`[-\s]{4,}`)이어야 매칭 — 맵 이름 내부의 단일 대시(예: `정거장-오르비스행`)를 구분자로 오인하지 않음

캡쳐 후 후처리:
```javascript
// 대시 → 공백, 연속 공백 제거
cleaned = captured.replace(/-+/g, ' ').replace(/\s+/g, ' ').trim();
// 한글로 시작하는 연속 토큰 추출
mapRun = cleaned.match(/([\uAC00-\uD7A3][\uAC00-\uD7A3a-zA-Z0-9 ]*)/);
```

매칭 예시:
```
Map------블루 와이번의 둥지------Profile   → 블루 와이번의 둥지
Map-\n-----정거장-오르비스행-------Profile → 정거장 오르비스행
Map--\t---리프레------Profile              → 리프레
```

### 5단계: 중복 제거

프로필 코드를 `Set`으로 관리하여 동일 유저의 중복 등록을 방지합니다.

```javascript
if (user.profile && !profileSet.has(user.profile)) {
  profileSet.add(user.profile);
  users.push(user);
}
```

### 6단계: 렌더링

추출된 유저 목록을 `#userlist-tbody` 테이블에 닉네임 | 맵 | 프로필 코드 3열로 표시합니다. 모든 값은 HTML 이스케이프 처리됩니다.

## 한계 및 주의사항

- 패킷 데이터가 극도로 손상된 경우 키워드 자체가 깨져 추출에 실패할 수 있음
- `Attacks` 키워드가 두 패킷에 걸쳐 분할되면 해당 블록은 다음 패킷 수신 시까지 처리 보류
- 맵 이름 내부에 4자 이상 연속 구분자가 포함된 경우 맵 이름이 잘릴 수 있음
- 버퍼 64KB 초과 시 앞부분이 잘리므로, 해당 구간의 미완성 블록은 유실됨
