/**
 * WebSocket 클라이언트 매니저
 */
const WS = (() => {
  const BASE = `ws://${location.host}`;
  const connections = {};

  function connect(path, { onMessage, onOpen, onClose } = {}) {
    if (connections[path] && connections[path].readyState <= 1) {
      return connections[path];
    }

    const ws = new WebSocket(BASE + path);
    connections[path] = ws;

    ws.onopen = () => {
      console.log(`[WS] connected: ${path}`);
      if (onOpen) onOpen(ws);
    };

    ws.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        if (onMessage) onMessage(data, ws);
      } catch (err) {
        console.error('[WS] parse error:', err);
      }
    };

    ws.onclose = () => {
      console.log(`[WS] closed: ${path}`);
      delete connections[path];
      if (onClose) onClose();
      // auto-reconnect after 2s
      setTimeout(() => connect(path, { onMessage, onOpen, onClose }), 2000);
    };

    ws.onerror = (err) => {
      console.error(`[WS] error: ${path}`, err);
    };

    return ws;
  }

  function send(path, data) {
    const ws = connections[path];
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(data));
    }
  }

  function close(path) {
    const ws = connections[path];
    if (ws) {
      ws.onclose = null; // prevent auto-reconnect
      ws.close();
      delete connections[path];
    }
  }

  return { connect, send, close };
})();
