"""패킷 캡쳐 UI 애플리케이션."""

from __future__ import annotations

import tkinter as tk

from capture_app import PacketCaptureApp
from capture_app.friend_services import (
    extract_entries_from_friends_page,
    extract_friend_codes_from_profile,
    extract_world_matches_from_html,
    fetch_friend_statuses,
    find_friend_by_world_code,
    find_ppsn,
    get_initial_friends,
    iter_friend_pages,
)
from capture_app.network import fetch_html


def main() -> None:
    root = tk.Tk()
    app = PacketCaptureApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
