#!/usr/bin/env python3
# utils/session.py — Session state manager for BRTX

import uuid
from datetime import datetime


class Session:

    def __init__(self):
        self._id       = str(uuid.uuid4())[:8].upper()
        self._started  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._attempts: dict = {}
        self._history:  list = []
        self._reports:  int  = 0
        self._scans:    int  = 0

    def add_attempts(self, module: str, attempts: list):
        if module not in self._attempts:
            self._attempts[module] = []
        self._attempts[module].extend(attempts)
        self._scans += 1
        target = attempts[0].get("url", "—") if attempts else "—"
        self._history.append({
            "module": module,
            "target": target,
            "count":  len(attempts),
            "time":   datetime.now().strftime("%H:%M:%S"),
        })

    def get_all_attempts(self) -> dict:
        return dict(self._attempts)

    def get_history(self) -> list:
        return list(self._history)

    def increment_reports(self):
        self._reports += 1

    def get_stats(self) -> dict:
        total_attempts = sum(len(v) for v in self._attempts.values())
        return {
            "id":       self._id,
            "started":  self._started,
            "scans":    self._scans,
            "attempts": total_attempts,
            "reports":  self._reports,
        }
