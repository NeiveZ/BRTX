#!/usr/bin/env python3
# modules/base.py — Abstract base class for all BRTX modules

from abc import ABC, abstractmethod
from utils.colors import Colors, print_table, print_section


class BaseModule(ABC):

    NAME:        str  = "base"
    DESCRIPTION: str  = ""
    AUTHOR:      str  = "NeiveZ"
    PROTOCOL:    str  = ""
    REFERENCES:  list = []

    def __init__(self):
        self.options: dict = {}
        self._define_options()

    @abstractmethod
    def _define_options(self):
        ...

    @abstractmethod
    def run(self) -> list:
        """Execute brute force. Returns list of valid credential dicts."""
        ...

    # ── Option helpers ────────────────────────────────────────────

    def _add_option(self, name: str, default, required: bool, description: str):
        self.options[name.upper()] = {
            "value":    default,
            "required": required,
            "desc":     description,
        }

    def set_option(self, name: str, value: str) -> bool:
        if name.upper() not in self.options:
            return False
        self.options[name.upper()]["value"] = value
        return True

    def get_option(self, name: str):
        return self.options.get(name.upper(), {}).get("value")

    def _validate(self) -> bool:
        for name, meta in self.options.items():
            if meta["required"] and not meta["value"]:
                from utils.colors import print_status
                print_status(f"Required option not set: {Colors.CYAN}{name}{Colors.RESET}", "error")
                return False
        return True

    def _credential(self, target: str, username: str, password: str,
                    protocol: str = "", extra: dict = None) -> dict:
        """Build a standardized credential result dict."""
        result = {
            "target":   target,
            "username": username,
            "password": password,
            "protocol": protocol or self.PROTOCOL,
        }
        if extra:
            result.update(extra)
        return result

    # ── Display helpers ───────────────────────────────────────────

    def show_options(self):
        print_section(f"Options — {self.NAME}")
        rows = [
            (
                name,
                str(meta["value"]) if meta["value"] else Colors.DARK_GRAY + "unset" + Colors.RESET,
                "yes" if meta["required"] else "no",
                meta["desc"],
            )
            for name, meta in self.options.items()
        ]
        print_table(["Option", "Value", "Required", "Description"], rows)

    def show_info(self):
        print_section(f"Module — {self.NAME}")
        print(f"  {Colors.DARK_GRAY}Name       {Colors.RESET}: {Colors.WHITE}{self.NAME}{Colors.RESET}")
        print(f"  {Colors.DARK_GRAY}Description{Colors.RESET}: {self.DESCRIPTION}")
        print(f"  {Colors.DARK_GRAY}Protocol   {Colors.RESET}: {Colors.CYAN}{self.PROTOCOL}{Colors.RESET}")
        print(f"  {Colors.DARK_GRAY}Author     {Colors.RESET}: {self.AUTHOR}")
        if self.REFERENCES:
            print(f"  {Colors.DARK_GRAY}References {Colors.RESET}:")
            for ref in self.REFERENCES:
                print(f"    {Colors.CYAN}{ref}{Colors.RESET}")
        print()
        self.show_options()
