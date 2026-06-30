#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BRTX - Brute Force & Credential Tester
Author: NeiveZ | github.com/NeiveZ/BRTX
For authorized security testing only.
"""

import cmd
import sys
import os
import json
import shutil
from datetime import datetime

from utils.colors import Colors, print_status
from utils.session import Session

from modules.http_brute  import HTTPBrute
from modules.ssh_brute   import SSHBrute
from modules.ftp_brute   import FTPBrute
from modules.smb_brute   import SMBBrute
from modules.report_gen  import ReportGenerator


class BRTXShell(cmd.Cmd):
    """Interactive shell for BRTX."""

    intro  = ""
    prompt = f"{Colors.BOLD}{Colors.RED}brtx{Colors.RESET} {Colors.WHITE}>{Colors.RESET} "

    def __init__(self):
        super().__init__()
        self.session = Session()
        self.modules = {
            "brute/http": HTTPBrute,
            "brute/ssh":  SSHBrute,
            "brute/ftp":  FTPBrute,
            "brute/smb":  SMBBrute,
        }
        self.active_module      = None
        self.active_module_name = None
        self._show_header()

    # ── Header ────────────────────────────────────────────────────

    def _show_header(self):
        stats = self.session.get_stats()
        print(f"\n  {Colors.BOLD}{Colors.RED}BRTX{Colors.RESET}  "
              f"{Colors.DARK_GRAY}Brute Force & Credential Tester{Colors.RESET}  "
              f"{Colors.WHITE}v1.0.0{Colors.RESET}")
        print(f"  {Colors.DARK_GRAY}Author: NeiveZ  |  For authorized testing only{Colors.RESET}")
        print(f"  {Colors.DARK_GRAY}Scans: {Colors.WHITE}{stats['scans']}"
              f"  {Colors.DARK_GRAY}Found: {Colors.WHITE}{stats['attempts']}"
              f"  {Colors.DARK_GRAY}Reports: {Colors.WHITE}{stats['reports']}{Colors.RESET}")
        print(f"\n  {Colors.DARK_GRAY}Type {Colors.CYAN}help{Colors.DARK_GRAY} "
              f"to list commands.{Colors.RESET}\n")

    def _update_prompt(self):
        if self.active_module_name:
            self.prompt = (
                f"{Colors.BOLD}{Colors.RED}brtx{Colors.RESET}"
                f"{Colors.DARK_GRAY}({Colors.RESET}"
                f"{Colors.YELLOW}{self.active_module_name}{Colors.RESET}"
                f"{Colors.DARK_GRAY}){Colors.RESET} "
                f"{Colors.WHITE}>{Colors.RESET} "
            )
        else:
            self.prompt = f"{Colors.BOLD}{Colors.RED}brtx{Colors.RESET} {Colors.WHITE}>{Colors.RESET} "

    def default(self, line):
        print_status(f"Unknown command: '{line}'. Type 'help'.", "error")

    def emptyline(self):
        pass

    # ── Core Commands ─────────────────────────────────────────────

    def do_use(self, module_name):
        """Load a module.\n  Usage: use <module>"""
        module_name = module_name.strip()
        if not module_name:
            print_status("Usage: use <module_name>", "warn")
            return
        if module_name not in self.modules:
            print_status(f"Module '{module_name}' not found. Run 'show modules'.", "error")
            return
        self.active_module_name = module_name
        self.active_module = self.modules[module_name]()
        self._update_prompt()
        print_status(f"Module loaded: {Colors.YELLOW}{module_name}{Colors.RESET}", "ok")
        print()
        self.active_module.show_info()

    def do_set(self, args):
        """Set a module option.\n  Usage: set <OPTION> <value>"""
        if not self.active_module:
            print_status("No module loaded.", "warn")
            return
        parts = args.strip().split(None, 1)
        if len(parts) < 2:
            print_status("Usage: set <OPTION> <value>", "warn")
            return
        opt, val = parts[0].upper(), parts[1]
        if self.active_module.set_option(opt, val):
            print_status(f"{Colors.CYAN}{opt}{Colors.RESET} => {Colors.WHITE}{val}{Colors.RESET}", "ok")
        else:
            print_status(f"Unknown option: {opt}. Run 'options'.", "error")

    def do_run(self, _):
        """Execute the loaded module.\n  Usage: run"""
        if not self.active_module:
            print_status("No module loaded.", "warn")
            return
        print()
        try:
            results = self.active_module.run()
            if results:
                self.session.add_findings(self.active_module_name, results)
                self._auto_save(results)
        except KeyboardInterrupt:
            print()
            print_status("Attack interrupted by user.", "warn")
        except Exception as e:
            print_status(f"Module error: {e}", "error")

    def do_options(self, _):
        """Show module options.\n  Usage: options"""
        if not self.active_module:
            print_status("No module loaded.", "warn")
            return
        self.active_module.show_options()

    def do_info(self, _):
        """Show module info.\n  Usage: info"""
        if not self.active_module:
            print_status("No module loaded.", "warn")
            return
        self.active_module.show_info()

    def do_back(self, _):
        """Unload current module.\n  Usage: back"""
        if self.active_module:
            print_status(f"Unloaded: {self.active_module_name}", "info")
            self.active_module      = None
            self.active_module_name = None
            self._update_prompt()
        else:
            print_status("No module loaded.", "warn")

    # ── Show Commands ─────────────────────────────────────────────

    def do_show(self, args):
        """Show modules, results, or session.\n  Usage: show modules | results | session"""
        arg = args.strip().lower()
        if arg == "modules":
            self._show_modules()
        elif arg in ("results", "findings", "creds"):
            self._show_results()
        elif arg in ("session", "sessions"):
            self._show_session()
        else:
            print_status("Usage: show [modules|results|session]", "warn")

    def _show_modules(self):
        col_w = shutil.get_terminal_size((80, 20)).columns
        print(f"\n  {Colors.BOLD}{Colors.WHITE}Available Modules{Colors.RESET}\n")
        print(f"  {'─' * (col_w - 4)}")
        print(f"{Colors.DARK_GRAY}  {'Name':<18} {'Protocol':<12} Description{Colors.RESET}")
        print(f"  {'─' * (col_w - 4)}")
        info = {
            "brute/http": ("HTTP/S",   "Login form brute force — field detection + rate limiting"),
            "brute/ssh":  ("SSH",      "SSH credential brute force via paramiko"),
            "brute/ftp":  ("FTP",      "FTP credential brute force"),
            "brute/smb":  ("SMB/445",  "SMB credential brute force via smbclient"),
        }
        for name, (proto, desc) in info.items():
            print(f"  {Colors.CYAN}{name:<18}{Colors.RESET}"
                  f"{Colors.DARK_GRAY}{proto:<12}{Colors.RESET}"
                  f"{Colors.WHITE}{desc}{Colors.RESET}")
        print(f"  {'─' * (col_w - 4)}\n")

    def _show_results(self):
        all_results = self.session.get_all_findings()
        if not all_results:
            print_status("No credentials found yet.", "warn")
            return
        print(f"\n  {Colors.BOLD}{Colors.WHITE}Found Credentials{Colors.RESET}\n")
        for module, results in all_results.items():
            print(f"  {Colors.YELLOW}[{module}]{Colors.RESET}")
            for r in results:
                print(f"    {Colors.GREEN}[VALID]{Colors.RESET} "
                      f"{Colors.WHITE}{r.get('username','')}:{r.get('password','')}{Colors.RESET}  "
                      f"{Colors.DARK_GRAY}{r.get('target','')}{Colors.RESET}")
            print()

    def _show_session(self):
        stats = self.session.get_stats()
        print(f"\n  {Colors.BOLD}{Colors.WHITE}Session{Colors.RESET}\n")
        print(f"  {Colors.DARK_GRAY}Session ID {Colors.RESET}: {Colors.CYAN}{stats['id']}{Colors.RESET}")
        print(f"  {Colors.DARK_GRAY}Started    {Colors.RESET}: {stats['started']}")
        print(f"  {Colors.DARK_GRAY}Scans      {Colors.RESET}: {Colors.WHITE}{stats['scans']}{Colors.RESET}")
        print(f"  {Colors.DARK_GRAY}Creds Found{Colors.RESET}: {Colors.WHITE}{stats['attempts']}{Colors.RESET}")
        print(f"  {Colors.DARK_GRAY}Reports    {Colors.RESET}: {Colors.WHITE}{stats['reports']}{Colors.RESET}\n")

    # ── Report ────────────────────────────────────────────────────

    def do_report(self, args):
        """Generate report.\n  Usage: report [json|txt|html] [filename]"""
        parts = args.strip().split()
        fmt   = parts[0].lower() if parts else "txt"
        fname = parts[1] if len(parts) > 1 else None
        results = self.session.get_all_findings()
        if not results:
            print_status("No results to report.", "warn")
            return
        gen  = ReportGenerator(results, self.session.get_stats())
        path = gen.generate(fmt=fmt, filename=fname)
        if path:
            self.session.increment_reports()
            print_status(f"Report saved: {Colors.CYAN}{path}{Colors.RESET}", "ok")

    def _auto_save(self, results):
        os.makedirs("reports", exist_ok=True)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = f"reports/auto_{self.active_module_name.replace('/', '_')}_{ts}.json"
        try:
            with open(path, "w") as f:
                json.dump({
                    "module":    self.active_module_name,
                    "timestamp": ts,
                    "results":   results,
                }, f, indent=2, default=str)
        except Exception:
            pass

    # ── Utility ───────────────────────────────────────────────────

    def do_clear(self, _):
        """Clear screen."""
        os.system("clear")
        self._show_header()

    def do_exit(self, _):
        """Exit BRTX."""
        print(f"\n  {Colors.DARK_GRAY}Goodbye. Stay ethical.{Colors.RESET}\n")
        return True

    def do_quit(self, _):
        return self.do_exit(_)

    def do_help(self, arg):
        if arg:
            super().do_help(arg)
            return
        print(f"""
  {Colors.BOLD}{Colors.WHITE}Core Commands{Colors.RESET}
  {'─'*40}
  {Colors.CYAN}use <module>{Colors.RESET}            Load a module
  {Colors.CYAN}set <OPTION> <value>{Colors.RESET}    Set option
  {Colors.CYAN}run{Colors.RESET}                     Execute module
  {Colors.CYAN}options{Colors.RESET}                 Show options
  {Colors.CYAN}info{Colors.RESET}                    Module info
  {Colors.CYAN}back{Colors.RESET}                    Unload module

  {Colors.BOLD}{Colors.WHITE}Show{Colors.RESET}
  {'─'*40}
  {Colors.CYAN}show modules{Colors.RESET}            List modules
  {Colors.CYAN}show results{Colors.RESET}            Found credentials
  {Colors.CYAN}show session{Colors.RESET}            Session info

  {Colors.BOLD}{Colors.WHITE}Output{Colors.RESET}
  {'─'*40}
  {Colors.CYAN}report [json|txt|html]{Colors.RESET}  Generate report

  {Colors.BOLD}{Colors.WHITE}Utility{Colors.RESET}
  {'─'*40}
  {Colors.CYAN}clear{Colors.RESET}                   Clear screen
  {Colors.CYAN}exit{Colors.RESET}                    Exit BRTX
""")


def main():
    try:
        shell = BRTXShell()
        shell.cmdloop()
    except KeyboardInterrupt:
        print(f"\n\n  {Colors.DARK_GRAY}Interrupted. Goodbye.{Colors.RESET}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
