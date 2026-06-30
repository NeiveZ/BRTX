# BRTX

> Brute Force & Credential Tester — modular credential attack framework with Metasploit-style interactive shell.

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-557C94?style=flat-square&logo=kalilinux&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## Overview

BRTX is a modular credential testing framework built around an **interactive shell interface** — load a module, configure the target, run. Covers HTTP login forms, SSH, FTP, and SMB in a single unified tool. Valid credentials are stored in session memory and exportable as TXT, JSON, or HTML reports.

---

## Modules

| Module | Protocol | Description |
|---|---|---|
| `brute/http` | HTTP/S | Login form brute force — auto-detects fields and hidden tokens |
| `brute/ssh` | SSH | SSH credential brute force via paramiko |
| `brute/ftp` | FTP | FTP credential brute force via Python ftplib |
| `brute/smb` | SMB/445 | SMB credential brute force via smbclient |

---

## Features

- **Interactive shell** — `use`, `set`, `run`, `back` workflow identical to Metasploit
- **HTTP form auto-detection** — detects username/password field names and hidden CSRF tokens automatically
- **Custom wordlists** — pass any file with `-w` or use built-in credential lists
- **Rate limiting** — configurable delay between attempts to avoid lockouts
- **Session persistence** — found credentials accumulate across modules
- **Report generation** — TXT, JSON, or HTML
- **Auto-save** — every scan auto-saves findings to `reports/` as JSON

---

## Requirements

| Dependency | Purpose | Install |
|---|---|---|
| `python 3.10+` | Runtime | `apt install python3` |
| `paramiko` | SSH module | `pip install paramiko` |
| `smbclient` | SMB module | `apt install smbclient` |

```bash
# All at once
sudo apt install python3 smbclient
pip install paramiko --break-system-packages
```

HTTP and FTP modules require no external dependencies.

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/NeiveZ/BRTX.git
cd BRTX
```

### 2. Make executable

```bash
chmod +x brtx.sh
```

### 3. Install dependencies

```bash
./brtx.sh --install
```

### 4. Launch

```bash
./brtx.sh
```

---

## Usage

```
brtx > use <module>
brtx > set <OPTION> <value>
brtx > run
```

### Core commands

```
use <module>            Load a module
set <OPTION> <value>    Set a module option
run                     Execute the loaded module
options                 Show current module options
info                    Show module description and options
back                    Unload current module

show modules            List all available modules
show results            View found credentials
show session            Session statistics

report [txt|json|html]  Export results to a report file
clear                   Clear the screen
exit                    Quit BRTX
```

---

## Examples

**HTTP login form — auto-detect fields:**
```
brtx > use brute/http
brtx (brute/http) > set TARGET https://site.com/login
brtx (brute/http) > set PASSLIST /usr/share/wordlists/rockyou.txt
brtx (brute/http) > run
```

**HTTP with known username and custom success string:**
```
brtx > use brute/http
brtx (brute/http) > set TARGET https://site.com/login
brtx (brute/http) > set USERNAME admin
brtx (brute/http) > set SUCCESS dashboard
brtx (brute/http) > run
```

**SSH brute force:**
```
brtx > use brute/ssh
brtx (brute/ssh) > set TARGET 192.168.1.10
brtx (brute/ssh) > set USERNAME root
brtx (brute/ssh) > set PASSLIST /usr/share/wordlists/rockyou.txt
brtx (brute/ssh) > run
```

**FTP brute force:**
```
brtx > use brute/ftp
brtx (brute/ftp) > set TARGET 192.168.1.10
brtx (brute/ftp) > set USERLIST users.txt
brtx (brute/ftp) > set PASSLIST passwords.txt
brtx (brute/ftp) > run
```

**SMB brute force with domain:**
```
brtx > use brute/smb
brtx (brute/smb) > set TARGET 192.168.1.10
brtx (brute/smb) > set DOMAIN WORKGROUP
brtx (brute/smb) > set USERNAME administrator
brtx (brute/smb) > set PASSLIST /usr/share/wordlists/rockyou.txt
brtx (brute/smb) > run
```

**Generate report after finding credentials:**
```
brtx > report html results
brtx > report txt results
```

---

## Output

```
brtx (brute/ssh) > run

── SSH Brute Force — 192.168.1.10:22 ───────────────────

[*] Usernames : 8
[*] Passwords : 8

  [    1/64] root                password             [FAIL]
  [    2/64] root                123456               [FAIL]
  [    3/64] root                toor                 [FAIL]

  [VALID] root:toor @ 192.168.1.10:22

[+] Found 1 valid credential(s).
```

---

## Module Options Reference

### brute/http

| Option | Default | Description |
|---|---|---|
| `TARGET` | — | Login page URL |
| `USER_FIELD` | `username` | Username field name (auto-detected if blank) |
| `PASS_FIELD` | `password` | Password field name (auto-detected if blank) |
| `USERNAME` | — | Single username to test |
| `USERLIST` | built-in | Path to username wordlist |
| `PASSLIST` | built-in | Path to password wordlist |
| `SUCCESS` | — | Custom string indicating successful login |
| `FAIL` | — | Custom string indicating failed login |
| `DELAY` | `0.5` | Delay between attempts in seconds |

### brute/ssh / brute/ftp

| Option | Default | Description |
|---|---|---|
| `TARGET` | — | Target IP or hostname |
| `PORT` | `22` / `21` | Service port |
| `USERNAME` | — | Single username |
| `USERLIST` | built-in | Path to username wordlist |
| `PASSLIST` | built-in | Path to password wordlist |
| `DELAY` | `0.3` | Delay between attempts |

### brute/smb

| Option | Default | Description |
|---|---|---|
| `TARGET` | — | Target IP or hostname |
| `DOMAIN` | `.` | Domain or workgroup |
| `SHARE` | `IPC$` | SMB share to authenticate against |
| `USERNAME` | — | Single username |
| `USERLIST` | built-in | Path to username wordlist |
| `PASSLIST` | built-in | Path to password wordlist |

---

## Repository Structure

```
BRTX/
├── brtx.py               # Interactive shell entry point
├── brtx.sh               # Bash launcher and installer
├── modules/
│   ├── base.py           # Abstract base class
│   ├── http_brute.py     # HTTP login form module
│   ├── ssh_brute.py      # SSH module
│   ├── ftp_brute.py      # FTP module (inside ssh_brute.py)
│   ├── smb_brute.py      # SMB module (inside ssh_brute.py)
│   └── report_gen.py     # Report generator
└── utils/
    ├── colors.py         # Terminal color and UI system
    └── session.py        # Session state manager
```

---

## Legal

For use only on systems you own or have explicit written authorization to test.
Unauthorized use against third-party systems is illegal.
