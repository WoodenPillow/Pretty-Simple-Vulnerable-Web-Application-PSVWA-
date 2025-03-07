# Pretty-Simple-Vulnerable-Web-Application-PSVWA-

**Author**: Yap Ming Shen 
**Last Update**: March 07, 2025

## Overview
PSVWA is a Flask app demoing web vulnerabilities (XSS, SQL Injection, Command Injection, CSRF) in its vulnerable version (`vulnerable_app.py`) and fixes in its resolved version (`resolved_app.py`).

## Features
- Login: `admin` (admin123), `user` (user123).
- Tickets, Search, Commands (admin), Profile.

## Setup
1. Install: `pip install Flask`
2. Install dependencies: `pip install -r requirements.txt`
3. Uninstall dependencies `pip uninstall -r requirements.txt -y`
4. Run Vulnerable: `python Pretty Simple Vulnerable Web Application (PSVWA).py` (http://127.0.0.1:5000, "Vulnerable PSVWA")
5. Run Resolved: `python ResolvedPSVWA.py` (http://127.0.0.1:5888, "Resolved PSVWA")

## Vulnerabilities
- **XSS**: `<script>alert('XSS')</script>` runs.
- **SQL Injection**: `' OR '1'='1` lists users.
- **Command Injection**: `dir & echo BAD` executes.
- **CSRF**: External form changes password.

## Fixes
- XSS: Escaped output.
- SQL Injection: Parameterized queries.
- Command Injection: Denied, no output.
- CSRF: Token validation.

## Notes
- Reset: Delete `vuln_app.db`.
- For educational use.
