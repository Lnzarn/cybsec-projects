Windows Event Log Analyzer (Python)

A lightweight Python tool for reading Windows Event Logs (Application, System, Security) using PyWin32. Supports forward or reverse reading and limits output using command-line options.

Features:

- Read logs from: Application, System, Security
- Forward or backward reading (--reverse)
- Limit number of events shown (--max)
- Displays key event details (ID, timestamp, category, source, message)
- Checks admin privileges and enables required security permissions

Requirements:
-Windows OS
-Python 3.8+
-PyWin32: pip install pywin32

Run as administrator.

Usage:
python loganalyzer.py --source Security --max 20 --reverse

Arguments:
-s, --source Log source (application, system, security)
-m, --max Max logs to display (default: 10)
-r, --reverse Read newest to oldest

Example
python loganalyzer.py -s system -m 5
