#!/usr/bin/env python3
"""Configuration vulnerability scanner.

Reads a server configuration file (INI format) and flags settings that are
known to be insecure. Each finding has a severity and a recommended fix.

Usage: python src/vuln_scanner.py samples/server_config.ini
"""
import configparser
import sys

# (section, key, check function, severity, message, recommendation)
CHECKS = [
    ("ssh", "PermitRootLogin", lambda v: v.lower() == "yes", "HIGH",
     "Root can log in over SSH", "Set PermitRootLogin to no"),
    ("ssh", "PasswordAuthentication", lambda v: v.lower() == "yes", "MEDIUM",
     "SSH allows password logins", "Use key-based authentication only"),
    ("ssh", "Port", lambda v: v == "22", "LOW",
     "SSH runs on the default port", "Consider a non-default port to reduce scan noise"),
    ("services", "telnet", lambda v: v.lower() == "enabled", "HIGH",
     "Telnet sends passwords in clear text", "Disable Telnet and use SSH"),
    ("services", "ftp", lambda v: v.lower() == "enabled", "MEDIUM",
     "FTP is unencrypted", "Replace FTP with SFTP"),
    ("password_policy", "min_length", lambda v: v.isdigit() and int(v) < 12, "MEDIUM",
     "Minimum password length is below 12", "Set min_length to 12 or more"),
    ("password_policy", "max_failed_attempts", lambda v: v.isdigit() and int(v) > 5, "MEDIUM",
     "Account lockout allows too many failed attempts", "Lock accounts after 5 failed attempts"),
    ("files", "shadow_permissions", lambda v: v not in ("600", "640"), "HIGH",
     "/etc/shadow permissions are too open", "chmod 640 /etc/shadow"),
]

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def scan(path):
    """Return a list of findings for the given configuration file."""
    config = configparser.ConfigParser()
    config.optionxform = str  # keep key names as written
    if not config.read(path):
        raise FileNotFoundError(path)
    findings = []
    for section, key, is_bad, severity, message, fix in CHECKS:
        value = config.get(section, key, fallback=None)
        if value is not None and is_bad(value.strip()):
            findings.append((severity, f"[{section}] {key} = {value}", message, fix))
    return sorted(findings, key=lambda f: SEVERITY_ORDER[f[0]])


def main():
    if len(sys.argv) != 2:
        print("Usage: python src/vuln_scanner.py <config.ini>")
        sys.exit(1)
    findings = scan(sys.argv[1])
    print("=== Vulnerability Scan Report ===")
    print(f"Findings: {len(findings)}")
    for severity, setting, message, fix in findings:
        print(f"  [{severity:<6}] {setting}")
        print(f"           Issue: {message}")
        print(f"           Fix:   {fix}")
    sys.exit(1 if any(f[0] == "HIGH" for f in findings) else 0)


if __name__ == "__main__":
    main()
