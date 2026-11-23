"""Run all three security checks on the sample data in one command."""
import subprocess
import sys

CHECKS = [
    ("Log analysis", ["src/log_analyzer.py", "samples/sample_auth.log"]),
    ("Firewall validation", ["src/firewall_validator.py", "samples/firewall_rules.csv"]),
    ("Vulnerability scan", ["src/vuln_scanner.py", "samples/server_config.ini"]),
]

for name, args in CHECKS:
    print(f"\n########## {name} ##########")
    subprocess.run([sys.executable, *args])
