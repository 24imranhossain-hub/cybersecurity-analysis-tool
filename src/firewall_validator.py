#!/usr/bin/env python3
"""Firewall rule validator.

Reads firewall rules from a CSV file and reports:
  * syntax errors (bad action, protocol, IP address or port)
  * duplicate rules
  * risky rules that allow ANY source to a sensitive port

CSV columns: rule_id,action,protocol,source,destination,port
Usage: python src/firewall_validator.py samples/firewall_rules.csv
"""
import csv
import ipaddress
import sys

VALID_ACTIONS = {"allow", "deny"}
VALID_PROTOCOLS = {"tcp", "udp", "icmp", "any"}
SENSITIVE_PORTS = {22: "SSH", 23: "Telnet", 445: "SMB", 3306: "MySQL", 3389: "RDP"}


def valid_address(value):
    """Return True for 'any' or a valid IPv4/IPv6 address or network."""
    if value.lower() == "any":
        return True
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def valid_port(value):
    """Return True for 'any' or a port number between 1 and 65535."""
    if value.lower() == "any":
        return True
    return value.isdigit() and 1 <= int(value) <= 65535


def validate_rules(path):
    """Check every rule in the CSV file and return (errors, warnings)."""
    errors, warnings, seen = [], [], {}
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            rid = row["rule_id"].strip()
            action = row["action"].strip().lower()
            proto = row["protocol"].strip().lower()
            src = row["source"].strip()
            dst = row["destination"].strip()
            port = row["port"].strip()

            if action not in VALID_ACTIONS:
                errors.append(f"Rule {rid}: invalid action '{action}'")
            if proto not in VALID_PROTOCOLS:
                errors.append(f"Rule {rid}: invalid protocol '{proto}'")
            for label, addr in (("source", src), ("destination", dst)):
                if not valid_address(addr):
                    errors.append(f"Rule {rid}: invalid {label} address '{addr}'")
            if not valid_port(port):
                errors.append(f"Rule {rid}: invalid port '{port}'")

            key = (action, proto, src, dst, port)
            if key in seen:
                warnings.append(f"Rule {rid}: duplicate of rule {seen[key]}")
            else:
                seen[key] = rid

            if (action == "allow" and src.lower() == "any"
                    and port.isdigit() and int(port) in SENSITIVE_PORTS):
                service = SENSITIVE_PORTS[int(port)]
                warnings.append(f"Rule {rid}: allows ANY source to {service} (port {port})")
    return errors, warnings


def main():
    if len(sys.argv) != 2:
        print("Usage: python src/firewall_validator.py <rules.csv>")
        sys.exit(1)
    errors, warnings = validate_rules(sys.argv[1])
    print("=== Firewall Rule Validation Report ===")
    print(f"Errors:   {len(errors)}")
    for err in errors:
        print(f"  [ERROR] {err}")
    print(f"Warnings: {len(warnings)}")
    for warn in warnings:
        print(f"  [WARN]  {warn}")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
