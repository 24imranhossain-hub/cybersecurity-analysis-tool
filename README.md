# Cybersecurity Analysis Tool

A small Python toolkit that helps security analysts review logs, check systems for insecure settings and validate firewall rules before they are deployed. This repository was built for the **Version Control and Issue Tracking** assignment (NSA-590, MITT) to practise GitHub version control and Freshworks (Freshservice) issue tracking on a real security project.

## Features

| Module | Branch | What it does |
|---|---|---|
| Log analysis | `feature/log-analysis` | Parses Linux auth logs and flags failed logins and possible brute-force attacks |
| Vulnerability scan | `feature/vulnerability-scan` | Checks a system configuration file for insecure settings (root SSH login, weak password policy, Telnet enabled) |
| Firewall configuration | `feature/firewall-configuration` | Validates firewall rules for correct syntax, duplicate rules and risky "allow any" rules |

## Repository structure

```
cybersecurity-analysis-tool/
├── src/              # Python scripts for each tool
├── samples/          # Sample log, config and firewall rule files for testing
├── .github/          # Pull request template
├── CONTRIBUTING.md   # How to contribute (branches, commits, PRs)
└── README.md
```

## Setup instructions

1. Install **Python 3.10+** and **Git**.
2. Clone the repository:
   ```bash
   git clone https://github.com/24imranhossain-hub/cybersecurity-analysis-tool.git
   cd cybersecurity-analysis-tool
   ```
3. Switch to the development branch to get the latest features:
   ```bash
   git checkout development
   ```
4. Run a tool against the sample data, for example:
   ```bash
   python src/log_analyzer.py samples/sample_auth.log
   python src/firewall_validator.py samples/firewall_rules.csv
   python src/vuln_scanner.py samples/server_config.ini
   ```

No third-party packages are needed; every script uses the Python standard library only.

## Branching strategy

| Branch | Purpose |
|---|---|
| `main` | Stable production code. Updated only by a pull request from `development`. |
| `development` | Integration branch where finished features are merged and tested. |
| `feature/<name>` | One branch per feature or fix, created from `development` (e.g. `feature/log-analysis`). |

## Commit message convention

```
<type>(<scope>): <short summary> [ticket ID]
```

Types: `feat`, `fix`, `docs`, `test`, `chore`.
Example: `feat(firewall): add duplicate rule detection [#SR-1]`

## Pull request process

1. Push the feature branch to GitHub.
2. Open a pull request into `development` and fill in the PR template (summary, changes, testing, linked ticket).
3. A reviewer checks the code and leaves comments.
4. After approval the PR is merged and the feature branch is deleted.
5. When `development` is stable, a release PR merges it into `main`.

## Issue tracking process (Freshworks)

All work is tracked in the Freshservice project **Cybersecurity Analysis Tool**.

1. Create a ticket for every feature or bug with a clear description, requirements or steps to reproduce, and a priority.
2. Assign the ticket to a team member.
3. Move the ticket to **In Progress** when work starts on its feature branch.
4. Put the ticket ID in every related commit message and pull request.
5. Add a note with the pull request link, then set the ticket to **Resolved** after the PR is merged.

## Author

Imran Hossain, Network and Systems Administration, MITT
