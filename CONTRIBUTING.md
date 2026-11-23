# Contributing Guide

Thank you for helping improve the Cybersecurity Analysis Tool. Please follow these rules so the history stays clean and every change can be traced to a Freshservice ticket.

## 1. Pick or create a ticket
Every change starts with a ticket in the Freshservice project **Cybersecurity Analysis Tool**. Assign it to yourself and set it to **In Progress**.

## 2. Create a feature branch from development
```bash
git checkout development
git pull origin development
git checkout -b feature/<short-name>
```

## 3. Commit small, clear changes
Use the format `<type>(<scope>): <summary> [ticket ID]`, for example:
- `feat(log-analysis): detect brute-force login attempts [#SR-2]`
- `fix(firewall): reject rules with invalid port numbers [#SR-1]`
- `docs(readme): add usage example for vuln scanner [#SR-3]`

## 4. Push and open a pull request
```bash
git push -u origin feature/<short-name>
```
Open a PR into `development`, fill in every section of the template and link the ticket.

## 5. Review and merge
At least one review comment is required before merging. After merge, delete the feature branch and set the ticket to **Resolved** with a link to the PR.

## Security note
Never commit passwords, API keys or real customer log files. Use the files in `samples/` for testing.
