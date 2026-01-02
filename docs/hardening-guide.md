# Windows 11 CIS Hardening Guide with Wazuh

## Setup Overview
1. Wazuh manager in Docker on Lubuntu VM.
2. Installed Wazuh agent on Windows 11.
3. Configured SCA for CIS Windows 11 benchmark.

## Initial Findings
- 332 failed checks across categories: Password Policy, Account Lockout, Auditing, Services, etc.

## Remediation Strategy
- Grouped failures by type.
- Wrote PowerShell scripts using:
  - `secedit` for security policies
  - Registry edits via `Set-ItemProperty`
  - `auditpol` for auditing
  - Service management with `Set-Service`



## Verification
- Re-ran SCA scan → 100% passed.
<img width="1341" height="449" alt="Screenshot 2025-12-31 162224" src="https://github.com/user-attachments/assets/2178741c-0a51-4b3f-9828-8e1b7f545669" />

## Lessons Learned
- Many defaults are insecure for enterprise.
- Automation saves hours vs manual GUI fixes.
