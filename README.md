# Wazuh-Powered Windows 11 Hardening: 332 → 0 CIS Failures

[![Wazuh](https://img.shields.io/badge/Wazuh-SIEM-blue)](https://wazuh.com/)
[![PowerShell](https://img.shields.io/badge/PowerShell-Automation-yellow)](https://learn.microsoft.com/powershell/)
[![CIS Benchmark](https://img.shields.io/badge/CIS-100%25_Compliant-green)](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)

**From vulnerable defaults to fully hardened: Remediated 332 CIS Level 1/2 misconfigurations on Windows 11 using Wazuh SCA and custom PowerShell automation.**

## Project Overview
Deployed a Wazuh agent on a Windows 11 host (monitored via Dockerized Wazuh manager in Lubuntu VM). Ran Security Configuration Assessment (SCA) against CIS Microsoft Windows 11 benchmarks:
- Initial scan: **332 failed policies** (common defaults like weak passwords, disabled auditing, unnecessary services).
- No vulnerabilities, malware, or rootkits detected.
- Developed PowerShell scripts to automatically remediate **all 332 failures**.
- Re-scanned: **100% compliance achieved**.

This project demonstrates end-to-end endpoint hardening, compliance automation, and blue team skills.

## Key Results
![Wazuh Dashboard](Report/Vulnerability_and_SCA_Result.png)

- Reduced attack surface significantly.
- Automated fixes for categories: Account Policies, Auditing, User Rights, Services, Firewall, etc.

## Tech Stack
- Wazuh (SCA module)
- PowerShell 7+
- Windows 11
- Docker (for Wazuh manager)
- VMware + Lubuntu VM

## Setup & Reproduction
1. Install Wazuh manager (Docker Compose example in docs/).
2. Deploy agent on Windows 11.
3. Run initial SCA scan.
4. Execute `scripts/remediation_script_*.ps1`.
5. Re-scan to verify.

Detailed guide: [docs/hardening-guide.md](docs/hardening-guide.md)

## Reports & Scripts
- Reports: [/reports](Report/)
- Remediation Scripts: [/scripts](scripts/)

## Future Improvements
- Integrate with Intune for enterprise deployment.
- Add alerting for drift detection.


⭐ Star if you found this useful!    

→ LinkedIn: [linkedin.com/in/fadilahmad47](https://linkedin.com/in/fadilahmad47)    

Questions? Open an issue!
