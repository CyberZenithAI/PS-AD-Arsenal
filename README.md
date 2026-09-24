 # 🛡️ PS-AD-Arsenal

 ### Enterprise Active Directory Automation & Security Toolkit

 **PowerShell • Active Directory Domain Services • Security Hardening • Automation • Auditing • SecOps**

 \
 \
 \
 \
 \

---

 ## 📌 Overview

 **PS-AD-Arsenal** is a PowerShell-based toolkit for **Active Directory Domain Services (AD DS)** administration, security hardening, automation, auditing, and controlled security testing.

 The project follows a **Blue Team / Red Team mindset**, combining infrastructure automation with defensive security practices to help administrators and security practitioners build more consistent, auditable, and resilient Windows environments.

 The toolkit is intended for:

 - Active Directory administration
- Windows Server hardening
- Identity and Access Management (IAM)
- User and group provisioning
- Security auditing
- Honeypot and deception concepts
- PowerShell automation
- SecOps and security engineering laboratories
- Educational and controlled enterprise environments

 > **Project philosophy:** Automate repetitive administrative tasks, reduce configuration drift, increase visibility, and apply security controls consistently.

---

 ## 🎯 Project Goals

 PS-AD-Arsenal focuses on five core objectives:

 1. **Automate** repetitive Active Directory administration tasks.
2. **Harden** Windows and AD DS environments using documented security practices.
3. **Audit** configuration and administrative activity.
4. **Detect** suspicious interaction with controlled deception mechanisms.
5. **Document** infrastructure changes for operational and compliance purposes.

---

 ## ⚔️ Core Modules

 ### 🛡️ Module 01 — AD DS Hardening

 **Blue Team / Infrastructure Security**

 Automates selected security-hardening tasks for Windows Server and Active Directory environments.

 #### Capabilities

 - Configures selected password and account-lockout policies.
- Applies configurable security baselines.
- Disables legacy services or protocols when appropriate.
- Supports administrative account hardening.
- Performs configuration checks before applying changes.
- Generates execution and change logs.
- Designed for controlled testing before production deployment.

 #### Security Objective

 Reduce unnecessary attack surface and improve the security baseline of domain infrastructure.

 > **Important:** Hardening recommendations should be validated against organizational requirements and tested before production deployment.

---

 ### 🎣 Module 02 — Honeypot & Deception

 **Blue Team / Threat Detection**

 Provides controlled deception mechanisms designed to generate security telemetry when a monitored account or resource is accessed.

 #### Capabilities

 - Creates a dedicated monitored account or resource.
- Applies controlled auditing configurations.
- Generates security events when defined interactions occur.
- Supports integration with security monitoring workflows.
- Helps identify potentially suspicious internal activity.

 #### Security Objective

 Create additional detection opportunities for unauthorized access and lateral-movement activity.

 > **Operational note:** Honeypot accounts must be carefully isolated and monitored to avoid creating unnecessary security or operational risks.

---

 ### ⚙️ Module 03 — Mass Automation & Auditing

 **SysAdmin / DevOps / IAM**

 Automates repetitive Active Directory provisioning tasks while maintaining execution traceability.

 #### Capabilities

 - Bulk Organizational Unit creation.
- Bulk group creation.
- Bulk user provisioning from CSV.
- Group membership assignment.
- Role-Based Access Control (**RBAC**) workflows.
- Input validation.
- Error handling.
- Execution logging.
- Repeatable provisioning workflows.

 #### Security Objective

 Improve consistency and traceability during large-scale identity administration.

---

 ## 🏗️ Architecture

 Mermaid flowchart: CSV / Requirements, PowerShell Automation Engine, Module Selection, AD DS Hardening, Honeypot / Honey Token, Mass User Automation, Security & Configuration Audit, Security Baseline, Detection Telemetry, Identity Lifecycle, Audit Evidence, (Active Directory), SIEM / Monitoring, Backup & Recovery, Hybrid Identity

---

 ## 🔄 Operational Workflow

```
┌───────────────────────────────┐
│      Requirements / CSV       │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐
│    PowerShell Automation      │
│            Engine             │
└───────────────┬───────────────┘
                │
       ┌────────┼────────┐
       ▼        ▼        ▼
   Hardening  Deception  IAM
       │        │        │
       └────────┼────────┘
                ▼
┌───────────────────────────────┐
│      Active Directory         │
│             AD DS             │
└───────────────┬───────────────┘
                │
       ┌────────┼─────────┐
       ▼        ▼         ▼
    Auditing   SIEM     Backup
```

---

 ## 🔐 Security Principles

 PS-AD-Arsenal is designed around the following principles:

 - **Least Privilege**
- **Defense in Depth**
- **Secure by Default**
- **Identity-Centric Security**
- **Configuration Consistency**
- **Auditability**
- **Change Traceability**
- **Controlled Automation**
- **Separation of Administrative Responsibilities**

---

 ## 📜 Framework & Compliance Mapping

 The project can be used to support controls and practices related to:

 ### ISO/IEC 27001:2022

 Relevant areas may include:

 - Access control
- Identity management
- Authentication information
- Logging and monitoring
- Configuration management
- Operational security

 ### NIST

 Potential mappings include concepts related to:

 - **AC — Access Control**
- **IA — Identification and Authentication**
- **AU — Audit and Accountability**
- **CM — Configuration Management**
- **SI — System and Information Integrity**

 ### CIS Benchmarks

 The toolkit can complement configuration-hardening practices for supported Windows Server environments.

 ### 🇵🇪 Peru — Ley N.° 29733

 The project may support technical and organizational security practices related to protecting personal information when deployed as part of an appropriately designed organizational security program.

 > **Disclaimer:** PS-AD-Arsenal is not a certification or compliance product. Framework mappings are provided as technical guidance and must be validated against the organization's applicable requirements, scope, and policies.

---

 ## 🖥️ Supported Environment

 ### Operating Systems

 - Windows Server 2019
- Windows Server 2022
- Windows Server 2025
- Windows 10/11 for supported administrative tooling and laboratory scenarios

 ### Required Components

 - PowerShell 5.1+ or compatible PowerShell version
- Active Directory Domain Services
- RSAT / Active Directory PowerShell module
- Appropriate administrative privileges
- Domain-joined or management workstation where required

 ### Recommended Lab Environment

```
┌─────────────────────────────┐
│ Windows Server Domain       │
│                             │
│ ├── Domain Controller       │
│ ├── DNS                     │
│ ├── Active Directory        │
│ └── Test OUs / Users        │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ Windows Administration VM   │
│                             │
│ ├── PowerShell              │
│ ├── RSAT                    │
│ └── PS-AD-Arsenal           │
└─────────────────────────────┘
```

---

 ## 🚀 Quick Start

 ### 1\. Clone the Repository

```
git clone https://github.com/[YOUR_USERNAME]/PS-AD-Arsenal.git
cd PS-AD-Arsenal
```

 ### 2\. Review the Repository

 Before executing any script:

```
Get-ChildItem -Recurse
```

 Review the source code and understand every change that the selected module will perform.

 ### 3\. Verify PowerShell

```
$PSVersionTable
```

 ### 4\. Verify the Active Directory Module

```
Get-Module -ListAvailable ActiveDirectory
```

 If required:

```
Import-Module ActiveDirectory
```

 ### 5\. Execute a Module

 Example:

```
.\Scripts\01-ADDS-Hardening.ps1
```

 > **Security recommendation:** Always test scripts in an isolated lab environment before applying configuration changes to production Active Directory.

---

 ## 📁 Repository Structure

```
PS-AD-Arsenal/
│
├── README.md
├── LICENSE
├── .gitignore
│
├── Scripts/
│   ├── 01-ADDS-Hardening.ps1
│   ├── 02-Honeypot-Deception.ps1
│   ├── 03-Mass-Provisioning.ps1
│   └── 04-AD-Audit.ps1
│
├── Config/
│   ├── hardening.json
│   └── provisioning.csv
│
├── Logs/
│   └── .gitkeep
│
├── Docs/
│   ├── Architecture.md
│   ├── Hardening.md
│   ├── Honeypot.md
│   └── Provisioning.md
│
└── Tests/
    ├── Hardening.Tests.ps1
    └── Provisioning.Tests.ps1
```

---

 ## 🧪 Testing Strategy

 The project should follow a controlled testing lifecycle:

```
Development
     │
     ▼
Static Review
     │
     ▼
Lab Environment
     │
     ▼
Functional Testing
     │
     ▼
Security Validation
     │
     ▼
Change Review
     │
     ▼
Production Deployment
```

 Recommended validation areas:

 - Syntax validation
- Parameter validation
- Permission validation
- Error handling
- Rollback considerations
- Logging verification
- Active Directory object validation
- Security-event verification
- Idempotency where applicable

---

 ## 📊 Logging & Auditability

 Scripts should provide sufficient information to understand:

 - What operation was executed.
- When the operation was executed.
- Which target was affected.
- Whether the operation succeeded or failed.
- Relevant error information.
- Administrative context where appropriate.

 Example:

```
[2026-09-24 09:00:12] INFO  Starting provisioning workflow
[2026-09-24 09:00:13] INFO  Validating CSV input
[2026-09-24 09:00:14] INFO  Creating organizational units
[2026-09-24 09:00:15] INFO  Creating security groups
[2026-09-24 09:00:16] INFO  Creating user accounts
[2026-09-24 09:00:18] INFO  Workflow completed
```

---

 ## 🧠 Blue Team + Red Team Mindset

 PS-AD-Arsenal follows a **dual security mindset**.

 ### 🔵 Blue Team

 Focuses on:

 - Prevention
- Hardening
- Monitoring
- Logging
- Detection
- Incident visibility
- Identity security

 ### 🔴 Red Team

 Provides an adversarial perspective through controlled security testing and deception scenarios.

 Focuses on:

 - Attack-surface awareness
- Lateral-movement concepts
- Credential exposure scenarios
- Detection validation
- Security-control testing

 ### 🟣 Purple Team Perspective

 The combination creates a continuous security feedback loop:

```
Attack Scenario
      │
      ▼
Detection Opportunity
      │
      ▼
Security Control
      │
      ▼
Validation
      │
      ▼
Improvement
      │
      └──────────────► Repeat
```

 The objective is not to build offensive tooling for uncontrolled environments, but to use adversarial thinking to improve defensive security.

---

 ## 🔒 Security Considerations

 This repository can modify identity and security configurations.

 Before using it:

 - Test in a dedicated laboratory.
- Review every script before execution.
- Use least-privilege administrative accounts where possible.
- Maintain backups and recovery procedures.
- Document production changes.
- Validate compatibility with existing Group Policies.
- Avoid hardcoding credentials.
- Never commit passwords, tokens, private keys, or secrets.
- Review generated logs before publishing them publicly.

 ### 🚨 Never Commit Secrets

 Do **not** place credentials directly inside scripts:

```
# ❌ Never do this
$Password = "MyRealPassword123!"
```

 Prefer secure credential handling:

```
$Credential = Get-Credential
```

 Use `.gitignore` to prevent accidental publication of sensitive files.

---

 ## 📋 Roadmap

 ### Phase 1 — Foundation

 - [x] Repository architecture
- [x] Initial README
- [ ] Core PowerShell modules
- [ ] Logging framework
- [ ] Configuration management

 ### Phase 2 — Security

 - [ ] AD DS hardening module
- [ ] Security auditing module
- [ ] Honeypot/deception module
- [ ] Event validation
- [ ] Baseline comparison

 ### Phase 3 — Engineering

 - [ ] Pester tests
- [ ] CI validation
- [ ] PowerShell ScriptAnalyzer integration
- [ ] Documentation improvements
- [ ] Error-handling standardization

 ### Phase 4 — Enterprise

 - [ ] SIEM integration examples
- [ ] Microsoft Sentinel integration examples
- [ ] Hybrid identity scenarios
- [ ] Reporting
- [ ] Configuration drift detection

---

 ## 🧰 Technology Stack

 | Technology | Purpose |
| --- | --- |
| **PowerShell** | Automation and administration |
| **Active Directory Domain Services** | Identity and directory services |
| **Windows Server** | Infrastructure platform |
| **RSAT** | Administrative tooling |
| **Pester** | PowerShell testing |
| **Git / GitHub** | Version control |
| **SIEM** | Security monitoring |
| **Mermaid** | Architecture documentation |

---

 ## 📚 Documentation

 Additional documentation will be maintained under:

```
/docs
```

 Planned documentation:

 - Architecture
- Installation
- Hardening
- Honeypot deployment
- User provisioning
- Auditing
- Troubleshooting
- Security considerations
- Framework mappings

---

 ## 🤝 Contributing

 Contributions are welcome.

 Before submitting a Pull Request:

 1. Review the existing code.
2. Follow PowerShell best practices.
3. Add or update documentation.
4. Include tests where applicable.
5. Do not commit secrets or sensitive organizational information.
6. Clearly describe the security and operational impact of the change.

---

 ## ⚖️ Responsible Use

 PS-AD-Arsenal is intended for:

 - Authorized administration
- Security engineering
- Defensive security
- Controlled penetration-testing laboratories
- Academic research
- Enterprise security validation

 Do not deploy these scripts against systems or environments without appropriate authorization.

 The repository author is not responsible for unauthorized use, service disruption, data loss, or security incidents resulting from improper deployment or modification of the toolkit.

---

 ## 👨‍💻 Author

 **\[Your Full Name\]**

 _IT Support Engineering Student | SENATI_\
 _Aspiring SecOps / Identity & Access Management Engineer_

 - 📧 Email: `[your.email@example.com]`
- 💼 LinkedIn: `[your-linkedin-profile]`
- 🌐 Portfolio: `[your-portfolio-url]`
- 🐙 GitHub: `[your-github-profile]`

---

 ## 📄 License

 This project is licensed under the **MIT License**.

 See `LICENSE` for the complete license text.

---

 \<div align="center"\> ### 🛡️ PS-AD-Arsenal

 **Automate. Harden. Audit. Detect.**

 _Built for authorized security engineering, Active Directory administration, and controlled security research._

 \</div\>
