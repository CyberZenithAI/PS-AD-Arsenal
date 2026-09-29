🛡️ PS-AD-Arsenal
Enterprise Active Directory Automation & Security Toolkit
<p align="center">

PowerShell • Active Directory Domain Services • Security Hardening • Automation • Auditing • SecOps

</p> <p align="center">







</p>
📌 Overview

PS-AD-Arsenal is a PowerShell-based toolkit designed for Active Directory Domain Services (AD DS) administration, security hardening, automation, auditing, and controlled security testing.

The project follows a Blue Team / Red Team mindset, combining infrastructure automation with defensive security practices to help administrators and security practitioners build more consistent, auditable, and resilient Windows environments.

🎯 Intended Use

The toolkit is designed for:

Active Directory administration

Windows Server hardening

Identity and Access Management (IAM)

User and group provisioning

Security auditing

Honeypot and deception concepts

PowerShell automation

SecOps and security engineering laboratories

Educational and controlled enterprise environments

Project Philosophy: Automate repetitive administrative tasks, reduce configuration drift, increase visibility, and apply security controls consistently.

🎯 Project Goals

PS-AD-Arsenal focuses on five core objectives:

Objective	Description
⚙️ Automate	Reduce repetitive Active Directory administration tasks.
🛡️ Harden	Apply documented security-hardening practices.
🔎 Audit	Improve visibility into configuration and administrative activity.
🎣 Detect	Create controlled detection opportunities through deception mechanisms.
📋 Document	Maintain traceability of infrastructure changes and operations.
⚔️ Core Modules
🛡️ Module 01 — AD DS Hardening

Blue Team / Infrastructure Security

Automates selected security-hardening tasks for Windows Server and Active Directory environments.

Capabilities

Configures selected password and account-lockout policies.

Applies configurable security baselines.

Disables legacy services or protocols when appropriate.

Supports administrative account hardening.

Performs configuration checks before applying changes.

Generates execution and change logs.

Designed for controlled testing before production deployment.

Security Objective

Reduce unnecessary attack surface and improve the security baseline of domain infrastructure.

⚠️ Important: Hardening recommendations should be validated against organizational requirements and tested before production deployment.

🎣 Module 02 — Honeypot & Deception

Blue Team / Threat Detection

Provides controlled deception mechanisms designed to generate security telemetry when a monitored account or resource is accessed.

Capabilities

Creates a dedicated monitored account or resource.

Applies controlled auditing configurations.

Generates security events when defined interactions occur.

Supports integration with security monitoring workflows.

Helps identify potentially suspicious internal activity.

Security Objective

Create additional detection opportunities for unauthorized access and lateral-movement activity.

⚠️ Operational Note: Honeypot accounts must be carefully isolated and monitored to avoid creating unnecessary security or operational risks.

⚙️ Module 03 — Mass Automation & Auditing

SysAdmin / DevOps / IAM

Automates repetitive Active Directory provisioning tasks while maintaining execution traceability.

Capabilities

Bulk Organizational Unit creation.

Bulk group creation.

Bulk user provisioning from CSV.

Group membership assignment.

Role-Based Access Control (RBAC) workflows.

Input validation.

Error handling.

Execution logging.

Repeatable provisioning workflows.

Security Objective

Improve consistency, scalability, and traceability during large-scale identity administration.

🏗️ Architecture
📄 Requirements / CSV
⚙️ PowerShell Automation Engine
Module Selection
🛡️ AD DS Hardening
🎣 Honeypot / Deception
👥 Mass IAM Automation
(🏢 Active Directory AD DS)
🔎 Auditing
📊 SIEM / Monitoring
💾 Backup & Recovery
🔄 Operational Workflow
┌──────────────────────────────────┐
│       Requirements / CSV         │
└────────────────┬─────────────────┘
                 │
                 ▼
┌──────────────────────────────────┐
│     PowerShell Automation        │
│             Engine               │
└────────────────┬─────────────────┘
                 │
        ┌────────┼────────┐
        ▼        ▼        ▼
   ┌────────┐ ┌────────┐ ┌────────┐
   │Hardening│ │Deception│ │  IAM   │
   └────┬────┘ └────┬────┘ └────┬───┘
        │           │           │
        └───────────┼───────────┘
                    ▼
        ┌────────────────────────┐
        │     Active Directory   │
        │          AD DS         │
        └────────────┬───────────┘
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
      ┌────────┐ ┌────────┐ ┌────────┐
      │Auditing│ │  SIEM  │ │ Backup │
      └────────┘ └────────┘ └────────┘

🔐 Security Principles

PS-AD-Arsenal is designed around the following security principles:

🔑 Least Privilege

🛡️ Defense in Depth

🔒 Secure by Default

👤 Identity-Centric Security

⚙️ Configuration Consistency

🔎 Auditability

📝 Change Traceability

🤖 Controlled Automation

🧩 Separation of Administrative Responsibilities

📜 Framework & Compliance Mapping

PS-AD-Arsenal can be used as a technical implementation reference for security practices related to several frameworks and standards.

ISO/IEC 27001:2022

Potentially relevant areas include:

Access control

Identity management

Authentication information

Logging and monitoring

Configuration management

Operational security

NIST Cybersecurity Concepts

Potential mappings include:

NIST Area	Related Concept
AC	Access Control
IA	Identification & Authentication
AU	Audit & Accountability
CM	Configuration Management
SI	System & Information Integrity
CIS Benchmarks

The toolkit can complement configuration-hardening practices for supported Windows Server environments.

🇵🇪 Peru — Ley N.° 29733

The project may support technical and organizational security practices related to the protection of personal information when deployed as part of an appropriately designed organizational security program.

Disclaimer: PS-AD-Arsenal is not a certification or compliance product. Framework mappings are provided as technical guidance and must be validated against the organization's applicable requirements, scope, policies, and regulatory obligations.

🖥️ Supported Environment
Operating Systems

Windows Server 2019

Windows Server 2022

Windows Server 2025

Windows 10

Windows 11

Windows 10/11 are intended primarily for supported administrative tooling and laboratory scenarios.

Required Components

PowerShell 5.1+ or compatible PowerShell version

Active Directory Domain Services

RSAT / Active Directory PowerShell module

Appropriate administrative privileges

Domain-joined or management workstation where required

📁 Repository Structure
PS-AD-Arsenal/
│
├── 📂 Scripts/
│   ├── 01-ADDS-Hardening.ps1
│   ├── 02-Honeypot-Deception.ps1
│   └── 03-Mass-Automation.ps1
│
├── 📂 Config/
│   └── configuration files
│
├── 📂 Data/
│   └── users.csv
│
├── 📂 Logs/
│   └── execution logs
│
├── 📂 Documentation/
│   └── technical documentation
│
├── 📄 README.md
├── 📄 LICENSE
└── 📄 .gitignore


Adjust the structure above to match the actual repository contents.

🚀 Quick Start
1. Clone the Repository
git clone https://github.com/[TU_USUARIO]/PS-AD-Arsenal.git
cd PS-AD-Arsenal

2. Review the Repository

Before executing any script, review the source code and understand every change that the selected module may perform.

Get-ChildItem -Recurse

3. Verify PowerShell
$PSVersionTable

4. Verify the Active Directory Module
Get-Module -ListAvailable ActiveDirectory


Import the module:

Import-Module ActiveDirectory

5. Execute a Module

Example:

.\Scripts\01-ADDS-Hardening.ps1


⚠️ Security Recommendation: Always test scripts in an isolated laboratory environment before applying configuration changes to a production Active Directory environment.

📊 Logging & Auditability

Scripts are designed to provide sufficient information to understand:

What operation was executed.

When the operation was executed.

Which target was affected.

Whether the operation succeeded or failed.

Relevant errors generated during execution.

Example
[2026-09-24 09:00:12] INFO  Starting provisioning workflow
[2026-09-24 09:00:13] INFO  Validating CSV input
[2026-09-24 09:00:14] INFO  Creating organizational units
[2026-09-24 09:00:16] INFO  Creating user accounts
[2026-09-24 09:00:18] INFO  Workflow completed

🧠 Development Methodology: AI-Assisted Engineering

This project was developed using a modern AI-augmented engineering workflow.

As an IT Support Engineering student with foundational knowledge of PowerShell, I used Prompt Engineering with AI tools, including Qwen, as a development aid for scripting, documentation, and problem-solving.

My Role in the Project
1. 🏗️ Architecture & Logic Design

Defined the project's:

Security requirements

Operational workflows

Module structure

Automation objectives

Compliance considerations

2. 🧠 Prompt Engineering

Created context-rich prompts to assist with:

PowerShell scripting

Error handling

Automation logic

Documentation

Security considerations

Code improvement

3. 🔎 Validation & Testing

Reviewed and tested generated solutions in an isolated Active Directory laboratory environment, focusing on:

Expected behavior

Configuration impact

Error handling

Repeatability

Safety

Alignment with documented requirements

4. 📚 Documentation

Structured the repository and documented:

Architecture

Operational workflows

Security considerations

Installation requirements

Usage instructions

Development methodology

Engineering Principle: AI-generated code is treated as an engineering aid—not as a substitute for human review, testing, security validation, or operational responsibility.

This workflow demonstrates how modern IT professionals can combine foundational scripting knowledge with AI-assisted development to build, understand, validate, and document infrastructure automation solutions.

🔒 Security Considerations

Before using PS-AD-Arsenal:

🧪 Test scripts in a dedicated laboratory.

🔍 Review every script before execution.

🔑 Use least-privilege administrative accounts where possible.

💾 Maintain tested backup and recovery procedures.

📝 Maintain appropriate execution logs.

🛡️ Validate changes against organizational security policies.

🚫 Never execute unreviewed scripts directly against production infrastructure.

🔐 Never commit passwords, tokens, private keys, API keys, or other secrets.

⚠️ Disclaimer

PS-AD-Arsenal is intended for:

Authorized Active Directory administration

Security engineering

Defensive security testing

Educational purposes

Controlled laboratory environments

The author is not responsible for damage, data loss, service interruption, unauthorized access, or other consequences resulting from improper use of the toolkit.

Always obtain appropriate authorization before performing security testing or configuration changes on systems you do not own or administer.

👨‍💻 Author
Joaquín Ocampo

IT Support Engineering Student @ SENATI
Aspiring SecOps & IAM Engineer

Passionate about:

🔐 Cybersecurity

🛡️ Security Operations

👤 Identity & Access Management

⚙️ Infrastructure Automation

🪟 Windows Server & Active Directory

🤖 AI-Assisted Engineering

Contact

📧 Email: [webdev.student123@outlook.com]

💼 LinkedIn: [linkedin.com/in/joaquinocampo-cybersecurity]

🐙 GitHub: [github.com/CyberZenithAI]

📄 License

This project is licensed under the MIT License.

See LICENSE for the complete license text.

<div align="center">
🛡️ PS-AD-Arsenal
Automate. Harden. Audit. Detect.

Built for authorized security engineering, Active Directory administration, and controlled security research.

⭐ If this project is useful for learning or experimentation, consider giving it a star.

</div>
