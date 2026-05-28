# Security Policy

## Supported Versions

At this time, only the latest major release is actively supported for security updates.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :white_check_mark: |

## Security Model Overview
Sirius Vault treats the underlying operating system as an inherently untrusted environment. 
* **RAM Protection:** Cryptographic keys are kept in memory only for the exact duration of the I/O operation and are explicitly set to `None` upon completion.
* **Clipboard Protection:** The application uses `ExcludeClipboardContentFromMonitorProcessing` and `CanIncludeInClipboardHistory` DWORD payloads to prevent external OS services (like Windows Clipboard History) from logging sensitive copied text.
* **File I/O:** Temporary media files are subjected to multi-pass byte overwrites (`secure_delete`) before OS-level file removal.

## Reporting a Vulnerability
Security is the absolute priority of this project. If you discover a potential vulnerability, memory leak, or cryptographic flaw, please **do not create a public issue.**

Instead, please report it privately by sending an email to:
📧 **ghospicer@gmail.com**

Please include the following details in your report:
* Description of the vulnerability and its potential impact.
* Detailed steps to reproduce the issue.
* Your operating system and Python version.

All security reports are taken seriously and will be addressed with the highest priority.
