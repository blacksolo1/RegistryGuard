# RegistryGuard Pro 🛡️
**Author:** blacksolo

RegistryGuard Pro is a professional OCI/Docker Registry auditing tool designed to identify critical misconfigurations, information leaks, and supply-chain vulnerabilities.

## Features
- **Auth Bypass Detection**: Checks for unauthenticated V2 API access.
- **Deep Inventory Mapping**: Automatically lists every repository and associated tag.
- **Write-Access Verification**: Tests for unauthorized image poisoning risks.
- **Structured Reporting**: Exports all findings to a professional JSON report.

## Installation

🛠️ Installation & Setup Guide

This guide will walk you through setting up RegistryGuard Pro on your local machine or a VPS.
1. Prerequisites

Ensure you have Python 3.8 or higher installed on your system.

    Linux/macOS: Python is usually pre-installed. Check with python3 --version.

    Windows: Download the latest version from python.org.

2. Clone the Repository

Open your terminal or command prompt and run the following command to download the tool:


     git clone https://github.com/blacksolo/RegistryGuard.git
     cd RegistryGuard

3. Create a Virtual Environment (Recommended)

Using a virtual environment keeps your global Python installation clean and prevents library conflicts.


     # Windows
     python -m venv venv
     venv\Scripts\activate

    # Linux/macOS
    python3 -m venv venv
    source venv/bin/activate

4. Install Dependencies

Install the required libraries using the provided requirements.txt file:
Bash

    pip install -r requirements.txt

🚀 Running Your First Audit

Once installed, you can start auditing Docker registries immediately.
Basic Scan
Bash

    python3 registry_guard.py -d registry.example.com


Disclaimer

Provided for educational and authorized auditing purposes only.


---

Any Suggetion Ping Me .
iamblacksolo@gmail.com

### 3. `LICENSE`

MIT License
Copyright (c) 2026 blacksolo

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.


