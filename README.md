# RegistryGuard Pro 🛡️
**Author:** blacksolo

RegistryGuard Pro is a professional OCI/Docker Registry auditing tool designed to identify critical misconfigurations, information leaks, and supply-chain vulnerabilities.

## Features
- **Auth Bypass Detection**: Checks for unauthenticated V2 API access.
- **Deep Inventory Mapping**: Automatically lists every repository and associated tag.
- **Write-Access Verification**: Tests for unauthorized image poisoning risks.
- **Structured Reporting**: Exports all findings to a professional JSON report.

## Installation
```bash
pip install -r requirements.txt

Usage

python3 registry_guard.py -d registry.example.com


Disclaimer

Provided for educational and authorized auditing purposes only.


---

### 3. `LICENSE`

MIT License
Copyright (c) 2026 blacksolo

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.


