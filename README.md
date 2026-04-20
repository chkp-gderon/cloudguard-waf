# Check Point WAF Scripts

A collection of Python scripts for automating Check Point CloudGuard Web Application Firewall (WAF) operations and management.

## Overview

This repository contains utility scripts designed to streamline WAF management tasks in Check Point CloudGuard environments, including retrieval of tuning suggestions and policy optimization.

## Contents

- **python-scripts/** - Python-based automation scripts
  - `waf_get_tuning_suggestions.py` - Retrieve and list WAF tuning suggestions for all assets

## Quick Start

### Requirements
- Python 3.x
- `requests` library: `pip install requests`

### Usage

1. Clone the repository
2. Update credentials in the scripts (CLIENT_ID and ACCESS_KEY)
3. Run desired script: `python python-scripts/waf_get_tuning_suggestions.py`

## Features

✅ Automated WAF tuning suggestion retrieval  
✅ Asset-based filtering and reporting  
✅ Detailed event analysis (severity, attack types, policies)  
✅ Easy-to-read output format

## Documentation

See individual script directories for detailed documentation and configuration options.

## Security Note

⚠️ Handle API credentials securely. Never commit credentials to version control.

## License

Open source - Check Point CloudGuard environment compatible