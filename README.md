# Security Automation Scripts

Python and PowerShell scripts for automating common SOC operations, incident response tasks, and security analysis workflows.

## Overview

This repository contains practical automation tools developed for real-world security operations. Each script addresses a specific operational need in SOC environments, from log analysis to IOC extraction and threat intelligence enrichment.

## Scripts

### Log Analysis
- **log_parser.py** - Parse and analyze common log formats (Windows Event, Syslog, web server logs)
- **failed_login_analyzer.py** - Identify brute force patterns in authentication logs
- **suspicious_process_finder.py** - Detect anomalous process execution from logs

### IOC Management
- **ioc_extractor.py** - Extract indicators of compromise (IPs, domains, hashes) from text
- **ioc_enricher.py** - Enrich IOCs with threat intelligence from multiple sources
- **hash_checker.py** - Bulk hash lookup against VirusTotal and other services

### Email Analysis
- **email_header_analyzer.py** - Parse and analyze email headers for phishing indicators
- **url_extractor.py** - Extract and defang URLs from emails and documents
- **attachment_analyzer.py** - Analyze email attachments for suspicious characteristics

### Network Analysis
- **ip_geo_lookup.py** - Bulk IP geolocation and reputation checking
- **domain_analyzer.py** - WHOIS lookup and domain reputation analysis
- **pcap_analyzer.py** - Basic packet capture analysis and statistics

### Incident Response
- **timeline_generator.py** - Create incident timelines from multiple log sources
- **evidence_collector.py** - Automated evidence collection from endpoints
- **report_generator.py** - Generate incident reports from investigation data

### Threat Intelligence
- **threat_feed_aggregator.py** - Aggregate and normalize threat intelligence feeds
- **ioc_to_siem.py** - Convert IOCs to SIEM detection rules
- **threat_hunting_toolkit.py** - Collection of threat hunting utilities

## Requirements

Most scripts require Python 3.8+ with common libraries:
```
pip install -r requirements.txt
```

Common dependencies:
- requests - API interactions
- pandas - Data analysis
- python-whois - Domain analysis
- dnspython - DNS queries
- email - Email parsing

## Usage

Each script includes:
- Help documentation (--help flag)
- Input validation
- Error handling
- Logging capabilities

Example:
```bash
python ioc_extractor.py --input incident_notes.txt --output iocs.csv
```

## Best Practices

**Security Considerations:**
- Never run scripts with production credentials in non-production environments
- Validate inputs to prevent injection attacks
- Store API keys in environment variables, not hardcoded
- Log all operations for audit trails

**Operational Use:**
- Test scripts in lab environment before production use
- Document modifications for specific environments
- Version control all changes
- Share improvements with the team

## Environment Setup

**Recommended setup:**
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
# Edit .env with your API keys and settings
```

## API Keys and Configuration

Some scripts require API keys for threat intelligence services:
- VirusTotal API
- AbuseIPDB API
- Shodan API
- AlienVault OTX API

Store in environment variables or `.env` file (never commit API keys to repo).

## Contributing

Improvements and new scripts welcome. Focus on:
- Real operational needs
- Clean, documented code
- Error handling
- Reusability across different environments

## Testing

Test scripts with sample data before production use:
```bash
# Run tests
python -m pytest tests/

# Test with sample data
python script_name.py --input test_data/sample.log
```

## Disclaimer

These scripts are for authorized security operations only. Always:
- Follow your organization's policies
- Obtain proper authorization before scanning or analyzing systems
- Respect data privacy and handling requirements
- Use responsibly and ethically

## License

MIT License - Feel free to modify for your operational needs.

## Resources

- [MITRE ATT&CK](https://attack.mitre.org/) - Threat intelligence framework
- [Sigma Rules](https://github.com/SigmaHQ/sigma) - Detection rule format
- [OWASP](https://owasp.org/) - Security best practices
- [SANS SEC487](https://www.sans.org/cyber-security-courses/open-source-intelligence-gathering/) - OSINT techniques
