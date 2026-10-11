# Security Automation Scripts

Small scripts for routine SOC and incident response work.

## Scripts

| Script | What it does |
| --- | --- |
| [ioc_extractor.py](ioc_extractor.py) | Pulls indicators of compromise (IPv4 addresses, domains, URLs, email addresses, MD5/SHA1/SHA256 hashes) out of text such as incident notes or logs |

## Usage

Requires Python 3.8 or newer. `ioc_extractor.py` uses only the standard library.

```bash
python ioc_extractor.py --help
python ioc_extractor.py --input incident_notes.txt --output iocs.csv
```

## Disclaimer

For authorized security work only.
