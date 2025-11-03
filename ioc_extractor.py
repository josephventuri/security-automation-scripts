#!/usr/bin/env python3
"""
IOC Extractor
Extracts indicators of compromise (IPv4, domains, URLs, hashes) from text files.
Useful for parsing incident notes, logs, or unstructured threat intelligence.
"""

import re
import argparse
import sys
from pathlib import Path
from typing import Set, Dict
import csv


class IOCExtractor:
    """Extract various types of indicators from text"""

    def __init__(self):
        # Regex patterns for different IOC types
        self.patterns = {
            'ipv4': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
            'url': r'https?://[^\s<>"{}|\\^`\[\]]+',
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        }

        # Common false positives to filter out
        self.false_positives = {
            'ipv4': {'0.0.0.0', '127.0.0.1', '255.255.255.255'},
            'domain': {'example.com', 'localhost', 'test.com'},
        }

    def extract_iocs(self, text: str) -> Dict[str, Set[str]]:
        """
        Extract all IOC types from text

        Args:
            text: Input text to extract IOCs from

        Returns:
            Dictionary with IOC types as keys and sets of found IOCs as values
        """
        results = {}

        for ioc_type, pattern in self.patterns.items():
            matches = set(re.findall(pattern, text, re.IGNORECASE))

            # Filter out false positives
            if ioc_type in self.false_positives:
                matches = matches - self.false_positives[ioc_type]

            # Additional validation
            if ioc_type == 'ipv4':
                matches = {ip for ip in matches if self._is_valid_ip(ip)}

            results[ioc_type] = matches

        return results

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IPv4 address"""
        try:
            octets = ip.split('.')
            return all(0 <= int(octet) <= 255 for octet in octets)
        except (ValueError, AttributeError):
            return False

    def defang_ioc(self, ioc: str, ioc_type: str) -> str:
        """
        Defang IOCs to prevent accidental clicks

        Args:
            ioc: The indicator to defang
            ioc_type: Type of indicator

        Returns:
            Defanged version of the IOC
        """
        if ioc_type == 'ipv4':
            return ioc.replace('.', '[.]')
        elif ioc_type in ['domain', 'url']:
            return ioc.replace('http://', 'hxxp://').replace('https://', 'hxxps://').replace('.', '[.]')
        else:
            return ioc

    def save_to_csv(self, iocs: Dict[str, Set[str]], output_path: Path, defang: bool = True):
        """
        Save extracted IOCs to CSV file

        Args:
            iocs: Dictionary of extracted IOCs
            output_path: Path to output CSV file
            defang: Whether to defang the IOCs
        """
        with open(output_path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Type', 'Indicator', 'Defanged'])

            for ioc_type, indicators in iocs.items():
                for indicator in sorted(indicators):
                    defanged = self.defang_ioc(indicator, ioc_type) if defang else indicator
                    writer.writerow([ioc_type, indicator, defanged])

    def print_results(self, iocs: Dict[str, Set[str]], defang: bool = True):
        """Print extracted IOCs to console"""
        total_count = sum(len(indicators) for indicators in iocs.values())

        print(f"\n[+] Extracted {total_count} total indicators\n")

        for ioc_type, indicators in iocs.items():
            if indicators:
                print(f"\n{ioc_type.upper()} ({len(indicators)} found):")
                print("-" * 50)
                for indicator in sorted(indicators):
                    if defang:
                        defanged = self.defang_ioc(indicator, ioc_type)
                        print(f"  {defanged}")
                    else:
                        print(f"  {indicator}")


def main():
    parser = argparse.ArgumentParser(
        description='Extract indicators of compromise from text files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Extract IOCs from incident notes
  python ioc_extractor.py --input incident_report.txt

  # Save to CSV without defanging
  python ioc_extractor.py --input logs.txt --output iocs.csv --no-defang

  # Read from stdin
  cat suspicious_email.txt | python ioc_extractor.py
        """
    )

    parser.add_argument('-i', '--input', type=Path,
                       help='Input file to extract IOCs from (use stdin if not provided)')
    parser.add_argument('-o', '--output', type=Path,
                       help='Output CSV file (optional)')
    parser.add_argument('--no-defang', action='store_true',
                       help='Do not defang IOCs in output')
    parser.add_argument('--quiet', action='store_true',
                       help='Suppress console output')

    args = parser.parse_args()

    # Read input
    try:
        if args.input:
            text = args.input.read_text(encoding='utf-8')
        else:
            # Read from stdin
            text = sys.stdin.read()
    except Exception as e:
        print(f"[!] Error reading input: {e}", file=sys.stderr)
        sys.exit(1)

    # Extract IOCs
    extractor = IOCExtractor()
    iocs = extractor.extract_iocs(text)

    # Output results
    defang = not args.no_defang

    if not args.quiet:
        extractor.print_results(iocs, defang=defang)

    if args.output:
        try:
            extractor.save_to_csv(iocs, args.output, defang=defang)
            print(f"\n[+] Results saved to {args.output}")
        except Exception as e:
            print(f"[!] Error saving output: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == '__main__':
    main()
