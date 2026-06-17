#!/usr/bin/env python3
"""
Email Triage Helper — Phishing Investigation Yardımcı Parser

Bu araç .eml/.txt dosyasından header alanlarını, Received zincirini,
URL/IP adaylarını ve attachment bilgisini çıkarır.

**Verdict VERMEZ.** Sadece analiste bulguları sunar.
Karar, yorum ve ekran görüntüleri analiste aittir.

Kullanım:
    python email_triage_helper.py <dosya_yolu>
    python email_triage_helper.py samples/ornek.eml

Çıktı:
    1. Key Header Fields (From, Return-Path, Reply-To, Subject, Date, Message-ID)
    2. Authentication Results (SPF, DKIM, DMARC)
    3. Received Chain (mail rotası)
    4. URLs Found (body içindeki http/https linkleri)
    5. IP Addresses Found
    6. Attachment Summary (dosya adı, tipi)
"""

import re
import sys
import email
import hashlib
from email import policy
from email.message import EmailMessage
from email.utils import parsedate_to_datetime
from pathlib import Path


def parse_email(filepath: str) -> EmailMessage:
    """Read and parse an .eml or .txt file."""
    path = Path(filepath)
    if not path.exists():
        print(f"[!] File not found: {filepath}")
        sys.exit(1)

    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        raw = f.read()

    return email.message_from_string(raw, policy=policy.default)


def extract_headers(msg: EmailMessage) -> dict:
    """Extract key header fields."""
    fields = {
        'From': msg.get('From', 'N/A'),
        'Return-Path': msg.get('Return-Path', 'N/A'),
        'Reply-To': msg.get('Reply-To', 'N/A'),
        'Subject': msg.get('Subject', 'N/A'),
        'Date': msg.get('Date', 'N/A'),
        'Message-ID': msg.get('Message-ID', 'N/A'),
        'To': msg.get('To', 'N/A'),
        'CC': msg.get('CC', 'N/A'),
        'Content-Type': msg.get('Content-Type', 'N/A'),
    }
    return fields


def extract_received_chain(msg: EmailMessage) -> list:
    """Extract all Received headers in chronological order (top to bottom)."""
    received = msg.get_all('Received', [])
    # Received headers are stored top-to-bottom (newest first)
    # Reverse to show chronological: origin first, destination last
    return received


def extract_auth_results(msg: EmailMessage) -> dict:
    """Extract SPF, DKIM, DMARC results from Authentication-Results header."""
    auth_header = msg.get('Authentication-Results', '')
    results = {
        'spf': 'not found',
        'dkim': 'not found',
        'dmarc': 'not found',
    }

    spf_match = re.search(r'spf=(\w+)', auth_header, re.IGNORECASE)
    if spf_match:
        results['spf'] = spf_match.group(1)

    dkim_match = re.search(r'dkim=(\w+)', auth_header, re.IGNORECASE)
    if dkim_match:
        results['dkim'] = dkim_match.group(1)

    dmarc_match = re.search(r'dmarc=(\w+)', auth_header, re.IGNORECASE)
    if dmarc_match:
        results['dmarc'] = dmarc_match.group(1)

    return results


def extract_urls(body: str) -> list:
    """Find all http/https URLs in the email body."""
    url_pattern = re.compile(r'https?://[^\s<>"\'\[\]]+', re.IGNORECASE)
    urls = url_pattern.findall(body)
    # Remove duplicates, preserve order
    seen = set()
    unique_urls = []
    for url in urls:
        # Clean trailing punctuation
        url = url.rstrip('.,;:!?)]}')
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)
    return unique_urls


def extract_ips(body: str) -> list:
    """Find IPv4 addresses in email body and headers."""
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    ips = ip_pattern.findall(body)
    # Filter out invalid IPs and common false positives
    valid_ips = []
    seen = set()
    for ip in ips:
        parts = ip.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            # Skip common non-routable false positives
            if ip not in ('0.0.0.0', '127.0.0.1', '255.255.255.255'):
                if ip not in seen:
                    seen.add(ip)
                    valid_ips.append(ip)
    return valid_ips


def extract_attachments(msg: EmailMessage) -> list:
    """List attachment filenames, types, and hashes."""
    attachments = []
    for part in msg.walk():
        content_disposition = part.get_content_disposition()
        if content_disposition == 'attachment':
            filename = part.get_filename() or 'unnamed'
            content_type = part.get_content_type()
            payload = part.get_payload(decode=True)
            if payload:
                sha256 = hashlib.sha256(payload).hexdigest()
                size = len(payload)
            else:
                sha256 = 'N/A (no payload)'
                size = 0

            attachments.append({
                'filename': filename,
                'type': content_type,
                'sha256': sha256,
                'size': size,
            })
    return attachments


def get_body_text(msg: EmailMessage) -> str:
    """Extract plain text body, fallback to HTML."""
    body_parts = []
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain':
                payload = part.get_payload(decode=True)
                if payload:
                    body_parts.append(payload.decode('utf-8', errors='replace'))
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body_parts.append(payload.decode('utf-8', errors='replace'))

    return '\n'.join(body_parts) if body_parts else str(msg)


def get_raw_source(msg) -> str:
    """Get raw email source as string (for full-text search)."""
    return str(msg)


def print_banner(filepath: str):
    """Print tool banner."""
    print("=" * 60)
    print("  EMAIL TRIAGE HELPER — Phishing Investigation")
    print("=" * 60)
    print(f"\n  File: {filepath}")
    print(f"  Note: Bu araç VERDICT VERMEZ. Yorum analiste aittir.")
    print()


def print_section(title: str):
    """Print section header."""
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")


def main():
    if len(sys.argv) < 2:
        print("Kullanım: python email_triage_helper.py <dosya_yolu>")
        print("Örnek:   python email_triage_helper.py samples/ornek.eml")
        sys.exit(1)

    filepath = sys.argv[1]
    print_banner(filepath)

    # Parse
    msg = parse_email(filepath)

    # 1. Key Headers
    print_section("1. KEY HEADER FIELDS")
    headers = extract_headers(msg)
    for field, value in headers.items():
        print(f"  {field:15s}: {value}")

    # Check for mismatches
    from_addr = headers.get('From', '')
    return_path = headers.get('Return-Path', '')
    reply_to = headers.get('Reply-To', '')
    msg_id = headers.get('Message-ID', '')

    print(f"\n  [>] Mismatch Check:")
    if return_path != 'N/A' and from_addr != 'N/A':
        if return_path != from_addr:
            print(f"      ⚠ Return-Path differs from From — possible spoofing")
        else:
            print(f"      ✓ Return-Path matches From")
    if reply_to != 'N/A' and from_addr != 'N/A':
        if reply_to != from_addr:
            print(f"      ⚠ Reply-To differs from From — replies go elsewhere")

    # Extract domain from Message-ID
    msgid_domain_match = re.search(r'@([^>\s]+)', msg_id)
    if msgid_domain_match:
        msgid_domain = msgid_domain_match.group(1)
        from_domain_match = re.search(r'@([^>\s]+)', from_addr)
        if from_domain_match:
            from_domain = from_domain_match.group(1)
            if msgid_domain.lower() != from_domain.lower():
                print(f"      ⚠ Message-ID domain ({msgid_domain}) != From domain ({from_domain})")
            else:
                print(f"      ✓ Message-ID domain matches From domain")

    # 2. Authentication Results
    print_section("2. AUTHENTICATION RESULTS")
    auth = extract_auth_results(msg)
    for mech, result in auth.items():
        icon = "✓" if result == 'pass' else ("⚠" if result == 'fail' else "○")
        print(f"  {mech.upper():6s}: {result:10s} {icon}")

    # Interpretation hints
    print(f"\n  [>] Quick Interpretation:")
    if auth['spf'] == 'fail' and auth['dkim'] == 'none' and auth['dmarc'] == 'fail':
        print(f"      ⚠ SPF fail + DKIM none + DMARC fail → STRONG phishing indicator")
    elif auth['dmarc'] == 'fail':
        print(f"      ⚠ DMARC fail → phishing likely (but check forwarding)")
    elif auth['spf'] == 'pass' and auth['dkim'] == 'pass' and auth['dmarc'] == 'pass':
        print(f"      ○ All passed → look at domain similarity (typosquatting)")

    # 3. Received Chain
    print_section("3. RECEIVED CHAIN (top = newest, bottom = origin)")
    received_chain = extract_received_chain(msg)
    if received_chain:
        for i, rec in enumerate(received_chain, 1):
            # Extract key info from received header
            from_match = re.search(r'from\s+(\S+)', rec, re.IGNORECASE)
            by_match = re.search(r'by\s+(\S+)', rec, re.IGNORECASE)
            ip_match = re.search(r'\[([0-9.]+)\]', rec)

            from_info = from_match.group(1) if from_match else '?'
            by_info = by_match.group(1) if by_match else '?'
            ip_info = f" ({ip_match.group(1)})" if ip_match else ''

            print(f"\n  [{i}] from: {from_info}{ip_info}")
            print(f"       by: {by_info}")
    else:
        print("  No Received headers found.")

    # 4. URLs
    print_section("4. URLs FOUND IN EMAIL BODY")
    raw_source = get_raw_source(msg)
    body_text = get_body_text(msg)
    urls = extract_urls(raw_source)
    if urls:
        for i, url in enumerate(urls, 1):
            print(f"  [{i}] {url}")
    else:
        print("  No URLs found.")

    # 5. IPs
    print_section("5. IP ADDRESSES FOUND")
    ips = extract_ips(raw_source)
    if ips:
        for i, ip in enumerate(ips, 1):
            print(f"  [{i}] {ip}")
    else:
        print("  No IP addresses found.")

    # 6. Attachments
    print_section("6. ATTACHMENTS")
    attachments = extract_attachments(msg)
    if attachments:
        for i, att in enumerate(attachments, 1):
            print(f"  [{i}] Filename : {att['filename']}")
            print(f"       Type     : {att['type']}")
            print(f"       SHA256   : {att['sha256']}")
            print(f"       Size     : {att['size']} bytes")
    else:
        print("  No attachments found.")

    # 7. IOC Summary (for copy-paste to CSV)
    print_section("7. IOC CANDIDATES (for manual review)")
    print(f"  --- Copy candidates below to iocs/iocs.csv ---")
    for url in urls:
        # Extract domain
        domain_match = re.search(r'https?://([^/]+)', url)
        domain = domain_match.group(1) if domain_match else url
        print(f"  Domain,{domain},Email body,Medium,Needs review")
        print(f"  URL,{url},Email body,Medium,Needs review")
    for ip in ips:
        print(f"  IP,{ip},Email source,Medium,Needs reputation check")
    for att in attachments:
        print(f"  Hash,{att['sha256']},Attachment,Medium,{att['filename']}")

    print(f"\n{'=' * 60}")
    print(f"  Triage complete. Now: MANUAL ANALYSIS required.")
    print(f"  → Check VirusTotal, URLScan, WHOIS, AbuseIPDB")
    print(f"  → Fill out iocs/iocs.csv with confidence levels")
    print(f"  → Write verdict in reports/phishing_investigation_report_CASE1_FINAL.md")
    print(f"{'=' * 60}")


if __name__ == '__main__':
    main()
