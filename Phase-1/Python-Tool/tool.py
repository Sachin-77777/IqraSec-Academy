#!/usr/bin/env python3
"""
IOC Extractor (Python-Tool/tool.py)
===================================
Pull Indicators of Compromise out of any plain-text file - log files, phishing
e-mails, threat reports, pastebin dumps - and print a clean, de-duplicated and
frequency-sorted summary.

Why this exists
---------------
When you triage an incident, the first job is to pull every IP address, domain,
URL, e-mail address, file hash and CVE id out of the notes and reports you were
handed, so that you can block or hunt for them. Doing that by hand is slow and
easy to get wrong. This tool does it in a single pass.

Author  : Sachin Shrestha
Version : 1.0
Python  : 3.8+ (standard library only - nothing to pip install)
"""

import argparse
import csv
import ipaddress
import json
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

VERSION = "1.0"

# -----------------------------------------------------------------------------
# Recognition patterns
#
# Every pattern is compiled once at import time: compiling is the slow part of
# using a regular expression, so doing it here keeps the extraction loop fast
# even on large files.
# -----------------------------------------------------------------------------

# An IPv4 candidate. We deliberately allow 1-3 digits per octet here and let the
# ipaddress module reject the impossible ones (999.1.1.1) - a regex that tried
# to enforce 0-255 would be unreadable.
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

# user@host.tld - the local part allows the characters that really appear in
# addresses; the domain part must end in a dotted alphabetic TLD.
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,63}")

# Domains such as example-bad.test or cdn.example-bad.test.
# Labels may not start or end with a hyphen, which is what the (_?[A-Za-z0-9])
# construct enforces.
_DOMAIN_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b"
)

# http://, https:// and ftp:// URLs. The character class stops the match at a
# space, quote, angle bracket or closing bracket so a URL inside prose or HTML
# does not swallow the rest of the sentence.
_URL_RE = re.compile(r"(?:https?|ftp)://[^\s\"'<>\)\]\},;]+", re.IGNORECASE)

# CVE-YYYY-NNNN (the sequence number is 4 or more digits).
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# File hashes, distinguished purely by length. The \b boundaries matter: without
# them a 32-character pattern would also fire four times inside a SHA-256 value.
_MD5_RE = re.compile(r"\b[A-Fa-f0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[A-Fa-f0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[A-Fa-f0-9]{64}\b")

# Extensions that look like a domain to the domain pattern but are really file
# names. "invoice.txt" must not be reported as the host "invoice.txt".
FILE_EXTENSIONS = frozenset({
    "7z", "bak", "bat", "bin", "bmp", "cfg", "conf", "csv", "dat", "db", "dll",
    "doc", "docx", "err", "exe", "gif", "gz", "htm", "html", "ini", "iso",
    "jpeg", "jpg", "js", "json", "lock", "log", "md", "out", "pdf", "php",
    "png", "ppt", "pptx", "ps1", "py", "pyc", "rar", "rb", "sh", "sql", "tar",
    "tmp", "txt", "xls", "xlsx", "xml", "yaml", "yml", "zip",
})

# RFC 5737 documentation ranges. Python's ipaddress module counts these as
# "private", but they are the standard placeholder addresses used in reports
# and training material, so we keep reporting them instead of hiding them.
_DOCUMENTATION_RANGES = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)

# The IOC types a user may ask for, in the order we print them.
CANONICAL_TYPES = ("ips", "urls", "domains", "emails", "hashes", "cves")

# Internal display keys. Hashes are split per algorithm because "MD5" and
# "SHA256" mean very different things to an analyst.
DISPLAY_ORDER = (
    "ips", "urls", "domains", "emails",
    "hash-md5", "hash-sha1", "hash-sha256", "cves",
)

TYPE_LABELS = {
    "ips": "IPv4 addresses",
    "urls": "URLs",
    "domains": "Domains",
    "emails": "E-mail addresses",
    "hash-md5": "MD5 hashes",
    "hash-sha1": "SHA1 hashes",
    "hash-sha256": "SHA256 hashes",
    "cves": "CVE identifiers",
}


# =============================================================================
#  Reading
# =============================================================================

def read_file(path):
    """Read the whole file as text and return it.

    errors="replace" is the important detail: real-world logs and pasted
    reports regularly contain a stray byte that is not valid UTF-8. Without it
    the whole run would die on one bad character; with it we get a replacement
    character and carry on analysing the rest of the file.
    """
    return path.read_text(encoding="utf-8", errors="replace")


# =============================================================================
#  Extractors - each one returns a Counter, i.e. {ioc: how_many_times_seen}
# =============================================================================

def extract_ips(text, include_private=False):
    """Return a Counter of IPv4 addresses found in the text.

    Every candidate is validated with the ipaddress module, which throws away
    anything that only looks like an address (for example 999.1.1.1 or the tail
    of a version string). Loopback, link-local, multicast and "this network"
    addresses are always dropped because they are never useful in a report.
    RFC 1918 private ranges are dropped too unless include_private is True.
    """
    counter = Counter()

    for match in _IP_RE.finditer(text):
        candidate = match.group(0)
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            # Not a real address - skip it rather than crashing.
            continue

        if address.is_loopback or address.is_link_local:
            continue
        if address.is_multicast or address.is_unspecified or address.is_reserved:
            continue

        # Private space is noise in most reports, so it is opt-in.
        if address.is_private and not include_private:
            if not _is_documentation_ip(address):
                continue

        counter[str(address)] += 1

    return counter


def extract_domains(text, skip_spans=()):
    """Return a Counter of domain names found in the text.

    skip_spans holds the (start, end) character positions of the e-mail
    addresses that were already found. A domain matched *inside* one of those
    spans is ignored, so "example.com" is not counted twice just because it
    appeared as "user@example.com". If the same domain also appears on its own
    somewhere else in the text, that separate occurrence is still counted.

    Names whose last label is a known file extension are dropped, so file names
    such as "invoice.txt" are not mistaken for hosts.
    """
    counter = Counter()

    for match in _DOMAIN_RE.finditer(text):
        if _inside_any(match.span(), skip_spans):
            continue

        candidate = match.group(0).rstrip(".")
        tld = candidate.rsplit(".", 1)[-1].lower()
        if tld in FILE_EXTENSIONS:
            continue

        counter[candidate.lower()] += 1

    return counter


def extract_urls(text):
    """Return a Counter of URLs found in the text.

    A trailing punctuation mark is stripped because a URL at the end of a
    sentence ("visit http://example.com/x.") would otherwise keep the full stop
    as part of the path.
    """
    counter = Counter()

    for match in _URL_RE.finditer(text):
        counter[match.group(0).rstrip(".,;:!?")] += 1

    return counter


def extract_emails(text):
    """Return a Counter of e-mail addresses found in the text."""
    return Counter(match.group(0) for match in _EMAIL_RE.finditer(text))


def extract_hashes(text):
    """Return {algorithm: Counter} for every file hash in the text.

    The algorithm is inferred from the length of the hex string, which is the
    only way to tell them apart in unstructured text: 32 characters is MD5,
    40 is SHA-1 and 64 is SHA-256. Matching longest-first is not required here
    because the word boundaries stop a short pattern from firing inside a
    longer digest, but the ordering documents the intent.
    """
    found = {}

    for label, pattern in (
        ("sha256", _SHA256_RE),
        ("sha1", _SHA1_RE),
        ("md5", _MD5_RE),
    ):
        matches = Counter(m.group(0).lower() for m in pattern.finditer(text))
        if matches:
            found[label] = matches

    return found


def extract_cves(text):
    """Return a Counter of CVE identifiers, normalised to upper case.

    CVE ids are case-insensitive in the wild ("cve-2021-44228"), so folding
    them to one spelling stops the same vulnerability being listed twice.
    """
    return Counter(match.group(0).upper() for match in _CVE_RE.finditer(text))


# =============================================================================
#  Small internal helpers
# =============================================================================

def _is_documentation_ip(address):
    """True when the address is inside an RFC 5737 documentation range."""
    return any(address in network for network in _DOCUMENTATION_RANGES)


def _inside_any(span, spans):
    """True when the (start, end) span overlaps any span in spans."""
    start, end = span
    return any(start >= s and end <= e for s, e in spans)


def _sorted_entries(counter):
    """Turn a Counter into a list of {value, count} dicts, commonest first.

    Ties are broken alphabetically so the report looks identical every time it
    is run, which matters when the output is pasted into a ticket.
    """
    ordered = sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    return [{"value": value, "count": count} for value, count in ordered]


# =============================================================================
#  Report building and rendering
# =============================================================================

def build_report(source_name, text, wanted_types, include_private=False):
    """Run the requested extractors and return one nested report dictionary.

    The e-mail spans are computed first even when e-mails are not requested,
    because the domain extractor needs them to avoid double counting, and they
    are cheap to find.
    """
    email_spans = [match.span() for match in _EMAIL_RE.finditer(text)]
    types = {}

    if "ips" in wanted_types:
        types["ips"] = _sorted_entries(extract_ips(text, include_private))

    if "urls" in wanted_types:
        types["urls"] = _sorted_entries(extract_urls(text))

    if "domains" in wanted_types:
        types["domains"] = _sorted_entries(extract_domains(text, email_spans))

    if "emails" in wanted_types:
        types["emails"] = _sorted_entries(extract_emails(text))

    if "hashes" in wanted_types:
        hashes = extract_hashes(text)
        for algorithm in ("md5", "sha1", "sha256"):
            if algorithm in hashes:
                types["hash-" + algorithm] = _sorted_entries(hashes[algorithm])

    if "cves" in wanted_types:
        types["cves"] = _sorted_entries(extract_cves(text))

    return {
        "source": source_name,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "types": types,
    }


def defang_value(value, ioc_type):
    """Return a safely shareable version of an IOC.

    Defanging makes an indicator non-clickable and non-resolvable so that it is
    safe to paste into a chat, a ticket or an e-mail: hxxp:// instead of
    http://, and example[.]com instead of example.com.

    Hash digests and CVE ids are not defanged - they contain nothing that can be
    accidentally executed or resolved, and mangling them would make them
    impossible to copy into a blocklist.
    """
    if ioc_type.startswith("hash-") or ioc_type == "cves":
        return value

    if ioc_type == "urls":
        # ^http also covers https, giving hxxp / hxxps.
        value = re.sub(r"^http", "hxxp", value, flags=re.IGNORECASE)

    return value.replace(".", "[.]")


def render_text(report, defang=False):
    """Build the human-readable report as a single string."""
    width = 66
    lines = [
        "=" * width,
        f" IOC Extractor  v{VERSION}",
        " Extract, de-duplicate and count indicators of compromise",
        "=" * width,
        f"Source file : {report['source']}",
        f"Generated   : {report['generated']}",
    ]
    if defang:
        lines.append("Defanging   : on (safe to share)")
    lines.append("")

    types = report["types"]

    # ---- Summary table ------------------------------------------------------
    lines.append("SUMMARY")
    lines.append("-" * width)
    total = 0
    for key in DISPLAY_ORDER:
        if key not in types:
            continue
        total += len(types[key])
        lines.append(f"  {TYPE_LABELS[key]:<24} {len(types[key]):>4}")
    if not types:
        lines.append("  (no IOC types were selected)")
    lines.append("  " + "-" * (width - 4))
    lines.append(f"  {'TOTAL (distinct IOCs)':<24} {total:>4}")
    lines.append("")

    # ---- One section per type ----------------------------------------------
    for key in DISPLAY_ORDER:
        if key not in types or not types[key]:
            continue
        lines.append(f"{TYPE_LABELS[key]} ({len(types[key])})")
        lines.append("-" * width)
        for entry in types[key]:
            value = entry["value"]
            if defang:
                value = defang_value(value, key)
            lines.append(f"  {entry['count']:>5}  {value}")
        lines.append("")

    lines.append("Counts show how many times each indicator appeared in the file.")
    return "\n".join(lines)


def print_report(report, defang=False):
    """Print the report in plain-text form to standard output."""
    print(render_text(report, defang))


def save_report(report, output_path, output_format="text", defang=False):
    """Write the report to output_path as text, JSON or CSV.

    Returns True on success. Any operating-system error (bad path, read-only
    directory, disk full) is reported to the caller by returning False and the
    reason is printed to stderr, so main() can exit non-zero.
    """
    try:
        if output_format == "json":
            payload = {
                "source": report["source"],
                "generated": report["generated"],
                "defanged": defang,
                "iocs": {
                    key: [
                        {
                            "value": defang_value(e["value"], key) if defang else e["value"],
                            "count": e["count"],
                        }
                        for e in entries
                    ]
                    for key, entries in report["types"].items()
                },
            }
            with open(output_path, "w", encoding="utf-8", newline="") as handle:
                json.dump(payload, handle, indent=2)
                handle.write("\n")

        elif output_format == "csv":
            # newline="" lets the csv module control line endings, which keeps
            # the file identical on Windows and Linux.
            with open(output_path, "w", encoding="utf-8", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow(["type", "value", "count"])
                for key in DISPLAY_ORDER:
                    for entry in report["types"].get(key, []):
                        value = entry["value"]
                        if defang:
                            value = defang_value(value, key)
                        writer.writerow([key, value, entry["count"]])

        else:
            with open(output_path, "w", encoding="utf-8", newline="") as handle:
                handle.write(render_text(report, defang) + "\n")

    except OSError as exc:
        print(f"[ERROR] Could not write to '{output_path}': {exc}", file=sys.stderr)
        return False

    return True


# =============================================================================
#  Command-line interface
# =============================================================================

def parse_types(raw_value):
    """Turn "--types ips,urls" into a set of canonical type names.

    Raises ValueError for an unknown name so the caller can exit with the
    documented usage-error status.
    """
    requested = [part.strip().lower() for part in raw_value.split(",") if part.strip()]

    if not requested or requested == ["all"]:
        return set(CANONICAL_TYPES)

    unknown = [name for name in requested if name not in CANONICAL_TYPES]
    if unknown:
        raise ValueError(
            f"unknown IOC type(s): {', '.join(unknown)} "
            f"(choose from: {', '.join(CANONICAL_TYPES)}, all)"
        )

    return set(requested)


def build_parser():
    """Create the argparse parser.

    Using argparse means --help, error messages and exit codes come for free
    and stay consistent with the rest of the command-line world.
    """
    parser = argparse.ArgumentParser(
        prog="tool.py",
        description="Extract and de-duplicate indicators of compromise (IOCs) "
                    "from a text file.",
        epilog="Only analyse files you are authorised to handle. "
               "Use --defang before sharing results outside your team.",
    )
    parser.add_argument("input", help="text file to analyse (log, e-mail, report)")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="also save the report to this file")
    parser.add_argument("-f", "--format", choices=("text", "json", "csv"),
                        default="text", help="output format (default: text)")
    parser.add_argument("-t", "--types", default="all", metavar="LIST",
                        help="comma-separated IOC types to extract: "
                             "ips,domains,urls,emails,hashes,cves (default: all)")
    parser.add_argument("--defang", action="store_true",
                        help="print IOCs defanged (hxxp://, example[.]com) "
                             "so the output is safe to share")
    parser.add_argument("--private", action="store_true",
                        help="include private and reserved IP addresses")
    return parser


def main(argv=None):
    """Parse arguments, run the extraction and report the outcome."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # --- Validate the type list before touching the filesystem --------------
    try:
        wanted_types = parse_types(args.types)
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    # --- Validate the input file -------------------------------------------
    input_path = Path(args.input)

    if not input_path.exists():
        print(f"[ERROR] File not found: {input_path}", file=sys.stderr)
        return 1

    if input_path.is_dir():
        print(f"[ERROR] '{input_path}' is a directory, not a file.", file=sys.stderr)
        return 1

    try:
        text = read_file(input_path)
    except PermissionError:
        print(f"[ERROR] Permission denied reading '{input_path}'. "
              f"Check the file permissions.", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"[ERROR] Could not read '{input_path}': {exc}", file=sys.stderr)
        return 1

    if not text.strip():
        print(f"[ERROR] File is empty: {input_path}", file=sys.stderr)
        return 1

    # --- Do the work --------------------------------------------------------
    report = build_report(str(input_path), text, wanted_types, args.private)
    print_report(report, args.defang)

    # --- Optional copy on disk ---------------------------------------------
    if args.output:
        if not save_report(report, args.output, args.format, args.defang):
            return 1
        # Confirmation goes to stderr so that stdout stays clean for piping.
        print(f"[+] Report saved to: {args.output}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
