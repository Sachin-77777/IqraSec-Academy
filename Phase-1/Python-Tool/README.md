# Python Tool - IOC Extractor

## 1. Tool Name

**IOC Extractor** (`tool.py`)

---

## 2. Objective

Extract **Indicators of Compromise (IOCs)** from any plain-text file and turn
them into a clean, de-duplicated, frequency-sorted summary.

An "indicator of compromise" is any small piece of evidence that tells you an
attack happened or is happening - an attacker's IP address, a malicious domain,
a phishing URL, a sender address, the hash of a malware file, or the CVE id of
the vulnerability that was abused.

In a real incident these indicators are scattered through long threat reports,
e-mail headers and log files. Copying them out by hand is slow and you will
miss some. This tool reads the whole file in one pass, finds every indicator,
counts how many times each one appears, and prints a tidy report you can act on.

**Why the count matters:** the indicator that appears ten times is usually more
important than the one that appears once. Sorting by frequency puts the
attacker's main infrastructure at the top of the list.

---

## 3. Features

| # | Feature |
|---|---------|
| 1 | Extracts **IPv4 addresses**, validated with the `ipaddress` module |
| 2 | Extracts **URLs** (`http://`, `https://`, `ftp://`) |
| 3 | Extracts **domains**, ignoring file names such as `invoice.txt` |
| 4 | Extracts **e-mail addresses** |
| 5 | Extracts **file hashes**, labelling them MD5 / SHA-1 / SHA-256 by length |
| 6 | Extracts **CVE ids**, normalised to upper case |
| 7 | De-duplicates and shows a **count for each indicator**, most frequent first |
| 8 | Summary table with the number of distinct IOCs per type |
| 9 | `--defang` output (`hxxp://`, `example[.]com`) so results are safe to share |
| 10 | `--private` to include private / reserved IP addresses |
| 11 | `-t` to extract only the IOC types you care about |
| 12 | Output as **text**, **JSON** or **CSV**, optionally saved with `-o` |

Details that matter in practice:

- **Sensible false-positive filtering.** Version strings that are not valid
  addresses (`999.1.1.1`) are rejected, and file extensions (`notes.md`,
  `report.log`, `archive.zip`) are not mistaken for domains.
- **No double counting.** A domain that only appears inside an e-mail address is
  reported once, as part of that address - not twice.
- **Friendly error handling.** Missing file, empty file, unreadable file,
  invalid option values and write failures all produce a clear message on
  stderr and a non-zero exit code, so the tool is safe to use inside scripts.
- **Standard library only.** No `pip install`, nothing to compile.

---

## 4. Requirements

- **Python 3.8 or newer.**
- **Standard library only** - there is nothing to install. The modules used are
  `argparse`, `re`, `json`, `csv`, `ipaddress`, `pathlib`, `sys`, `collections`
  and `datetime`, all of which ship with Python.

---

## 5. How to Run

```bash
cd Python-Tool

# Analyse the bundled sample file
python3 tool.py samples/sample_input.txt

# Show the built-in help
python3 tool.py --help
```

> On Windows the command is usually `python tool.py ...` instead of
> `python3 tool.py ...`.

### Arguments

| Argument | Meaning | Default |
|----------|---------|---------|
| `input` | Text file to analyse (positional, required) | |
| `-o`, `--output <file>` | Also save the report to this file | *(none)* |
| `-f`, `--format {text,json,csv}` | Output format | `text` |
| `-t`, `--types <list>` | IOC types to extract: `ips,domains,urls,emails,hashes,cves` | `all` |
| `--defang` | Print IOCs defanged, safe to share | off |
| `--private` | Include private / reserved IP addresses | off |

---

## 6. Example Usage

```bash
# Extract everything from the sample threat report
python3 tool.py samples/sample_input.txt

# The same, but defanged so it is safe to paste into a chat or a ticket
python3 tool.py samples/sample_input.txt --defang

# Also include private addresses such as 10.0.10.15
python3 tool.py samples/sample_input.txt --private

# Only interested in IP addresses and CVE ids
python3 tool.py samples/sample_input.txt -t ips,cves

# Save a JSON report for a script or dashboard to consume
python3 tool.py samples/sample_input.txt -o report.json -f json

# Save a CSV that opens neatly in Excel / Google Sheets
python3 tool.py samples/sample_input.txt -o report.csv -f csv --defang

# Works on any text file - here, the Bash tool's authentication log
python3 tool.py ../Bash-Tool/samples/sample_auth.log -t ips --private

# Show the help text
python3 tool.py --help
```

---

## 7. Example Output

This is the **real output** produced by running
`python3 tool.py samples/sample_input.txt` against the bundled sample file:

```text
==================================================================
 IOC Extractor  v1.0
 Extract, de-duplicate and count indicators of compromise
==================================================================
Source file : samples/sample_input.txt
Generated   : 2026-11-03T09:57:21

SUMMARY
------------------------------------------------------------------
  IPv4 addresses              3
  URLs                        3
  Domains                     4
  E-mail addresses            2
  MD5 hashes                  1
  SHA256 hashes               1
  CVE identifiers             2
  --------------------------------------------------------------
  TOTAL (distinct IOCs)      16

IPv4 addresses (3)
------------------------------------------------------------------
      3  203.0.113.45
      2  198.51.100.7
      1  203.0.113.66

URLs (3)
------------------------------------------------------------------
      2  https://cdn-login.example-bad.test/updates/gate.php
      1  http://malware-drop.example-bad.test/payload/stage2.bin
      1  http://secure-login.example-bad.test/verify

Domains (4)
------------------------------------------------------------------
      2  cdn-login.example-bad.test
      2  update-server.example-bad.test
      1  malware-drop.example-bad.test
      1  secure-login.example-bad.test

E-mail addresses (2)
------------------------------------------------------------------
      1  analyst.help@example-org.test
      1  dropbox-agent@example-bad.test

MD5 hashes (1)
------------------------------------------------------------------
      1  d41d8cd98f00b204e9800998ecf8427e

SHA256 hashes (1)
------------------------------------------------------------------
      1  9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08

CVE identifiers (2)
------------------------------------------------------------------
      2  CVE-2021-44228
      1  CVE-2023-34362

Counts show how many times each indicator appeared in the file.
```

*(The `Generated` line shows your own current date and time, so it will be
different when you run it.)*

### How to read this report

- `203.0.113.45` appears **3 times**, so it is the top priority for blocking.
  It is described in the sample as the primary command-and-control server.
- `https://cdn-login.example-bad.test/updates/gate.php` appears twice because
  two different victims contacted the same fallback URL.
- The **private** address `10.0.10.15` does **not** appear, because private IP
  addresses are skipped by default - they are meaningless outside your own
  network.
- `example-bad.test` does not appear as a separate domain even though it is used
  inside e-mail addresses. It is counted once, as part of
  `dropbox-agent@example-bad.test`, which is exactly the "no double counting"
  rule in action.
- `invoice.txt`, `notes.md`, `report.log`, `config.yaml`, `archive.zip`,
  `payload/stage2.bin`, `deploy.sh` and `cleanup.py` are all deliberately
  **missing** from the domains list. They look like domains to a naive regular
  expression; the extension filter rejects them.
- `CVE-2021-44228` (Log4Shell) appears twice and sorts first, which is correct -
  it was the exploit used against two victims.

### `--defang` output

```bash
python3 tool.py samples/sample_input.txt --defang
```

```text
IPv4 addresses (3)
------------------------------------------------------------------
      3  203[.]0[.]113[.]45
      2  198[.]51[.]100[.]7
      1  203[.]0[.]113[.]66

URLs (3)
------------------------------------------------------------------
      2  hxxps://cdn-login[.]example-bad[.]test/updates/gate[.]php
      1  hxxp://malware-drop[.]example-bad[.]test/payload/stage2[.]bin
      1  hxxp://secure-login[.]example-bad[.]test/verify

Domains (4)
------------------------------------------------------------------
      2  cdn-login[.]example-bad[.]test
      2  update-server[.]example-bad[.]test
      1  malware-drop[.]example-bad[.]test
      1  secure-login[.]example-bad[.]test
```

Nothing is clickable any more, so the report can be shared safely. Hash values
and CVE ids are left untouched, because mangling them would make them impossible
to copy into a blocklist.

### `--private` output

```bash
python3 tool.py samples/sample_input.txt --private -t ips
```

```text
IPv4 addresses (4)
------------------------------------------------------------------
      3  203.0.113.45
      2  10.0.10.15
      2  198.51.100.7
      1  203.0.113.66
```

The internal host `10.0.10.15` now shows up. It is useful when you are hunting
inside your own network, and noise when you are not - which is why it is opt-in.

### JSON and CSV output

```bash
python3 tool.py samples/sample_input.txt -o report.json -f json -t ips,cves
```

```json
{
  "source": "samples/sample_input.txt",
  "generated": "2026-11-03T09:57:35",
  "defanged": false,
  "iocs": {
    "ips": [
      {
        "value": "203.0.113.45",
        "count": 3
      },
      {
        "value": "198.51.100.7",
        "count": 2
      },
      {
        "value": "203.0.113.66",
        "count": 1
      }
    ],
    "cves": [
      {
        "value": "CVE-2021-44228",
        "count": 2
      },
      {
        "value": "CVE-2023-34362",
        "count": 1
      }
    ]
  }
}
```

```bash
python3 tool.py samples/sample_input.txt -o report.csv -f csv --defang -t domains,emails
```

```text
type,value,count
domains,cdn-login[.]example-bad[.]test,2
domains,update-server[.]example-bad[.]test,2
domains,malware-drop[.]example-bad[.]test,1
domains,secure-login[.]example-bad[.]test,1
emails,analyst[.]help@example-org[.]test,1
emails,dropbox-agent@example-bad[.]test,1
```

### Error handling examples

```text
$ python3 tool.py nope.txt
[ERROR] File not found: nope.txt
$ echo $?
1

$ python3 tool.py empty.txt
[ERROR] File is empty: empty.txt
$ echo $?
1

$ python3 tool.py samples
[ERROR] 'samples' is a directory, not a file.
$ echo $?
1

$ python3 tool.py samples/sample_input.txt -t ips,bogus
[ERROR] unknown IOC type(s): bogus (choose from: ips, urls, domains, emails, hashes, cves, all)
$ echo $?
2

$ python3 tool.py samples/sample_input.txt -f xml
tool.py: error: argument -f/--format: invalid choice: 'xml' (choose from text, json, csv)
$ echo $?
2
```

A file containing invalid UTF-8 bytes is read with `errors="replace"` instead of
crashing, so a single corrupted byte does not stop the analysis:

```text
$ python3 tool.py nonutf8.bin -t ips,domains
IPv4 addresses (1)
------------------------------------------------------------------
      1  198.51.100.7

Domains (1)
------------------------------------------------------------------
      1  cdn.example-bad.test
```

---

## 8. Challenges Faced

These are real problems that came up while building and testing this tool.

1. **File extensions look exactly like domains.** `notes.md`, `report.log` and
   `invoice.txt` all match a normal domain pattern perfectly - `notes.md` looks
   like a host in the `.md` TLD. The first version of the tool happily reported
   `invoice.txt` as a domain. The fix was a blocklist of common file extensions
   checked against the last label of each match. This is a trade-off: a few real
   domains that end in an extension-like TLD (`.so` shared objects, `.pl` Perl
   scripts) will still be missed, which is the safer direction to be wrong in
   for a false-positive-sensitive tool.

2. **The e-mail host was being counted twice.** In the sample,
   `dropbox-agent@example-bad.test` produced *two* entries: the e-mail address,
   and the domain `example-bad.test`. The brief explicitly asks for the domain
   to be counted only if it also appears somewhere on its own. I solved this by
   recording the start and end position of every e-mail match first, then
   skipping any domain match that falls inside one of those spans. A standalone
   mention of the same domain is a different span, so it is still counted.

3. **Hashes of different lengths can overlap.** MD5 is 32 hex characters, SHA-1
   is 40 and SHA-256 is 64, so a naive "find 32 hex characters" pattern would
   also fire four times inside a single SHA-256 value. Word boundaries (`\b`)
   are what prevent this: inside a 64-character digest, the character after the
   32nd is still a hex digit, so there is no boundary there and the short
   pattern cannot match.

4. **Non-UTF-8 bytes killed the whole run.** The first version opened the file
   with plain UTF-8 decoding, and one stray byte in a log was enough to raise
   `UnicodeDecodeError` and lose the entire analysis. Reading with
   `errors="replace"` turns the bad byte into a replacement character and keeps
   the rest of the file usable.

5. **Private addresses are not all equally "private".** Python's `ipaddress`
   module classifies the RFC 5737 documentation ranges (`203.0.113.0/24`,
   `198.51.100.0/24`, `192.0.2.0/24`) as *private*. That is technically true,
   but those ranges are the standard placeholders used in reports and are
   perfectly safe to publish - and they are exactly what the sample file uses.
   Skipping them would have made the tool return nothing on its own sample data.
   I added an explicit exception so documentation addresses are always reported,
   while RFC 1918 addresses (`10.x`, `192.168.x`, `172.16-31.x`) stay opt-in.

6. **Some version numbers are valid IP addresses.** A string like `1.2.3.4` is a
   real, valid IPv4 address, so a version number in a report can be reported as
   an IOC. Validating with `ipaddress` removes the impossible ones (`999.1.1.1`)
   but cannot help with this case, because `1.2.3.4` genuinely is an address.
   This remains a known limitation rather than a bug.

---

## 9. Future Improvements

1. **IPv6 support.** Only IPv4 is extracted today. IPv6 addresses are common in
   modern logs and would need a separate pattern and validation pass.
2. **Defanged input.** The tool can *produce* defanged output, but it cannot yet
   *read* a report that already uses `hxxp://` and `example[.]com`. Being able to
   parse both styles would make it work on shared threat-intel feeds.
3. **Domain reputation lookup.** An optional `--enrich` flag that queries a
   public reputation service and adds a "known bad / unknown" column. This would
   be strictly opt-in, because it would make the tool talk to the network and
   would reveal the indicators to a third party.
4. **Context around each match.** Print the line number and the surrounding text
   for each indicator, so an analyst can see *why* a string was flagged without
   opening the source file.
5. **A confidence score.** Rank indicators by how strongly they look like real
   infrastructure - for example an attacker IP that appears in a log *and* inside
   a URL is more convincing than one that appears once in a sentence.
6. **A `--strict` mode** that chokes on ambiguous matches instead of dropping
   them, for analysts who would rather review the noise than miss a real
   indicator.

---

## Safety Note

Only run this tool on files, systems and data you are **authorised to analyse**.
Threat reports, e-mail headers and logs often contain personal data and
customer information; treat the output with the same care as the input.

Use `--defang` before sharing results outside your own team. A live,
clickable link to an attacker's infrastructure can be accidentally visited, and
it also tells the attacker that their infrastructure has been identified.

The bundled sample file is entirely synthetic. Every IP address comes from the
RFC 5737 documentation ranges (`203.0.113.x`, `198.51.100.x`) which can never
belong to a real host, every hostname is a made-up `.test` name, and the hashes
are well-known test values. No real indicator is included.

The tool is **read-only**: it never modifies the file it analyses, places no
network calls, and writes only the report you explicitly request with `-o`.
