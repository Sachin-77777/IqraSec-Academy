# Bash Tool - SSH Log Analyzer

## 1. Tool Name

**SSH Log Analyzer** (`tool.sh`)

---

## 2. Objective

Read a Linux authentication log (such as `/var/log/auth.log`) and report SSH
brute-force activity in a clear, human-readable form.

Every time somebody fails to log in over SSH, `sshd` writes a line into the
auth log. One failure is normal - a user mistyped their password. But hundreds
of failures from the same IP address in a short space of time is the classic
signature of a brute-force attack, where a script tries password after
password until one works.

This tool counts those failures, shows which IP addresses and usernames are
being targeted, and - most importantly - warns you when a **successful** login
comes from an IP address that had already failed many times. That last case is
the one that matters most, because it can mean the attacker eventually guessed
the right password.

---

## 3. Features

| # | Feature |
|---|---------|
| 1 | Summary: lines scanned, failed logins, successful logins, unique attacker IPs |
| 2 | Top N source IP addresses by number of failed attempts |
| 3 | Top N targeted usernames, with invalid (non-existent) user attempts counted separately |
| 4 | **SUSPICIOUS IPs**: any IP with failures at or above the threshold, marked `[ALERT]` |
| 5 | **Successful logins from a flagged IP**, marked `[CRITICAL: possible compromise]` |
| 6 | First and last timestamp of failed attempts, so you can see the attack window |

Extra behaviour worth knowing:

- **Coloured output** on a terminal. Colour switches itself **off** when the
  output is piped or redirected, so saved reports stay clean.
- **`-o` writes a plain-text copy** of the report (colour codes stripped out).
- **Read-only**: the log file is never modified. The only file the script can
  ever write is the optional report requested with `-o`.
- **Clear error messages and exit codes** instead of raw shell errors:
  `0` = success, `1` = usage error, `2` = file error.
- **Configurable threshold** - every environment is different, so the number of
  failures that counts as "suspicious" is a command-line option, not a
  hard-coded constant.

---

## 4. Requirements

- **Bash 4 or newer** (any normal Kali Linux or Ubuntu install).
- Standard Unix tools that are already present on those systems:
  `grep`, `awk`, `sed`, `sort`, `uniq`, `cut`, `wc`, `head`, `tail`, `date`.
- **No installation, no `pip`, no `apt install`.** Nothing else is needed.

> Note: the default log path is `/var/log/auth.log`, which only exists on Linux.
> That is why the sample log in `samples/` is used for the demonstrations below.

---

## 5. How to Run

```bash
cd Bash-Tool

# 1. Make the script executable (only needed once)
chmod +x tool.sh

# 2. Analyse the bundled sample log
./tool.sh -f samples/sample_auth.log

# 3. Show the built-in help
./tool.sh -h
```

### Options

| Option | Meaning | Default |
|--------|---------|---------|
| `-f <file>` | Log file to analyse | `/var/log/auth.log` |
| `-t <number>` | Failed attempts needed to flag an IP as suspicious | `5` |
| `-n <number>` | How many top entries to display | `5` |
| `-o <file>` | Also save the report to this plain-text file | *(none)* |
| `-h` | Show help and exit | |

---

## 6. Example Usage

```bash
# Analyse the sample log with the default threshold (5 failures)
./tool.sh -f samples/sample_auth.log

# Be more sensitive: flag an IP after 3 failures, and show the top 10 rows
./tool.sh -f samples/sample_auth.log -t 3 -n 10

# Analyse the real log on a Linux box (needs sudo - the file is root-only)
sudo ./tool.sh -f /var/log/auth.log

# Save a copy of the report next to the terminal output
./tool.sh -f samples/sample_auth.log -o report.txt

# Pipe into a pager; colour turns itself off automatically
./tool.sh -f samples/sample_auth.log | less

# Show the help text
./tool.sh -h
```

---

## 7. Example Output

This is the **real output** produced by running
`./tool.sh -f samples/sample_auth.log` against the bundled sample log:

```text
================================================================
 SSH Log Analyzer  v1.0
 Read-only analysis - the log itself was not modified
================================================================
Log file        : samples/sample_auth.log
Threshold       : 5 failed attempts flags an IP
Generated       : Tue, Nov  3, 2026  9:53:15 AM

1. SUMMARY
----------------------------------------------------------------
  Lines scanned         : 84
  Failed logins         : 15
  Successful logins     : 5
  Unique attacker IPs   : 4
  Invalid-user attempts : 6
  Failed attempts from  : Oct 27 09:14:11 (first)
  Failed attempts to    : Oct 27 10:20:45 (last)

2. TOP 5 SOURCE IPs BY FAILED ATTEMPTS
----------------------------------------------------------------
  COUNT  IP ADDRESS
      7  203.0.113.45
      5  198.51.100.7
      2  203.0.113.66
      1  198.51.100.23

3. TOP 5 TARGETED USERNAMES
----------------------------------------------------------------
  COUNT  USERNAME
      6  root
      4  admin
      1  backup
      1  oracle
      1  pi

  Invalid (non-existent) user attempts: 6

4. SUSPICIOUS IPs (>= 5 FAILED ATTEMPTS)
----------------------------------------------------------------
  [ALERT] 203.0.113.45     7 failed attempts
  [ALERT] 198.51.100.7     5 failed attempts

5. SUCCESSFUL LOGINS FROM FLAGGED IPs
----------------------------------------------------------------
  [CRITICAL: possible compromise]
  [CRITICAL] 203.0.113.45     logged in as root

  Action: verify these accounts, rotate their credentials and review
  the sessions they opened.

6. FAILED-ATTEMPT TIMEFRAME
----------------------------------------------------------------
  First failed attempt : Oct 27 09:14:11
  Last  failed attempt : Oct 27 10:20:45

Analysis complete.
```

*(The `Generated` line shows your own current date and time, so it will be
different when you run it.)*

### How to read this report

- **Section 1** is the "how bad is it" line. 84 lines were read; 15 of them were
  failed logins from 4 different IP addresses.
- **Section 2** ranks the sources. `203.0.113.45` produced 7 failures - well over
  the threshold of 5.
- **Section 3** shows which accounts were attacked. `root` was tried 6 times,
  which is normal for automated attacks because `root` exists on almost every
  Linux machine. Six of the attempts used **invalid** usernames such as
  `oracle` and `postgres`, which is a strong sign of a script that is guessing
  account names rather than a person who typed a wrong password.
- **Section 4** is the alert list - these are the IPs you would go and block.
- **Section 5** is the important one. `203.0.113.45` failed 7 times **and then
  logged in successfully as root**. That is not a mistake; that is either a
  lucky guess or a leaked password. Treat it as a possible compromise.
- **Section 6** shows the attack happened between 09:14 and 10:20.

### Raising the sensitivity

Running the same log with a lower threshold uses the same data but a different
rule:

```bash
./tool.sh -f samples/sample_auth.log -t 3 -n 2
```

```text
2. TOP 2 SOURCE IPs BY FAILED ATTEMPTS
----------------------------------------------------------------
  COUNT  IP ADDRESS
      7  203.0.113.45
      5  198.51.100.7

3. TOP 2 TARGETED USERNAMES
----------------------------------------------------------------
  COUNT  USERNAME
      6  root
      4  admin

  Invalid (non-existent) user attempts: 6

4. SUSPICIOUS IPs (>= 3 FAILED ATTEMPTS)
----------------------------------------------------------------
  [ALERT] 203.0.113.45     7 failed attempts
  [ALERT] 198.51.100.7     5 failed attempts
```

**Why this matters:** `203.0.113.66` had 2 failures in the sample log. With the
default threshold of 5 it is ignored; it is only flagged if you lower the
threshold. This is the normal trade-off in detection work - a low threshold
catches more but also produces more false alarms.

### Error handling examples

```text
$ ./tool.sh -f nope.log
[ERROR] Log file not found: nope.log
        Hint: pass a different log with -f, e.g. -f samples/sample_auth.log
$ echo $?
2

$ ./tool.sh -f samples/sample_auth.log -t abc
[ERROR] Threshold must be a positive whole number, got: 'abc'
$ echo $?
1

$ ./tool.sh -f samples/sample_auth.log -z
[ERROR] Unknown option: -z
        Run "tool.sh -h" for usage.
$ echo $?
1

$ ./tool.sh -f samples/sample_auth.log extra.log
[ERROR] Unexpected argument: 'extra.log'
        Use -f to select the log file, e.g. -f extra.log
$ echo $?
1
```

---

## 8. Challenges Faced

These are real problems that came up while building and testing this script.

1. **Timestamps are not one field.** A syslog timestamp looks like
   `Oct 27 09:14:11` - three space-separated fields with no year. Taking "the
   first column" gives you only `Oct`. I had to capture the first three columns
   together (`awk '{print $1" "$2" "$3}'`) before I could print a usable time
   range.

2. **Colour output breaks when it is piped.** My first version always printed
   ANSI colour codes. The moment the report was sent to a file or into `less`,
   the file filled up with junk like `^[[31m`. The fix was to test whether
   stdout is really a terminal (`[ -t 1 ]`) once at startup and blank out the
   colour variables if it is not. The `-o` report also strips the codes before
   writing, so the saved copy is readable anywhere.

3. **`grep` returning "no match" looks like a crash.** `grep` exits with status
   `1` when it finds nothing, which is a completely normal result here. With
   `set -e` that would abort the script on a perfectly healthy log that simply
   had no failed logins. I avoided `set -e` and handled each case, then
   explicitly tested a log with zero failures to be sure the tool says
   "nothing to report" instead of dying.

4. **A hidden byte-order mark corrupted the first timestamp.** My test file was
   created on Windows, which silently added a UTF-8 BOM (three invisible bytes)
   at the start of the file. The first timestamp came out looking like
   `Oct 27 09:00:00`. I added a small `read_log()` helper that strips the BOM
   from the first line only, which is a real-world problem for anyone who copies
   logs to a Windows machine to analyse them.

5. **Permission errors cannot be fully reproduced on Windows.** The
   "file is not readable" branch (`chmod 000` plus a hint to run with `sudo`)
   is written and syntax-checked, but Git Bash on Windows does not enforce
   Unix permission bits - Windows uses ACLs instead - so `chmod 000 file` still
   lets the file be read. That specific branch therefore could only be reviewed
   by reading the code, not by a live failure.

6. **`shellcheck` was not available in my test environment,** so the script was
   validated with `bash -n tool.sh` (syntax check) plus a full manual run of
   every option. If `shellcheck` is installed, it is worth running.

---

## 9. Future Improvements

1. **GeoIP / ASN lookup** - add a `--geo` flag that shows the country or hosting
   provider behind each attacker IP, so the report reads like
   "203.0.113.45 (Example Hosting, AS64500)".
2. **Time-window awareness** - the brute-force check currently counts failures
   across the whole file. A real brute force is a *burst*, so the tool should
   only count failures inside a rolling window (for example 60 seconds) and
   ignore slow, low-and-slow guessing.
3. **Allow-list / ignore file** - a small file of known-good IPs (the office, the
   VPN, the monitoring server) that are never flagged, to cut false positives.
4. **Machine-readable output** - an `--json` or `--csv` mode so the report can be
   fed into a dashboard or a ticketing system instead of only being read by a
   human.
5. **Support more log formats** - the parser currently understands `sshd` lines.
   It could be extended to read `journalctl -u ssh` output and cloud
   authentication logs, so the same tool works on more systems.
6. **Automatic blocking** - generate a ready-to-paste `iptables`/`ufw` blocklist
   from the flagged IPs. (This would need to be opt-in and clearly labelled,
   because automatically blocking addresses can lock out real users.)

---

## Safety Note

This tool reads authentication logs, which contain IP addresses and usernames
and are usually readable by `root` only. **Only run it on systems and logs you
own or are explicitly authorised to analyse.**

The bundled sample log is entirely synthetic. Every IP address in it comes from
the RFC 5737 documentation ranges (`203.0.113.x`, `198.51.100.x`) which are
reserved for examples and can never belong to a real host, and every hostname is
a made-up `.test` name. No real person, machine or credential was used.

The script is strictly read-only: it never modifies, moves or deletes the log it
reads, and the only file it can write is the report you ask for with `-o`.
