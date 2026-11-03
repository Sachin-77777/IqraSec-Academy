#!/usr/bin/env bash
# =============================================================================
#  SSH Log Analyzer  -  Bash-Tool/tool.sh
# -----------------------------------------------------------------------------
#  Purpose : Read-only analysis of a Linux authentication log (typically
#            /var/log/auth.log) that detects SSH brute-force activity and warns
#            when a successful login originates from a flagged attacker IP.
#  Author  : Sachin Shrestha
#  Version : 1.0
#  Target  : Kali Linux / Ubuntu (bash 4+, coreutils, GNU sed)
# -----------------------------------------------------------------------------
#  Design note: this is a forensic helper, so it NEVER edits the log it reads.
#  The only file it can ever write is the optional plain-text report (-o).
#
#  Exit codes
#     0 -> analysis completed successfully
#     1 -> usage error (unknown option, bad argument, missing value)
#     2 -> file error (log missing, unreadable, empty, or report not writable)
# =============================================================================

# `pipefail` makes a failure inside a pipeline (e.g. "grep | sort") visible
# instead of silently returning the status of the last command.
# We deliberately do NOT use `set -e`: grep exits with status 1 when it simply
# finds no match, which is a normal result for this tool, not an error.
set -o pipefail

VERSION="1.0"
AUTHOR="Sachin Shrestha"
PROGNAME="$(basename "$0")"

# --- Defaults (can all be overridden on the command line) --------------------
LOG_FILE="/var/log/auth.log"   # -f : log to analyse
THRESHOLD=5                    # -t : failed attempts needed to flag an IP
TOP_COUNT=5                    # -n : how many rows to show in "top" lists
OUTPUT_FILE=""                 # -o : optional report destination

# -----------------------------------------------------------------------------
#  Colour handling.
#  Running the tool interactively should be pleasant to read, but the moment the
#  output is piped or redirected (into `less`, `mail`, a file, CI logs, ...) the
#  ANSI escape codes become junk. So we test once whether stdout is a terminal
#  and simply blank out the colour variables when it is not.
# -----------------------------------------------------------------------------
if [ -t 1 ]; then
    C_RESET=$'\033[0m'
    C_BOLD=$'\033[1m'
    C_RED=$'\033[31m'
    C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'
    C_CYAN=$'\033[36m'
else
    C_RESET=""
    C_BOLD=""
    C_RED=""
    C_GREEN=""
    C_YELLOW=""
    C_CYAN=""
fi

# =============================================================================
#  Small output helpers (all write to stdout so they can be captured/redirected)
# =============================================================================

# Print the usage/help text. Called by -h and after any usage error.
usage() {
    cat <<EOF
${C_BOLD}SSH Log Analyzer${C_RESET} - detect SSH brute-force activity in an auth log

Usage:
  $PROGNAME [-f <file>] [-t <number>] [-n <number>] [-o <file>] [-h]

Options:
  -f <file>    Log file to analyse        (default: $LOG_FILE)
  -t <number>  Failed attempts needed to flag an IP as suspicious (default: $THRESHOLD)
  -n <number>  How many top entries to display (default: $TOP_COUNT)
  -o <file>    Also save the report to this plain-text file
  -h           Show this help and exit

Examples:
  $PROGNAME -f samples/sample_auth.log
  $PROGNAME -f samples/sample_auth.log -t 3 -n 10
  $PROGNAME -f /var/log/auth.log -o report.txt

Exit codes: 0 = success, 1 = usage error, 2 = file error
Only use this tool on systems and logs you are authorised to analyse.
EOF
}

# Print an error message on stderr (so it never pollutes a redirected report).
error() {
    printf '%s[ERROR]%s %s\n' "$C_RED" "$C_RESET" "$1" >&2
}

# Print a section heading plus an underline, for a tidy report layout.
print_heading() {
    printf '\n%s%s%s\n' "$C_BOLD$C_CYAN" "$1" "$C_RESET"
    printf '%s\n' "----------------------------------------------------------------"
}

# =============================================================================
#  Input validation helpers
# =============================================================================

# Return 0 only when the argument is a whole number greater than zero.
# We use a `case` pattern instead of `[ -gt ]` because a non-numeric string
# would make `-gt` print a syntax error to stderr, which is ugly for users.
is_positive_integer() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;   # empty, or contains a non-digit character
        0)           return 1 ;;   # zero is not a useful threshold/count
        *)           return 0 ;;
    esac
}

# Validate the log file before any parsing happens, so the user gets one clear
# message instead of a wall of grep warnings. Returns 0 if usable, else 2.
check_file() {
    if [ ! -e "$LOG_FILE" ]; then
        error "Log file not found: $LOG_FILE"
        printf '        Hint: pass a different log with -f, e.g. -f %s\n' "samples/sample_auth.log" >&2
        return 2
    fi

    if [ ! -f "$LOG_FILE" ]; then
        error "Not a regular file: $LOG_FILE"
        return 2
    fi

    if [ ! -r "$LOG_FILE" ]; then
        error "Log file is not readable: $LOG_FILE"
        printf '        Hint: authentication logs are usually root-only. Try: sudo %s -f %s\n' \
               "$PROGNAME" "$LOG_FILE" >&2
        return 2
    fi

    if [ ! -s "$LOG_FILE" ]; then
        error "Log file is empty: $LOG_FILE"
        return 2
    fi

    return 0
}

# =============================================================================
#  Parsing helpers - each one prints a simple, pipe-friendly text stream
# =============================================================================

# Feed the log to the pipeline, minus a possible UTF-8 byte-order mark.
# Why: logs copied to, or generated on, Windows often start with the three
# invisible BOM bytes (EF BB BF). They are harmless to grep, but they would
# cling to the very first timestamp and make it look corrupted in the report,
# so we strip them from the first line only.
read_log() {
    sed '1s/^\xef\xbb\xbf//' "$LOG_FILE" 2>/dev/null
}

# Print "<ip> <username>" for every failed-password line.
# Handles the two sshd flavours:
#   "Failed password for root from 203.0.113.45 port 51234 ssh2"
#   "Failed password for invalid user admin from 203.0.113.45 port 51234 ssh2"
parse_failed() {
    read_log \
        | grep -E 'Failed password for' \
        | sed -E 's/.*Failed password for (invalid user )?([^ ]+) from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*/\3 \2/'
}

# Print "<ip> <username>" for every successful login (password or public key).
parse_success() {
    read_log \
        | grep -E 'Accepted (password|publickey) for' \
        | sed -E 's/.*Accepted (password|publickey) for ([^ ]+) from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*/\3 \2/'
}

# Print "count ip" for every source IP, highest count first.
# `uniq -c` pads its output with spaces, so we normalise with awk before
# sorting numerically; the secondary sort keeps ties alphabetical and therefore
# reproducible between runs (nice when the output is pasted into a report).
failed_ip_counts() {
    parse_failed \
        | awk '{print $1}' \
        | sort \
        | uniq -c \
        | awk '{print $1, $2}' \
        | sort -k1,1nr -k2,2
}

# Print "count username" for every targeted account, highest count first,
# but only for the first TOP_COUNT entries.
failed_user_counts() {
    parse_failed \
        | awk '{print $2}' \
        | sort \
        | uniq -c \
        | awk '{print $1, $2}' \
        | sort -k1,1nr -k2,2 \
        | head -n "$TOP_COUNT"
}

# Print just the IP addresses whose failure count reached the threshold.
flagged_ips() {
    failed_ip_counts | awk -v t="$THRESHOLD" '$1 >= t {print $2}'
}

# Print "<ip> <user>" for successful logins coming from a flagged IP.
# Building the "bad" set inside awk once is much faster than re-scanning the
# flagged list for every successful line, and scales to large logs.
suspicious_success() {
    local flagged
    flagged="$(flagged_ips)"
    [ -z "$flagged" ] && return 0

    parse_success | awk -v list="$flagged" '
        BEGIN { n = split(list, a, "\n"); for (i = 1; i <= n; i++) bad[a[i]] = 1 }
        bad[$1] { print $0 }
    '
}

# =============================================================================
#  Counting helpers used by the summary block
# =============================================================================

# Number of lines in the log (the "how much did we actually read" figure).
count_lines() {
    wc -l < "$LOG_FILE" | tr -d ' '
}

# Total failed-password events. `grep -c` prints 0 and exits 1 when there are
# no matches, which is fine here because we only consume the printed number.
count_failed() {
    read_log | grep -c -E 'Failed password for' || true
}

# Total successful logins.
count_success() {
    read_log | grep -c -E 'Accepted (password|publickey) for' || true
}

# Number of distinct IPs that produced at least one failure.
count_unique_attackers() {
    parse_failed | awk '{print $1}' | sort -u | wc -l | tr -d ' '
}

# Attempts made against accounts that do not even exist on the machine - a
# strong signal of automated scanning, so the brief asks for it separately.
count_invalid_users() {
    read_log | grep -c -E 'Failed password for invalid user' || true
}

# Timestamp of the first / last failed attempt, in the log's own order.
# We keep three space-separated fields because classic syslog timestamps are
# "Mon DD HH:MM:SS" and we want them whole.
first_failed_time() {
    read_log | grep -E 'Failed password for' | awk '{print $1" "$2" "$3}' | head -n 1
}

last_failed_time() {
    read_log | grep -E 'Failed password for' | awk '{print $1" "$2" "$3}' | tail -n 1
}

# =============================================================================
#  Report rendering
# =============================================================================

# Build and print the complete report on stdout. Kept as one function so the
# caller can capture it once, show it on screen, and optionally save a copy.
generate_report() {
    local lines failed success attackers invalid_users first_seen last_seen

    lines=$(count_lines)
    failed=$(count_failed)
    success=$(count_success)
    attackers=$(count_unique_attackers)
    invalid_users=$(count_invalid_users)
    first_seen=$(first_failed_time)
    last_seen=$(last_failed_time)

    # ---- Header -------------------------------------------------------------
    printf '%s\n' "================================================================"
    printf '%s SSH Log Analyzer  v%s%s\n' "$C_BOLD" "$VERSION" "$C_RESET"
    printf '%s Read-only analysis - the log itself was not modified%s\n' "$C_CYAN" "$C_RESET"
    printf '%s\n' "================================================================"
    printf 'Log file        : %s\n' "$LOG_FILE"
    printf 'Threshold       : %s failed attempts flags an IP\n' "$THRESHOLD"
    printf 'Generated       : %s\n' "$(date)"

    # ---- 1. Summary ---------------------------------------------------------
    print_heading "1. SUMMARY"
    printf '  %-22s: %s\n' "Lines scanned"        "$lines"
    printf '  %-22s: %s\n' "Failed logins"        "$failed"
    printf '  %-22s: %s\n' "Successful logins"    "$success"
    printf '  %-22s: %s\n' "Unique attacker IPs"  "$attackers"

    # Nothing else is meaningful without failures, so stop here.
    if [ "$failed" -eq 0 ]; then
        printf '\n%sNo failed login attempts found - nothing to report.%s\n' "$C_GREEN" "$C_RESET"
        return 0
    fi

    printf '  %-22s: %s\n' "Invalid-user attempts" "$invalid_users"
    printf '  %-22s: %s (first)\n' "Failed attempts from" "${first_seen:-unknown}"
    printf '  %-22s: %s (last)\n'  "Failed attempts to"   "${last_seen:-unknown}"

    # ---- 2. Top source IPs --------------------------------------------------
    print_heading "2. TOP $TOP_COUNT SOURCE IPs BY FAILED ATTEMPTS"
    printf '  %5s  %s\n' "COUNT" "IP ADDRESS"
    failed_ip_counts | head -n "$TOP_COUNT" | while read -r cnt ip; do
        printf '  %5s  %s\n' "$cnt" "$ip"
    done

    # ---- 3. Top targeted usernames -----------------------------------------
    print_heading "3. TOP $TOP_COUNT TARGETED USERNAMES"
    printf '  %5s  %s\n' "COUNT" "USERNAME"
    failed_user_counts | while read -r cnt user; do
        printf '  %5s  %s\n' "$cnt" "$user"
    done
    printf '\n  Invalid (non-existent) user attempts: %s\n' "$invalid_users"

    # ---- 4. Suspicious IPs --------------------------------------------------
    print_heading "4. SUSPICIOUS IPs (>= $THRESHOLD FAILED ATTEMPTS)"
    local flagged
    flagged="$(flagged_ips)"
    if [ -z "$flagged" ]; then
        printf '  %sNone - no IP reached the threshold of %s.%s\n' "$C_GREEN" "$THRESHOLD" "$C_RESET"
    else
        failed_ip_counts | awk -v t="$THRESHOLD" '$1 >= t {print $1, $2}' | while read -r cnt ip; do
            printf '  %s[ALERT]%s %-16s %s failed attempts\n' "$C_RED" "$C_RESET" "$ip" "$cnt"
        done
    fi

    # ---- 5. Successful logins from flagged IPs ------------------------------
    print_heading "5. SUCCESSFUL LOGINS FROM FLAGGED IPs"
    local from_bad
    from_bad="$(suspicious_success)"
    if [ -z "$from_bad" ]; then
        printf '  %sGood news - no successful login came from a flagged IP.%s\n' "$C_GREEN" "$C_RESET"
    else
        printf '  %s[CRITICAL: possible compromise]%s\n' "$C_YELLOW" "$C_RESET"
        printf '  %s\n' "$from_bad" | while read -r ip user; do
            printf '  %s[CRITICAL]%s %-16s logged in as %s\n' "$C_YELLOW" "$C_RESET" "$ip" "$user"
        done
        printf '\n  Action: verify these accounts, rotate their credentials and review\n'
        printf '  the sessions they opened.\n'
    fi

    # ---- 6. Timeframe -------------------------------------------------------
    print_heading "6. FAILED-ATTEMPT TIMEFRAME"
    printf '  First failed attempt : %s\n' "${first_seen:-unknown}"
    printf '  Last  failed attempt : %s\n' "${last_seen:-unknown}"

    printf '\n%sAnalysis complete.%s\n' "$C_GREEN" "$C_RESET"
}

# Write the report to disk with the colour codes stripped out, so the saved
# copy stays readable in any editor or when mailed to a colleague.
save_report() {
    local content="$1"
    if ! printf '%s\n' "$content" | sed -E 's/\x1b\[[0-9;]*[A-Za-z]//g' > "$OUTPUT_FILE" 2>/dev/null; then
        error "Could not write report to: $OUTPUT_FILE"
        return 2
    fi
    printf '\n%sReport saved to: %s%s\n' "$C_GREEN" "$OUTPUT_FILE" "$C_RESET"
}

# =============================================================================
#  Entry point
# =============================================================================

main() {
    local opt report

    # getopts with a leading ':' lets us detect a missing option argument
    # ourselves (case ':') and give a friendlier message than the shell default.
    while getopts ":f:t:n:o:h" opt; do
        case "$opt" in
            f) LOG_FILE="$OPTARG" ;;
            t)
                if ! is_positive_integer "$OPTARG"; then
                    error "Threshold must be a positive whole number, got: '$OPTARG'"
                    return 1
                fi
                THRESHOLD="$OPTARG"
                ;;
            n)
                if ! is_positive_integer "$OPTARG"; then
                    error "Count must be a positive whole number, got: '$OPTARG'"
                    return 1
                fi
                TOP_COUNT="$OPTARG"
                ;;
            o) OUTPUT_FILE="$OPTARG" ;;
            h) usage; return 0 ;;
            :)
                error "Option -$OPTARG requires an argument"
                printf '        Run "%s -h" for usage.\n' "$PROGNAME" >&2
                return 1
                ;;
            \?)
                error "Unknown option: -$OPTARG"
                printf '        Run "%s -h" for usage.\n' "$PROGNAME" >&2
                return 1
                ;;
        esac
    done

    # Reject stray positional arguments - a common slip is "-t 5 logfile".
    shift $((OPTIND - 1))
    if [ "$#" -gt 0 ]; then
        error "Unexpected argument: '$1'"
        printf '        Use -f to select the log file, e.g. -f %s\n' "$1" >&2
        return 1
    fi

    # Validate the input before doing any work.
    check_file || return $?

    report="$(generate_report)"
    printf '%s\n' "$report"

    # Optional copy on disk (plain text, no escape codes).
    if [ -n "$OUTPUT_FILE" ]; then
        save_report "$report" || return $?
    fi

    return 0
}

main "$@"
exit $?
