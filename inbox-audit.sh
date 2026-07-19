#!/usr/bin/env bash
#
# inbox-audit — audit one domain's email deliverability posture.
#
# Read-only diagnostics: DNS lookups and TLS probes with timeouts.
# Never sends email. Never calls third-party APIs.
#
# Usage: ./inbox-audit.sh example.com [--selector s1[,s2]] [--no-smtp] [--json]
#
# Exit codes: 0 all checks pass, 1 warnings, 2 failures, 3 usage/dependency error.
#
# https://github.com/inboxauditkit/inbox-audit — MIT license.

set -u

VERSION="1.0.0"

# Common DKIM selectors probed when --selector is not given.
DKIM_PROBE_SELECTORS=(default mail dkim s1 s2 k1 google)

DIG_OPTS=(+time=5 +tries=3)

DOMAIN=""
SELECTORS=""
NO_SMTP=0
JSON=0

WARNINGS=0
FAILURES=0

usage() {
  cat <<EOF
inbox-audit $VERSION — audit one domain's email deliverability posture.

Usage: $0 <domain> [options]

Options:
  --selector s1[,s2]  DKIM selector(s) to check (default: probe a common list)
  --no-smtp           skip the port-25 TLS probe (many ISPs block port 25)
  --json              machine-readable output
  -h, --help          show this help

Read-only: DNS lookups and TLS handshakes only. Never sends email.
Exit codes: 0 all pass, 1 warnings, 2 failures, 3 usage/dependency error.
EOF
}

die() {
  printf 'inbox-audit: %s\n' "$1" >&2
  exit 3
}

check_deps() {
  if ((BASH_VERSINFO[0] < 4)); then
    die "bash 4 or newer required (found $BASH_VERSION)"
  fi
  local dep missing=""
  for dep in dig openssl; do
    command -v "$dep" >/dev/null 2>&1 || missing="$missing $dep"
  done
  if [[ -n "$missing" ]]; then
    die "missing required tool(s):$missing — install bind-utils/dnsutils and openssl"
  fi
}

parse_args() {
  while (($# > 0)); do
    case "$1" in
      --selector)
        [[ $# -ge 2 ]] || die "--selector needs a value"
        SELECTORS="$2"
        shift
        ;;
      --selector=*)
        SELECTORS="${1#--selector=}"
        ;;
      --no-smtp)
        # shellcheck disable=SC2034  # consumed by the TLS check (v1.0.0)
        NO_SMTP=1
        ;;
      --json)
        JSON=1
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      -*)
        die "unknown option: $1 (see --help)"
        ;;
      *)
        [[ -z "$DOMAIN" ]] || die "exactly one domain expected"
        DOMAIN="$1"
        ;;
    esac
    shift
  done

  [[ -n "$DOMAIN" ]] || { usage >&2; exit 3; }

  # normalize: lowercase, strip trailing dot
  DOMAIN="${DOMAIN,,}"
  DOMAIN="${DOMAIN%.}"
  [[ "$DOMAIN" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] \
    || die "'$DOMAIN' does not look like a domain name"

}

# ---------- output helpers ----------

# Human mode prints as it goes; --json collects per-check records instead.
JSON_CHECKS=""
CUR_ID=""
CUR_VERDICT=""
CUR_TEXT=""
CUR_NOTES=()
CUR_FIXES=()

json_escape() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  printf '%s' "$s"
}

# json_flush — close the in-progress check record and append it to JSON_CHECKS
json_flush() {
  [[ -n "$CUR_ID" ]] || return 0
  local x notes="" fixes=""
  if ((${#CUR_NOTES[@]} > 0)); then
    for x in "${CUR_NOTES[@]}"; do notes+="${notes:+,}\"$(json_escape "$x")\""; done
  fi
  if ((${#CUR_FIXES[@]} > 0)); then
    for x in "${CUR_FIXES[@]}"; do fixes+="${fixes:+,}\"$(json_escape "$x")\""; done
  fi
  JSON_CHECKS+="${JSON_CHECKS:+,}{\"check\":\"$CUR_ID\",\"verdict\":\"$CUR_VERDICT\","
  JSON_CHECKS+="\"detail\":\"$(json_escape "$CUR_TEXT")\",\"notes\":[$notes],\"fixes\":[$fixes]}"
  CUR_ID=""
  CUR_NOTES=()
  CUR_FIXES=()
}

# emit <PASS|WARN|FAIL|SKIP> <check-name> <one-line explanation>
emit() {
  local verdict=$1 name=$2 text=$3
  case "$verdict" in
    WARN) WARNINGS=$((WARNINGS + 1)) ;;
    FAIL) FAILURES=$((FAILURES + 1)) ;;
  esac
  if ((JSON)); then
    json_flush
    CUR_ID=$(tr '[:upper:]' '[:lower:]' <<<"$name")
    CUR_VERDICT=$verdict
    CUR_TEXT=$text
  else
    printf '[%s] %-6s %s\n' "$verdict" "$name" "$text"
  fi
}

# fix <one-line fix hint> — printed under a WARN/FAIL emit
fix() {
  if ((JSON)); then
    CUR_FIXES+=("$1")
  else
    printf '       fix: %s\n' "$1"
  fi
}

# note <detail line> — extra context under an emit
note() {
  if ((JSON)); then
    CUR_NOTES+=("$1")
  else
    printf '       %s\n' "$1"
  fi
}

# ---------- DNS helpers ----------

# dns_txt <name> — one TXT record per line, chunks joined, quotes stripped.
# Returns dig's exit code (non-zero = query problem, e.g. timeout).
dns_txt() {
  local out rc
  out=$(dig "${DIG_OPTS[@]}" +short TXT "$1" 2>/dev/null)
  rc=$?
  if ((rc != 0)); then
    # some networks silently drop large UDP DNS answers (no TC bit); retry TCP
    out=$(dig "${DIG_OPTS[@]}" +tcp +short TXT "$1" 2>/dev/null)
    rc=$?
  fi
  ((rc == 0)) || return "$rc"
  sed -e 's/" "//g' -e 's/^"//' -e 's/"$//' <<<"$out"
}

# dns_short <type> <name> — dig +short, addresses/hosts only (CNAME chain lines dropped)
dns_short() {
  local out rc
  out=$(dig "${DIG_OPTS[@]}" +short "$1" "$2" 2>/dev/null)
  rc=$?
  ((rc == 0)) || return "$rc"
  case "$1" in
    A)    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' <<<"$out" || true ;;
    AAAA) grep -E '^[0-9a-fA-F:]+$' <<<"$out" || true ;;
    *)    printf '%s\n' "$out" ;;
  esac
}

# worse <verdict-a> <verdict-b> — print the more severe of two verdicts
worse() {
  local v
  for v in FAIL WARN PASS; do
    if [[ "$1" == "$v" || "$2" == "$v" ]]; then
      printf '%s\n' "$v"
      return
    fi
  done
}

# ---------- check 1: SPF ----------

SPF_LOOKUPS=0
SPF_VISITED=""
SPF_DEPTH_HIT=0

# spf_record <domain> — print the domain's v=spf1 TXT record(s), one per line
spf_record() {
  local recs
  recs=$(dns_txt "$1") || return 1
  grep -iE '^v=spf1( |$)' <<<"$recs" || true
}

# spf_count_lookups <domain> <depth> — recursively count DNS-lookup mechanisms
# (include/a/mx/ptr/exists/redirect, RFC 7208 §4.6.4) into SPF_LOOKUPS.
spf_count_lookups() {
  local domain=$1 depth=$2 rec term lterm target
  if ((depth > 10)); then
    SPF_DEPTH_HIT=1
    return
  fi
  case " $SPF_VISITED " in *" $domain "*) return ;; esac
  SPF_VISITED="$SPF_VISITED $domain"
  rec=$(spf_record "$domain" | head -n1)
  [[ -n "$rec" ]] || return 0
  local -a terms
  read -ra terms <<<"$rec"
  for term in "${terms[@]}"; do
    term="${term#[-+~?]}"
    lterm="${term,,}"
    case "$lterm" in
      include:*|redirect=*)
        SPF_LOOKUPS=$((SPF_LOOKUPS + 1))
        target="${term#*[:=]}"
        # macro targets (%{...}) expand per-message; count but do not follow
        [[ "$target" == *%* ]] || spf_count_lookups "$target" $((depth + 1))
        ;;
      a|a:*|a/*|mx|mx:*|mx/*|ptr|ptr:*|exists:*)
        SPF_LOOKUPS=$((SPF_LOOKUPS + 1))
        ;;
    esac
  done
}

# spf_terminal_qualifier <domain> — print -all / ~all / ?all / +all / none,
# following redirect= chains (an SPF record's effective 'all' may live there).
spf_terminal_qualifier() {
  local domain=$1 hops=0 rec redirect
  while ((hops < 5)); do
    rec=$(spf_record "$domain" | head -n1)
    [[ -n "$rec" ]] || break
    if [[ "${rec,,}" =~ (^|[[:space:]])([-~?+]?)all([[:space:]]|$) ]]; then
      printf '%sall\n' "${BASH_REMATCH[2]:-+}"
      return
    fi
    redirect=$(grep -oiE '(^|[[:space:]])redirect=[^[:space:]]+' <<<"$rec" \
      | head -n1 | sed 's/.*=//')
    [[ -n "$redirect" ]] || break
    domain="$redirect"
    hops=$((hops + 1))
  done
  printf 'none\n'
}

check_spf() {
  local recs
  if ! recs=$(dns_txt "$DOMAIN"); then
    emit FAIL SPF "TXT lookup failed (DNS timeout or no response)"
    fix "check that $DOMAIN resolves and re-run"
    return
  fi
  local count
  count=$(grep -icE '^v=spf1( |$)' <<<"$recs") || true
  if ((count == 0)); then
    emit FAIL SPF "no v=spf1 record found"
    fix "publish a TXT record like \"v=spf1 mx -all\" listing every host that sends for you"
    return
  fi
  if ((count > 1)); then
    emit FAIL SPF "$count v=spf1 records found — receivers treat this as a permanent error (RFC 7208)"
    fix "merge every mechanism into one single v=spf1 record"
    return
  fi

  SPF_LOOKUPS=0 SPF_VISITED="" SPF_DEPTH_HIT=0
  spf_count_lookups "$DOMAIN" 0
  local qual verdict=PASS
  qual=$(spf_terminal_qualifier "$DOMAIN")

  ((SPF_LOOKUPS > 10)) && verdict=FAIL
  case "$qual" in
    "-all"|"~all") ;;
    *) verdict=FAIL ;;
  esac

  emit "$verdict" SPF "one v=spf1 record; $SPF_LOOKUPS/10 DNS lookups; terminal qualifier '$qual'"
  ((SPF_DEPTH_HIT)) && note "include/redirect chain deeper than 10 levels — lookup count is a lower bound"
  ((SPF_LOOKUPS > 10)) && \
    fix "over the 10-lookup limit (RFC 7208): flatten include: chains or drop unused mechanisms"
  case "$qual" in
    "~all") note "softfail '~all' is accepted; '-all' is the stricter finish once you trust the record" ;;
    "?all") fix "'?all' is neutral and protects nothing — finish the record with '-all'" ;;
    "+all") fix "'+all' authorizes the entire internet to send as you — finish the record with '-all'" ;;
    none)   fix "record never reaches an 'all' mechanism — finish the record with '-all'" ;;
  esac
}

# ---------- check 2: DKIM ----------

# tag_get <record> <tag> — value of a tag in a DKIM/DMARC tag=value record
tag_get() {
  tr ';' '\n' <<<"$1" \
    | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
    | grep -iE "^$2=" | head -n1 | sed 's/^[^=]*=//' | tr -d '[:space:]'
}

# dkim_key_bits <p-value-base64> — RSA modulus size in bits, empty if unparseable
dkim_key_bits() {
  printf '%s' "$1" | openssl base64 -d -A 2>/dev/null \
    | openssl pkey -pubin -inform DER -noout -text 2>/dev/null \
    | grep -oE '\([0-9]+ bit' | grep -oE '[0-9]+' | head -n1
}

check_dkim() {
  local -a sels lines
  local probing=0
  if [[ -n "$SELECTORS" ]]; then
    IFS=', ' read -ra sels <<<"$SELECTORS"
  else
    sels=("${DKIM_PROBE_SELECTORS[@]}")
    probing=1
  fi

  local sel raw rec found=0 verdict=PASS need_fix=""
  lines=()
  for sel in "${sels[@]}"; do
    raw=$(dns_txt "${sel}._domainkey.${DOMAIN}") || raw=""
    rec=$(grep -iE 'v=dkim1|p=' <<<"$raw" | head -n1) || true
    [[ -n "$rec" ]] || continue
    found=$((found + 1))

    local p k bits
    p=$(tag_get "$rec" p)
    k=$(tag_get "$rec" k)
    if ! grep -qiE '(^|;)[[:space:]]*p=' <<<"$rec"; then
      # p is a required tag — its absence usually means a truncated DNS answer
      verdict=FAIL
      lines+=("selector '$sel': record has no p= tag (malformed, or your resolver truncated the answer)")
      need_fix="verify with: dig @1.1.1.1 TXT ${sel}._domainkey.$DOMAIN — a DKIM record must carry p="
      continue
    fi
    if [[ -z "$p" ]]; then
      # p= present but empty means the key was revoked (RFC 6376 §3.6.1)
      verdict=FAIL
      lines+=("selector '$sel': key revoked (empty p= tag)")
      need_fix="publish a fresh public key, or stop signing with revoked selectors"
      continue
    fi
    if [[ "${k,,}" == "ed25519" ]]; then
      lines+=("selector '$sel': ed25519 key (RSA size thresholds do not apply)")
      continue
    fi
    bits=$(dkim_key_bits "$p")
    if [[ -z "$bits" ]]; then
      verdict=$(worse "$verdict" WARN)
      lines+=("selector '$sel': key present but could not be parsed to estimate size")
      need_fix="verify the p= value is valid base64 of an RSA public key"
    elif ((bits < 1024)); then
      verdict=FAIL
      lines+=("selector '$sel': ${bits}-bit RSA key — trivially crackable, receivers ignore it")
      need_fix="generate a 2048-bit key and publish it under a new selector"
    elif ((bits < 2048)); then
      verdict=$(worse "$verdict" WARN)
      lines+=("selector '$sel': ${bits}-bit RSA key — below the 2048-bit recommendation")
      need_fix="generate a 2048-bit key and publish it under a new selector"
    else
      lines+=("selector '$sel': ${bits}-bit RSA key")
    fi
  done

  if ((found == 0)); then
    if ((probing)); then
      emit FAIL DKIM "no DKIM key found at common selectors (${DKIM_PROBE_SELECTORS[*]})"
      fix "re-run with --selector <name> — your selector is in your signer config (e.g. opendkim KeyTable)"
    else
      emit FAIL DKIM "no DKIM record at ${SELECTORS//,/ or } for $DOMAIN"
      fix "publish the public key as TXT at <selector>._domainkey.$DOMAIN"
    fi
    return
  fi

  emit "$verdict" DKIM "$found selector(s) with a published key"
  local line
  for line in "${lines[@]}"; do
    note "$line"
  done
  [[ -n "$need_fix" ]] && fix "$need_fix"
}

# ---------- check 3: DMARC ----------

check_dmarc() {
  local raw
  if ! raw=$(dns_txt "_dmarc.$DOMAIN"); then
    emit FAIL DMARC "TXT lookup for _dmarc.$DOMAIN failed (DNS timeout or no response)"
    fix "check the resolver and re-run"
    return
  fi
  local count
  count=$(grep -icE '^v=dmarc1' <<<"$raw") || true
  if ((count == 0)); then
    emit FAIL DMARC "no v=DMARC1 record at _dmarc.$DOMAIN"
    fix "publish TXT \"v=DMARC1; p=none; rua=mailto:dmarc@$DOMAIN\" — then tighten to quarantine/reject"
    return
  fi
  if ((count > 1)); then
    emit FAIL DMARC "$count DMARC records found — receivers discard all of them (RFC 7489)"
    fix "keep exactly one record at _dmarc.$DOMAIN"
    return
  fi

  local rec p rua pct verdict=PASS ptxt
  rec=$(grep -iE '^v=dmarc1' <<<"$raw" | head -n1)
  p=$(tag_get "$rec" p)
  rua=$(tag_get "$rec" rua)
  pct=$(tag_get "$rec" pct)

  case "${p,,}" in
    reject|quarantine) ptxt="policy p=${p,,}" ;;
    none)
      verdict=WARN
      ptxt="policy p=none (monitoring only — failing mail is still delivered)"
      ;;
    "")
      verdict=FAIL
      ptxt="record has no p= policy tag and is invalid"
      ;;
    *)
      verdict=FAIL
      ptxt="unknown policy p=$p"
      ;;
  esac
  [[ -n "$rua" ]] || verdict=$(worse "$verdict" WARN)

  local rua_txt="missing"
  [[ -n "$rua" ]] && rua_txt="set"
  emit "$verdict" DMARC "$ptxt; rua $rua_txt"
  case "${p,,}" in
    none) fix "once reports look clean, step up: p=quarantine, then p=reject" ;;
    reject|quarantine) ;;
    *) fix "set an explicit policy: p=none to start, p=quarantine/p=reject when ready" ;;
  esac
  [[ -n "$rua" ]] || fix "add rua=mailto:<mailbox> — without it you get no aggregate reports"
  if [[ "$pct" =~ ^[0-9]+$ ]] && ((pct < 100)); then
    note "pct=$pct: policy applies to only ${pct}% of failing mail"
  fi
}

# ---------- check 4: MX sanity ----------

# Filled by check_mx, consumed by the rDNS and TLS checks.
MX_TARGETS=()   # MX hostnames (or the domain itself under implicit MX)
MX_ADDRS=()     # "host ip" pairs for every A/AAAA of every MX target

# mx_collect_addrs <host> — append the host's addresses to MX_ADDRS
mx_collect_addrs() {
  local host=$1 addr addrs
  addrs=$( { dns_short A "$host"; dns_short AAAA "$host"; } ) || addrs=""
  while read -r addr; do
    [[ -n "$addr" ]] && MX_ADDRS+=("$host $addr")
  done <<<"$addrs"
}

check_mx() {
  local raw rc
  raw=$(dig "${DIG_OPTS[@]}" +short MX "$DOMAIN" 2>/dev/null)
  rc=$?
  if ((rc != 0)); then
    emit FAIL MX "MX lookup failed (DNS timeout or no response)"
    fix "check the resolver and re-run"
    return
  fi
  raw=$(grep -E '^[0-9]+ ' <<<"$raw") || true

  if [[ -z "$raw" ]]; then
    local a aaaa
    a=$(dns_short A "$DOMAIN") || a=""
    aaaa=$(dns_short AAAA "$DOMAIN") || aaaa=""
    if [[ -n "$a$aaaa" ]]; then
      emit WARN MX "no MX records — mail falls back to the domain's A/AAAA record (implicit MX)"
      fix "publish an explicit MX record, even if it points at this same host"
      MX_TARGETS+=("$DOMAIN")
      mx_collect_addrs "$DOMAIN"
    else
      emit FAIL MX "no MX records and no A/AAAA fallback — this domain cannot receive mail"
      fix "publish an MX record pointing at your mail host"
    fi
    return
  fi

  if grep -qE '^0 \.$' <<<"$raw"; then
    emit FAIL MX "null MX (\"0 .\") published — the domain declares it accepts no mail (RFC 7505)"
    fix "remove the null MX and publish a real MX record if this domain should handle mail"
    return
  fi

  local -a problems=()
  local pref host cname a aaaa n=0 verdict=PASS
  while read -r pref host; do
    host="${host%.}"
    n=$((n + 1))
    cname=$(dig "${DIG_OPTS[@]}" +short CNAME "$host" 2>/dev/null) || cname=""
    if [[ -n "$cname" ]]; then
      verdict=FAIL
      problems+=("MX $pref $host is a CNAME (→ ${cname%.}) — MX targets must be hostnames with address records (RFC 2181)")
      continue
    fi
    a=$(dns_short A "$host") || a=""
    aaaa=$(dns_short AAAA "$host") || aaaa=""
    if [[ -z "$a$aaaa" ]]; then
      verdict=FAIL
      problems+=("MX $pref $host does not resolve to any address")
      continue
    fi
    MX_TARGETS+=("$host")
    local addr
    while read -r addr; do
      [[ -n "$addr" ]] && MX_ADDRS+=("$host $addr")
    done <<<"$a
$aaaa"
  done < <(sort -n <<<"$raw")

  if [[ "$verdict" == PASS ]]; then
    emit PASS MX "$n MX record(s); all targets resolve and none are CNAMEs"
    return
  fi
  emit FAIL MX "$n MX record(s) with problems"
  local prob
  for prob in "${problems[@]}"; do
    note "$prob"
  done
  fix "point each MX at a real A/AAAA hostname (no CNAME) and remove dead entries"
}

# ---------- check 5: rDNS / FCrDNS ----------

check_rdns() {
  if ((${#MX_ADDRS[@]} == 0)); then
    emit SKIP rDNS "skipped: no mail host addresses to check (see MX above)"
    return
  fi

  local entry host ip ptrs ptr fwd ok total=0 verdict=PASS
  local -a details=()
  for entry in "${MX_ADDRS[@]}"; do
    host=${entry%% *}
    ip=${entry#* }
    total=$((total + 1))
    ptrs=$(dig "${DIG_OPTS[@]}" +short -x "$ip" 2>/dev/null) || ptrs=""
    ptrs=$(grep -E '\.$' <<<"$ptrs") || true
    if [[ -z "$ptrs" ]]; then
      verdict=FAIL
      details+=("$ip ($host): no PTR record")
      continue
    fi
    ok=0
    ptr=""
    while read -r ptr; do
      ptr=${ptr%.}
      [[ -n "$ptr" ]] || continue
      if [[ "$ip" == *:* ]]; then
        fwd=$(dns_short AAAA "$ptr") || fwd=""
      else
        fwd=$(dns_short A "$ptr") || fwd=""
      fi
      if grep -qxF "$ip" <<<"$fwd"; then
        ok=1
        break
      fi
    done <<<"$ptrs"
    if ((ok)); then
      details+=("$ip ($host): PTR '$ptr' forward-confirms")
    else
      verdict=FAIL
      details+=("$ip ($host): PTR '${ptr}' does not resolve back to $ip")
    fi
  done

  local bad=0 d
  for d in "${details[@]}"; do
    [[ "$d" == *forward-confirms ]] || bad=$((bad + 1))
  done

  if [[ "$verdict" == PASS ]]; then
    emit PASS rDNS "$total/$total mail host IP(s) have forward-confirmed rDNS"
    return
  fi
  emit FAIL rDNS "$bad of $total mail host IP(s) lack forward-confirmed rDNS"
  for d in "${details[@]}"; do
    [[ "$d" == *forward-confirms ]] || note "$d"
  done
  fix "ask your hosting provider to set PTR ip → hostname matching forward DNS (FCrDNS)"
}

# ---------- check 6: TLS on port 25 ----------

TLS_SKIPPED=0

# tls_probe <host> — s_client STARTTLS probe; prints one classified detail line,
# returns 0 ok / 1 problem (STARTTLS or cert) / 2 unreachable
tls_probe() {
  local host=$1 out rc vline vcode vreason end
  out=$(timeout 8 openssl s_client -starttls smtp -connect "${host}:25" \
    -servername "$host" </dev/null 2>&1)
  rc=$?
  if ((rc == 124)); then
    printf '%s: cannot connect on port 25 (timed out)\n' "$host"
    return 2
  fi
  if grep -qi "didn't find starttls" <<<"$out"; then
    printf '%s: STARTTLS not offered\n' "$host"
    return 1
  fi
  if ! grep -q 'BEGIN CERTIFICATE' <<<"$out"; then
    printf '%s: cannot connect on port 25\n' "$host"
    return 2
  fi
  vline=$(grep -m1 -i 'verify return code' <<<"$out")
  vcode=$(grep -oE '[0-9]+' <<<"$vline" | head -n1)
  vreason=$(sed -E 's/.*\((.*)\).*/\1/' <<<"$vline")
  end=$(openssl x509 -noout -enddate 2>/dev/null <<<"$out" | sed 's/notAfter=//')
  case "$vcode" in
    0)
      printf '%s: STARTTLS ok, certificate valid until %s\n' "$host" "$end"
      return 0
      ;;
    10)
      printf '%s: certificate EXPIRED (%s)\n' "$host" "$end"
      return 1
      ;;
    *)
      printf '%s: certificate not valid (%s)\n' "$host" "${vreason:-verification failed}"
      return 1
      ;;
  esac
}

check_tls() {
  if ((NO_SMTP)); then
    TLS_SKIPPED=1
    emit SKIP TLS "skipped (--no-smtp): STARTTLS on port 25 not probed"
    return
  fi
  if ((${#MX_TARGETS[@]} == 0)); then
    TLS_SKIPPED=1
    emit SKIP TLS "skipped: no mail hosts to probe (see MX above)"
    return
  fi

  local host line rc total=0 ok=0 bad=0 unreachable=0
  local -a details=()
  for host in "${MX_TARGETS[@]}"; do
    total=$((total + 1))
    line=$(tls_probe "$host")
    rc=$?
    details+=("$line")
    case "$rc" in
      0) ok=$((ok + 1)) ;;
      1) bad=$((bad + 1)) ;;
      2) unreachable=$((unreachable + 1)) ;;
    esac
  done

  local d
  if ((bad > 0)); then
    emit FAIL TLS "$bad of $total MX host(s) fail the STARTTLS/certificate check"
    for d in "${details[@]}"; do note "$d"; done
    fix "enable STARTTLS with a trusted, unexpired certificate on every MX (see the TLS chapter)"
  elif ((unreachable > 0)); then
    emit WARN TLS "$unreachable of $total MX host(s) unreachable on port 25 — cannot verify"
    for d in "${details[@]}"; do note "$d"; done
    fix "many ISPs block outbound port 25; re-run from the mail server itself or use --no-smtp"
  else
    emit PASS TLS "$ok/$total MX host(s) offer STARTTLS with a valid certificate"
    for d in "${details[@]}"; do note "$d"; done
  fi
}

# ---------- main ----------

main() {
  check_deps
  parse_args "$@"

  if ((NO_SMTP == 0)) && ! command -v timeout >/dev/null 2>&1; then
    die "the TLS probe needs 'timeout' (coreutils) — install coreutils or re-run with --no-smtp"
  fi

  ((JSON)) || printf 'inbox-audit %s — %s\n\n' "$VERSION" "$DOMAIN"

  check_spf
  check_dkim
  check_dmarc
  check_mx
  check_rdns
  check_tls

  # check 7: Inbox Readiness — composite verdict against the Gmail/Yahoo
  # sender requirements (SPF + DKIM + DMARC at minimum p=none + FCrDNS + TLS)
  local readiness ec
  if ((FAILURES > 0)); then
    readiness="FAILING" ec=2
  elif ((WARNINGS > 0)); then
    readiness="AT RISK" ec=1
  else
    readiness="READY" ec=0
  fi

  if ((JSON)); then
    json_flush
    printf '{"tool":"inbox-audit","version":"%s","domain":"%s","checks":[%s],' \
      "$VERSION" "$DOMAIN" "$JSON_CHECKS"
    printf '"readiness":"%s","failures":%d,"warnings":%d,"exit_code":%d}\n' \
      "$readiness" "$FAILURES" "$WARNINGS" "$ec"
  else
    printf '\n'
    printf 'Inbox Readiness: %s — %d failure(s), %d warning(s)\n' \
      "$readiness" "$FAILURES" "$WARNINGS"
    note "Gmail/Yahoo sender minimums: SPF, DKIM, DMARC (p=none or stricter), FCrDNS, TLS"
    case "$readiness" in
      FAILING)   note "fix the [FAIL] items above, then re-run" ;;
      "AT RISK") note "mail may deliver today, but the [WARN] items above are where reputation erodes" ;;
      READY)     note "all minimums verified" ;;
    esac
    ((TLS_SKIPPED)) && note "TLS was not probed and is not covered by this verdict"
  fi
  exit "$ec"
}

main "$@"
