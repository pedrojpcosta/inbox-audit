# inbox-audit

[![ShellCheck](https://github.com/inboxauditkit/inbox-audit/actions/workflows/shellcheck.yml/badge.svg)](https://github.com/inboxauditkit/inbox-audit/actions/workflows/shellcheck.yml)

Find out in 30 seconds what Gmail and Yahoo hold against your mail setup.

`inbox-audit` is a single-file bash script that audits one domain's email
deliverability posture against the Gmail/Yahoo sender requirements: SPF, DKIM,
DMARC, MX hygiene, reverse DNS (FCrDNS) and STARTTLS. It runs entirely on your
machine using DNS lookups and TLS probes — it never sends email, never calls a
third-party API, and never phones home. Built for admins of self-hosted mail
servers who watched their mail start landing in spam after the 2024 bulk-sender
rules tightened.

## Quick start

```sh
curl -O https://raw.githubusercontent.com/inboxauditkit/inbox-audit/main/inbox-audit.sh
chmod +x inbox-audit.sh
./inbox-audit.sh example.com
```

Dependencies: bash 4+, `dig`, `openssl`, coreutils — already present on most
Linux systems (Debian/Ubuntu: `apt install dnsutils openssl`).

```
Usage: ./inbox-audit.sh <domain> [options]

  --selector s1[,s2]  DKIM selector(s) to check (default: probe a common list)
  --no-smtp           skip the port-25 TLS probe (many ISPs block port 25)
  --json              machine-readable output
```

Exit codes: `0` all pass, `1` warnings, `2` failures, `3` usage or missing
dependency. That makes it cron-able: run it nightly and alert on non-zero.

## Example

```
$ ./inbox-audit.sh example.com --selector mail
inbox-audit 1.0.1 — example.com

[PASS] SPF    one v=spf1 record; 4/10 DNS lookups; terminal qualifier '-all'
[WARN] DKIM   1 selector(s) with a published key
       selector 'mail': 1024-bit RSA key — below the 2048-bit recommendation
       fix: generate a 2048-bit key and publish it under a new selector
[WARN] DMARC  policy p=none (monitoring only — failing mail is still delivered); rua set
       fix: once reports look clean, step up: p=quarantine, then p=reject
[PASS] MX     1 MX record(s); all targets resolve and none are CNAMEs
[FAIL] rDNS   1 of 1 mail host IP(s) lack forward-confirmed rDNS
       192.0.2.10 (mail.example.com): PTR 'host-10.pool.example.net' does not resolve back to 192.0.2.10
       fix: ask your hosting provider to set PTR ip → hostname matching forward DNS (FCrDNS)
[PASS] TLS    1/1 MX host(s) offer STARTTLS with a valid certificate
       mail.example.com: STARTTLS ok, certificate valid until Nov 12 09:30:00 2026 GMT

Inbox Readiness: FAILING — 1 failure(s), 2 warning(s)
       Gmail/Yahoo sender minimums: SPF, DKIM, DMARC (p=none or stricter), FCrDNS, TLS
       fix the [FAIL] items above, then re-run
```

## What each check means — and why Gmail cares

| Check | What it verifies | Why it matters to Gmail/Yahoo |
|---|---|---|
| **SPF** | Exactly one `v=spf1` record, ≤ 10 DNS lookups, strict terminal qualifier | Both providers require SPF. Multiple records or >10 lookups are permanent errors (RFC 7208) — your SPF silently stops existing. `+all`/`?all` authorize the whole internet. |
| **DKIM** | Key published at your selector(s), RSA ≥ 2048 bits | Required for bulk senders, scored for everyone. 1024-bit keys are below current recommendations; revoked/empty keys mean unsigned mail. |
| **DMARC** | Record present, policy strength, `rua=` reporting | Gmail/Yahoo require at least `p=none`. Without `rua=` you're flying blind on who fails authentication as you. |
| **MX** | MX records exist, aren't CNAMEs, resolve | Broken MX plumbing looks like a throwaway domain. CNAME MX targets violate RFC 2181 and break some receivers. |
| **rDNS** | Every mail host IP has a PTR that forward-confirms (FCrDNS) | Gmail rejects or spam-folders mail from IPs without matching forward/reverse DNS. The #1 forgotten step on a fresh VPS. |
| **TLS** | Port 25 offers STARTTLS with a valid, unexpired certificate | Both providers require TLS for delivery. Expired certs erode reputation with every connection. |
| **Readiness** | Composite verdict: READY / AT RISK / FAILING | The five minimums above, in one line. AT RISK means delivering today, eroding tomorrow. |

## FAQ

**Why not mail-tester or MXToolbox?**
They're fine tools. This one runs locally, works offline from any shell, has no
rate limits, keeps your domain list private, and exits with meaningful codes so
you can script it, cron it, and diff it. Different tool for a different habit.

**DKIM says "inconclusive: no key at common selectors".**
DKIM selectors are arbitrary names — there's no way to enumerate them from
outside, which is why a probe miss is reported as inconclusive rather than a
failure. Pass yours for a definitive verdict: `--selector mail2024`. It's in
your signer config (OpenDKIM `KeyTable`, rspamd `dkim_signing.conf`, or your
provider's docs).

**Everything passes but my mail still lands in spam.**
DNS is the foundation, not the whole house. Content, volume patterns, list
hygiene and IP history all weigh in. Fix the FAILs first; reputation follows
configuration.

**The TLS check says my MX is unreachable.**
Most residential ISPs and many VPSes block outbound port 25. Re-run from the
mail server itself, or use `--no-smtp` — the check reports SKIPPED, never FAIL,
when it can't probe.

**What's next?**
v1.1 adds a DMARC aggregate-report (rua XML) parser — free update, same repo.

## Fixing what it finds

Every FAIL and WARN above has a matching chapter in **[Inbox Audit Kit: The Fix
Playbook](https://inboxauditkit.gumroad.com/l/xkfaq)** — step-by-step fixes with copy-paste configs for
Postfix and OpenDKIM, the staged DMARC rollout (`none` → `quarantine` →
`reject`), a PTR request template for your VPS provider, and paste-ready DNS
zone snippets. One purchase, yours forever, free v1.x updates.

## License

MIT — see [LICENSE](LICENSE).

## Contributing

Issues welcome, especially false positives/negatives from real domains
(sanitize your outputs). PRs that improve check accuracy are the most valuable
thing you can send.
