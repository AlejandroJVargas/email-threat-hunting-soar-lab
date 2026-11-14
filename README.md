# Email Threat Hunting & Phishing Triage Automation Lab

**Scenario:** At **Lumenfield** (fictional company, `lumenfield.com`, ~420 employees, Córdoba, Argentina).
Several employees reported suspicious emails during October 2026, and the finance team is worried about a supplier payment.
Management suspects the current email filter is missing attacks.

I receive **30 days of mail gateway logs (~99,000 emails)**, a set of raw `.eml` samples, and offline threat-intelligence data.

> All companies, people, domains and IPs in this lab are fictional or used as illustrative examples.
> Attachments are harmless placeholders. Threat-intel files are **simulated** (offline), so there's no real API keys.

---

## Data

| File | What it is |
|---|---|
| `data/emails_30d.csv` | Mail gateway log, 2026-10-01 to 2026-10-30, ~99,000 rows |
| `data/eml_samples/*.eml` | 10 raw emails with full headers (some malicious, some legit) |
| `data/threat_intel/whois_simulated.csv` | Domain creation date, registrar, privacy protection |
| `data/threat_intel/url_reputation_simulated.csv` | VirusTotal-style detections per URL domain |
| `data/threat_intel/attachment_hashes_simulated.csv` | Known-bad attachment hashes |

### `emails_30d.csv` columns

| Column | Meaning |
|---|---|
| `timestamp` | When the gateway received it (UTC-3) |
| `message_id` | Unique message ID |
| `sender`, `sender_domain` | Envelope/header From address and its domain |
| `display_name` | Name shown to the user (can be faked!) |
| `reply_to` | Where replies go (empty = same as sender) |
| `return_path` | Bounce address |
| `recipient` | Lumenfield employee who received it |
| `subject` | Subject line |
| `url_count`, `urls` | Links in the body (`|`-separated) |
| `attachment_name`, `attachment_type` | Attachment, if any |
| `sender_ip`, `sender_country` | Connecting server and its geolocation |
| `spf`, `dkim`, `dmarc` | Authentication results |
| `domain_age_days` | Age of the sender domain at receive time |
| `size_kb` | Message size |
| `filter_verdict` | What the **current** filter decided: `clean`, `spam`, `quarantine` |
| `user_reported` | Whether the recipient reported it as suspicious |


---

### Phase 1: Parse raw emails (Python) — 1 week

Write `src/parse_eml.py` that reads every file in `data/eml_samples/` and outputs one JSON object per email with:

- From (address + display name), Reply-To, Return-Path, To, Subject, Date
- First external `Received` IP
- SPF / DKIM / DMARC results (from `Authentication-Results`)
- All URLs (from the text **and** HTML parts, including `href` targets)
- Attachment names, types and SHA-256 hashes

Then add **red-flag checks**: Reply-To domain ≠ From domain, Return-Path domain ≠ From domain, display name mentions a brand the domain doesn't belong to, link text ≠ link target, risky attachment types.

*Hints:* Python's `email` module (`email.message_from_binary_file`, `policy.default`), `re`, `hashlib`, `base64`.

### Phase 2: Hunt in 99,000 emails (SQL / Splunk / Python) — 1 week

Load `emails_30d.csv` into Splunk (Add Data → Upload) **or** use SQL (sqlite) / Python.

Answer, with queries saved in `queries/`:

1. What does normal mail look like? (volume by day/hour, top senders, top domains)
2. Which campaigns can you find? For each: name, time window, senders/domains, number of emails, number of recipients, technique, MITRE ATT&CK mapping.
3. How many of each campaign did the filter mark `clean`? (false negatives)
4. Which **legitimate** mail did the filter block? (false positives)
5. Which hosts/users are most at risk (e.g. who received the most malicious mail)?

*Hints:* group by subject and count distinct sender domains; look at domain age, send hour, Reply-To, URL paths, attachment types, DMARC results. Not every burst is an attack, and not every new domain is malicious.

### Phase 3: Enrich and score — 1 week

Build `src/enrich_score.py`: for each email (or each sender domain), join the threat-intel files and calculate a **risk score** from signals you choose and weight. Example signals: domain age, privacy-protected WHOIS, URL reputation, Reply-To mismatch, DMARC fail, risky attachment, night-time sending, display-name brand mismatch.

Output a scored CSV and decide thresholds: **block**, **send to analyst**, **allow**.

### Phase 4: Detections (Splunk SPL + regex) — 1 week

Write at least **4 detection rules** in `detections/` (SPL, and optionally Sigma-style YAML), one per campaign type.

For each rule, measure on the dataset:

| Metric | Meaning |
|---|---|
| Hits | How many emails it flags |
| True positives / False positives | You'll validate these with your hunting results (and Claude has the answer key) |
| What it misses | Be honest |


### Phase 5: SOAR playbook — 1 week

Automate triage for a **user-reported email** with [Shuffle](https://shuffler.io) (open source) or Splunk SOAR Community Edition:

```
User reports email → parse (Phase 1) → enrich + score (Phase 3)
   → score high  : block domain/URL, search for other recipients, open ticket
   → score medium: open ticket for an analyst
   → score low   : reply to the user "looks safe", log it
```

### Phase 6: Report

Write `docs/incident_report.md`: executive summary, timeline, campaigns, IOCs, filter performance (before vs after your detections), recommendations.

## Suggested repo layout

```
src/            Python code
queries/        SQL / SPL used for hunting
detections/     Detection rules
playbook/       SOAR exports, diagram, screenshots
docs/           Findings and incident report
data/           Lab data (provided)
```
