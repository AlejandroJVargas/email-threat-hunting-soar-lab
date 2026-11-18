# Findings log: Lumenfield email threat hunt (October 2026)

Dataset: 99,042 emails (2026-10-01 to 2026-10-30). Tool: SQL (SQLite).

## Summary

| # | Finding | Verdict | Emails | Filter missed |
|---|---|---|---|---|
| 1 | Wednesday newsletter spikes | Benign (false-positive trap) | 8,189 | N/A |
| 2 | Credential phishing with domain rotation | Malicious | 1,800 | 1,546 (86%) |
| 3 | Malware via HTML, ISO and ZIP attachments | Malicious | 3,200 | 1,285 (40%) |
| 4 | Business Email Compromise from a real supplier account | Malicious | 42 | 42 (100%) |
| 5 | CEO impersonation via spoofed internal domain | Malicious | 300 | 154 (51%) |

---

## Finding 1: Weekly Wednesday volume spikes (benign)

| Field | Value |
|---|---|
| Verdict | **Legitimate**: scheduled newsletters, not an attack |
| Time window | Wednesdays Oct 7, 14, 21, 28, 2026, between 09:00 and 11:00 |
| Sender domains | club-lumen-benefits.com, mercadolibre.com.ar, techdigest-weekly.com |
| Emails on those days | 8,189 (2,776 + 2,745 + 2,668) |
| Key signals | Same subject every week, SPF/DKIM/DMARC pass, long-established domains |
| Technique / MITRE | N/A (benign) |
| Query used | `queries/02_spike_days.sql` |

**Notes:** A volume-based rule ("too many emails per day = attack") would flag these newsletters. High volume alone is not malicious.

---

## Finding 2: Credential phishing campaign with domain rotation

| Field | Value |
|---|---|
| Verdict | **Malicious**: credential phishing impersonating Microsoft 365 |
| Time window | 2026-10-05 00:03 -> 2026-10-14 23:53 |
| Sender domains | m365-secure-login.com, office-auth-review.net, m365-verify-account.org, secure-o365-portal.com, msonline-access-check.com, o365-mailbox-alerts.net, m365-session-guard.com, office-identity-sync.org |
| Emails | 1,800 |
| Unique recipients | 414 of ~420 employees |
| Filter marked clean (false negatives) | 1,546 (86%) |
| Key signals | Domains 1 day old, exactly 225 emails each, same 3 subjects, a new domain every day |
| Technique | Domain rotation, low and slow: ~75 emails/day per domain, each active ~3 days |
| MITRE ATT&CK | T1566.002 (Phishing: Spearphishing Link), T1583.001 (Acquire Infrastructure: Domains) |
| Query used | `queries/03_campaign_credential_phishing.sql` |

---

## Finding 3: Malware delivery via HTML, ISO and ZIP attachments

| Field | Value |
|---|---|
| Verdict | **Malicious**: malware delivery disguised as invoices and payment notices |
| Time window | 2026-10-12 00:03 -> 2026-10-19 23:20 |
| Sender domains | 449 (yahoo.com, hotmail.com, gmail.com, outlook.com + throwaway invoices-XXX.top) |
| Emails | 3,200 |
| Unique recipients | 421 (every employee) |
| Filter marked clean (false negatives) | 1,285 (40%) |
| Key signals | Attachment types .html/.zip/.iso; invoice/remittance subjects with random numbers |
| Technique | Throwaway senders on domains that can't be blocked; detection must rely on the attachment, not the sender |
| MITRE ATT&CK | T1566.001 (Spearphishing Attachment), T1027.006 (HTML Smuggling), T1585.002 (Establish Accounts: Email Accounts) |
| Query used | `queries/04_campaign_malware_attachments.sql` |

**Notes:** Campaigns 2 and 3 overlapped on Oct 12–14. It's not possible to confirm from this data whether they share the same attacker.

---

## Finding 4: Business Email Compromise from a real supplier account

| Field | Value |
|---|---|
| Verdict | **Malicious**: BEC, payment redirection fraud |
| Time window | 2026-10-22 02:22 -> 2026-10-25 04:48 |
| Sender | laura.gomez@andeslogistics.com.ar (real supplier account, likely compromised) |
| Emails | 42 (out of 1,860 from andeslogistics.com.ar) |
| Unique recipients | 18 (accounts.payable@, finance@ and finance staff) |
| Filter marked clean (false negatives) | 42 (100%) |
| Key signals | Sent from the Netherlands (all other Andes Logistics mail comes from Argentina); only one sender; between 02:00 and 05:00; 36 different IPs for 42 emails; every subject is about changing bank or payment details; 12 emails with a Reply-To to an external address |
| Technique | Compromised legitimate supplier mailbox: authentication passes, no links or attachments to scan |
| MITRE ATT&CK | T1586.002 (Compromise Accounts: Email Accounts), T1656 (Impersonation), T1657 (Financial Theft) |
| Query used | `queries/05_campaign_bec.sql` |

**Notes:** The Phase 1 parser detects only 12 of 42 (Reply-To mismatch). Detection needs behavioral baselines per sender: usual country, usual hours, usual topics.

**Immediate actions:** Tell finance not to pay any changed bank details without calling Andes Logistics at a known phone number; notify Andes Logistics that the account is likely compromised; check whether any payment was already made.

---

## Finding 5: CEO impersonation via spoofed internal domain

| Field | Value |
|---|---|
| Verdict | **Malicious**: CEO fraud (gift card scam) using a spoofed lumenfield.com address |
| Time window | 2026-10-27 03:19 -> 2026-10-30 23:27 |
| Sender | mariana.ibarra@lumenfield.com (forged: the CEO's address in the From, not her real account) |
| Emails | 300 |
| Unique recipients | 213 employees |
| Filter marked clean (false negatives) | 154 (51%) |
| Key signals | DMARC fail on our own domain; sent from Nigeria (157) and Russia (143), never from the internal network; all replies redirected to m.ibarra.ceo@protonmail.com; Return-Path on random mailer-XX.xyz domains; urgent, secretive requests ("gift cards", "confidential request", "are you at your desk?") |
| Technique | Exact-domain spoofing: the attacker forges the From header without compromising any account |
| MITRE ATT&CK | T1656 (Impersonation), T1657 (Financial Theft) |
| Query used | `queries/06_campaign_ceo_spoof.sql` |

**Root cause:** Lumenfield's DMARC policy is `p=none`, so emails that fail DMARC for our own domain are still delivered.

**Recommendations:**
- Change the DMARC policy for lumenfield.com from `p=none` to `p=quarantine`, then `p=reject` after monitoring.
- Add an "External sender" warning banner on emails from outside the company that use internal names.
- Remind staff: the CEO will never ask for gift cards by email; verify by phone or chat.

---

## Filter false positives (legit mail blocked)

| Sender | Emails blocked | Why it's legit | Query |
|---|---|---|---|
| lumenfield-eventos.com | 209 | Real HR end-of-year event invitation; domain only 9 days old, but auth passes and no other red flags | `queries/07_false_positives_and_targets.sql` |
| techdigest-weekly.com | 58 | Newsletter, long-established domain | same |
| club-lumen-benefits.com | 52 | Newsletter, long-established domain | same |
| mercadolibre.com.ar | 46 | Newsletter, long-established domain | same |
| **Total** | **365** | | |

**Note:** lumenfield.com also appears in the spam results (146 emails), but those are the spoofed CEO emails from finding 5. Blocking them was correct.

**Conclusion:** the filter judged each sender by a single signal (domain age or volume). Reliable decisions require several signals combined.

---

## Most targeted users

- **By volume:** the mass campaigns spread evenly, with each employee receiving about 21–23 malicious emails (top: lautaro.ruiz@lumenfield.com, 23).
- **By risk:** the finance team (accounts.payable@, finance@ and 16 finance staff), targeted by the BEC campaign. Low volume, but direct financial impact.

---

## Phase 3: Risk Scoring Engine (`src/enrich_score.py`)

### Goal
Automatically score all 99,042 emails from 0 to 100+ and decide for each one:
**block**, **send to analyst**, or **allow**.

### Pipeline
signals (yes/no) → weighted score → decision → evaluation against ground truth

### Signals and weights

| Signal | Level | Points | Reason |
|---|---|---|---|
| reply_to_mismatch | Strong | 35 | Replies go to the attacker; core BEC technique. Legit senders almost never do this. |
| dmarc_fail | Strong | 35 | Someone is sending as a domain they don't control (impersonation, e.g. CEO spoof). |
| risky_attachment (html/zip/iso) | Strong | 35 | Legit senders almost never send these; the filter must decide before the user clicks. |
| new_domain (< 30 days) | Medium | 20 | Suspicious, but lumenfield-eventos.com was new and legit, so it must not block on its own. |
| whois_privacy | Medium | 20 | Common in phishing, but many small legit businesses also hide WHOIS data. |
| payment_keywords | Medium | 20 | "bank details", "remittance", "payment details". Added after evaluation (see below). |
| night_hour (00:00–05:59) | Weak | 10 | Newsletters and other time zones send at night; only meaningful combined with other signals. |

### Thresholds

| Score | Decision |
|---|---|
| >= 45 | Block |
| 20–44 | Analyst review |
| < 20 | Allow |

### Results

| Label | Block | Analyst | Allow |
|---|---|---|---|
| ceo_spoof (300) | 300 | 0 | 0 |
| spam (8,000) | 8,000 | 0 | 0 |
| cred_phish (1,800) | 1,272 | 528 | 0 |
| malware (3,200) | 1,521 | 1,679 | 0 |
| bec (42) | 12 | 30 | 0 |
| legit_new_domain (700) | 0 | 700 | 0 |
| legit (85,000) | 0 | 0 | 85,000 |

- **0 attacks delivered without review**
- **0 legitimate emails blocked**
- lumenfield-eventos.com (new but legit domain) was sent to analyst review, not blocked

### Tuning: BEC coverage

| | Initial weights | Tuned weights (+ `payment_keywords`) |
|---|---|---|
| Attacks allowed | **30** (all BEC) | **0** |
| Legit emails blocked | 0 | 0 |
| Malware auto-blocked | 692 | 1,521 |
| Malware in analyst queue | 2,508 | 1,679 |

**Root cause:** the BEC came from a **compromised real vendor mailbox**
(laura.gomez@andeslogistics.com.ar). The domain is 10 years old, passes
SPF/DKIM/DMARC and has public WHOIS, so every domain-based signal was clean.
Only night_hour fired (score 10 → allow).

**Fix:** added `payment_keywords`. Generic words like "invoice" were rejected
because they matched 4,852 legit emails. Words describing a **change of payment
destination** matched all 42 BEC emails and 0 legit emails.

**Why Medium (20) and not Strong:** a real vendor may legitimately change bank
details. These emails go to analyst review so a human can verify by phone
(out-of-band verification) instead of auto-blocking.

**Conclusion:** domain reputation cannot detect compromised legitimate senders.
Behavioral and content signals are required.

### Next steps
- Analyst queue is ~98 emails/day (2,937 in 30 days), mostly malware scoring
  35–55. Next: tune malware thresholds to reduce alert fatigue.
- `unusual_country` signal (e.g. .com.ar domain sending from NL) would add a
  second behavioral check for compromised vendors.
- Keyword lists are easy for attackers to evade; they should be reviewed regularly.
- Weights were chosen by analyst judgment, then validated against ground truth;
  they are not statistically optimized.

---

## Phase 4: Splunk Detections

### Setup
- Splunk Enterprise (Free license) on Ubuntu VM, index `phishing`
- Data loaded with `splunk add oneshot` from a VirtualBox shared folder
- 99,042 events, same count as the Python analysis

### Detections

| ID | Name | Logic | Hits |
|---|---|---|---|
| PHISH-01 | BEC Compromised Vendor | Payment-change keywords AND `.com.ar` domain AND sender_country != AR | 42 (1 sender, 18 victims, NL) |
| PHISH-02 | Cred Phishing Brand Impersonation | display_name contains "Microsoft" AND domain is not microsoft.com | 1,800 (8 domains × 225) |
| PHISH-03 | Malware Attachments | attachment_type IN (html, zip, iso) | 3,200 |
| PHISH-04 | CEO Spoof DMARC Fail | sender_domain = lumenfield.com AND dmarc = fail | 300 (NG/RU, Reply-To ProtonMail) |

Queries: `queries/splunk/`. Dashboard: `Phishing Lab – Detections`.

### Key result: BEC detection in two stages

| Stage | Logic | Hits |
|---|---|---|
| A | Payment keywords only | 1,082 (mostly malware from freemail senders) |
| B | + `.com.ar` domain sending from outside AR | **42 (only the BEC, zero noise)** |

Missing one keyword ("payment details") dropped 14 of the 42 BEC emails, so every
keyword in a detection was tested against known data.

### Other observations
- 947 emails that failed DMARC were still delivered as clean, explained by the
  `p=none` policy (Finding 5).
- DMARC failures by country: NG 2,208, RU 2,168, VN 2,065, CN 2,004 (campaigns);
  US 73, BR 68 (likely misconfigured legit senders).

### Environment notes
- Splunk Free does not support scheduled searches or alerts; detections are saved
  as reports. In production they would run hourly and send Critical/High alerts
  to the SOAR playbook (Phase 5).
  
---


## Phase 5: SOAR Playbook (Shuffle)

### Goal
Automate the response to a phishing alert, so that a BEC alert at 03:00 is
handled in seconds instead of waiting for an analyst at 09:00.

### Workflow: `Phishing Triage – BEC` (`soar/phishing_triage_bec.json`)

| Step | Node | What it does |
|---|---|---|
| Trigger | Webhook (`Splunk Alert`) | Receives the alert as JSON |
| Enrich + score | Python (`Score_Alert`) | Reuses the Phase 3 logic: 4 signals → weighted score → decision |
| Decide | 3 conditional branches | `$score_alert.message.decision` equals block / analyst / allow |
| Act | `Block_Notify_Finance` / `Send_To_Analyst` / `Allow_And_Log` | Response message for each path |

### Signals used in the playbook

| Signal | Points |
|---|---|
| reply_to_mismatch | 35 |
| unusual_country (.com.ar domain sending from outside AR) | 35 |
| payment_keywords | 20 |
| night_hour | 10 |

`unusual_country` comes from the Splunk BEC detection (Phase 4, Stage B).

### Tests

| Test case | Score | Decision | Result |
|---|---|---|---|
| BEC from compromised vendor (NL, outlook.com Reply-To, 04:35) | 100 | block | Email quarantined, finance warned not to pay |
| Real vendor changing bank details (AR, office hours) | 20 | analyst | Ticket for phone verification |
| Normal event invitation | 0 | allow | Delivered and logged |

All three branches were tested; only the matching branch ran each time.

### Next steps
- Splunk Free cannot send alerts, so alerts were sent manually to the webhook
  (simulating Splunk). In production, the PHISH-01 alert would call the webhook.
- The webhook has no authentication in the lab. In production, add a secret
  header so only Splunk can trigger the workflow.
- Actions are simulated messages. In production they would call real APIs:
  Microsoft 365 quarantine, email to finance, ticket in TheHive or Jira.