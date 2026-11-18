# Incident Report: Business Email Compromise via Compromised Supplier Account

| Field | Value |
|---|---|
| Incident ID | IR-2026-001 |
| Severity | Critical |
| Status | Contained |
| Author | Alejandro José Vargas |
| Date | 2026-11-14 |

## 1. Executive Summary

Between October 22 and 25, 2026, an attacker used the real email account of
Laura Gómez, an employee of our supplier Andes Logistics, to send fake requests
asking us to change the bank account where we pay their invoices.

The attacker sent 42 emails to 18 people in our finance team, always between
2:00 and 5:00 in the morning, from the Netherlands instead of Argentina.

Our email filter delivered 100% of these emails, because they came from a real
supplier account, passed all authentication checks, and contained no links or
attachments to scan.

We built a new detection that flags payment-change requests from suppliers
sending from an unusual country, and an automated response that blocks these
emails and warns finance not to pay. Finance must confirm with Andes Logistics,
using a known phone number, whether any payment was already using a known phone number, whether any payment was already made.


---

## 2. Timeline (ART, UTC-3)

| Date / time | Event |
|---|---|
| 2026-10-01 → 10-21 | Normal traffic from Andes Logistics: sent from Argentina (181.47.12.x), office hours |
| **2026-10-22 02:22** | **First malicious email** from laura.gomez@andeslogistics.com.ar, sent from the Netherlands |
| 2026-10-22 → 10-25 | 10–11 emails per night, always between 02:00 and 05:00, from 36 different IPs |
| 2026-10-23 04:35 | One employee reports one of the emails as suspicious (1 of 42). No follow-up action recorded. |
| **2026-10-25 04:48** | **Last malicious email** |
| 2026-11 | Retrospective threat hunt (SQL) identifies the campaign (Finding 4) |
| 2026-11 | Risk-scoring engine v1 misses 30 of 42 emails; v2 adds `payment_keywords` and catches all 42 |
| 2026-11 | Splunk detection PHISH-01 created: 42 hits, zero false positives |
| 2026-11-14 | SOAR playbook tested: BEC alert scored 100 → blocked, finance notified |

---

## 3. Impact

| Item | Value |
|---|---|
| Malicious emails delivered | 42 of 42 (100%) |
| Recipients | 18: accounts.payable@, finance@ and 16 finance staff |
| Emails with a fake "New_Bank_Details" PDF | 16 |
| Emails with a Reply-To to an external address | 12 (laura.gomez.andes@outlook.com) |
| Reported by users | 1 |
| Financial loss | **Unknown: pending confirmation by finance** |

**Business risk:** if any invoice was paid to the new bank details, the money
went to the attacker. Wire transfers are usually hard or impossible to recover
after a few days, so this must be checked immediately.

---

## 4. Root Cause

| Cause | Explanation |
|---|---|
| **Supplier mailbox compromised** | The attacker controlled Laura Gómez's real account (likely stolen credentials at Andes Logistics; not confirmed). |
| Filter relies on authentication and reputation | The emails passed SPF, DKIM and DMARC and came from a 10-year-old domain, so every domain-based check was clean. |
| No behavioral baseline per sender | Nothing compared the sender's usual country (AR), hours (office time) and topics against these emails. |
| No enforced verification process | Bank detail changes could be accepted by email, without a phone call to a known number. |

---

## 5. Detection and Response

| Phase | Method | Result |
|---|---|---|
| Threat hunt | SQL over 99,042 emails | Campaign found: one sender, NL, 02:00–05:00, payment subjects |
| Risk scoring | Python, weighted signals | v1 missed 30 emails (only `night_hour` fired). v2 added `payment_keywords`: 0 missed |
| SIEM detection | Splunk PHISH-01 | Payment keywords + `.com.ar` domain + sender country ≠ AR → 42 hits, 0 noise |
| SOAR | Shuffle playbook | Score 100 → block + finance warning; a real bank change from AR scores 20 → analyst review |

---

## 6. Indicators of Compromise (IOCs)

| Type | Value | Action |
|---|---|---|
| Compromised account | laura.gomez@andeslogistics.com.ar | **Do not block the whole domain** (legitimate supplier). Hold mail from this account until Andes Logistics confirms it is secured. |
| Reply-To address | laura.gomez.andes@outlook.com | Block |
| Source IP range | 185.220.101.0/24 (36 IPs used) | Block for this sender; check reputation with threat intelligence |
| Source country | NL (supplier normally sends from AR) | Use as a behavioral signal |
| Subjects | "URGENT: payment details update", "Change of remittance account", "RE: Invoice #XXXX - updated bank details" | Detection keywords |
| Attachment name | New_Bank_Details_XX.pdf | Detection pattern |
| Sending time | 02:00–05:00 ART | Behavioral signal |

---

## 7. Recommendations

**Immediate (today)**
- Finance: check every payment to Andes Logistics since October 22. If any went to new bank details, contact the bank immediately to try to stop or recall the transfer.
- Call Andes Logistics at a known phone number (not one from the emails) and tell them Laura Gómez's account is compromised.
- Block the Reply-To address and the IOCs above.

**Short term (this month)**
- Policy: no bank detail change is accepted by email. Every change must be confirmed by phone, using a number already on file.
- Enable the PHISH-01 detection and the SOAR playbook in production.
- Add an "External sender" banner to emails from outside the company.
- Follow up on user reports: the employee who reported the email on October 23 was right.

**Long term**
- Build behavioral baselines for key suppliers: usual country, sending hours and topics.
- Security awareness training for finance focused on BEC and payment fraud.
- Ask critical suppliers to use MFA on their email accounts.

---

## 8. MITRE ATT&CK

| Technique | ID | How it was used |
|---|---|---|
| Compromise Accounts: Email Accounts | T1586.002 | The attacker took over the supplier's real mailbox |
| Impersonation | T1656 | Posed as a trusted supplier contact |
| Financial Theft | T1657 | Tried to redirect invoice payments to an attacker account |

---

## 9. Post-Incident Review

- **Authentication is not trust.** A real account passes every authentication check; detection must also look at behavior.
- **One signal is never enough.** The domain looked clean; the combination of country, hour and payment topic exposed the attack.
- **Detections are validated against known data.** Validation showed that domain-based signals alone left 30 of 42 BEC emails below the review threshold, and that every payment keyword was needed (removing one dropped 14 emails from the Splunk detection).
- **A human check is the right control for payments.** The playbook sends real bank changes to an analyst for phone verification instead of blocking them.