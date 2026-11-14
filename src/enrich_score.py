import csv 
import re
from unittest import signals


def get_domain(email_address):
    match = re.search(r"@([\w.-]+)", email_address)
    return match.group(1).lower() if match else None

def load_csv(path):
    with open(path, newline='', encoding = 'utf-8') as file:
        return list(csv.DictReader(file))

whois = {}

for row in load_csv('data/threat_intel/whois_simulated.csv'):
    whois[row['domain']] = row
    
truth = {}

for row in load_csv('data/threat_intel/ground_truth.csv'):
    truth[row['message_id']] = row['label'] 
    
emails = load_csv('data/emails_30d.csv')

def get_signals(row):
    signals = {}
    PAYMENT_WORDS = ("bank details", "remittance", "payment details")
    signals["payment_keywords"] = any(word in row["subject"].lower() for word in PAYMENT_WORDS)   
    signals["new_domain"] = int(row["domain_age_days"]) < 30
    signals["dmarc_fail"] = row["dmarc"] == "fail"
    signals["reply_to_mismatch"] = row["reply_to"] != "" and get_domain(row["reply_to"]) != row["sender_domain"]
    signals["night_hour"] = 0 <= int(row["timestamp"][11:13]) <= 5
    signals["risky_attachment"] = row["attachment_type"] in ("html", "zip", "iso")
    signals["whois_privacy"] = whois.get(row["sender_domain"], {}).get("privacy_protected") == "yes"
    return signals

    
WEIGHTS = {
    "new_domain": 20,
    "dmarc_fail": 35,
    "reply_to_mismatch": 35,
    "night_hour": 10,
    "risky_attachment": 35,
    "whois_privacy": 20,
    "payment_keywords": 20
}
    
    
def get_score(signals):
    score = 0
    for name, is_on in signals.items():
        if is_on:                     
            score += WEIGHTS[name]   
    return score                      


def get_decision(score):
    if score >= (45):        # blank 1: your red line
        return "block"
    elif score >= (20):      # blank 2: your yellow line
        return "analyst"
    else:
        return "allow"    # blank 3
    


for i in [11287, 70770]:
    s = get_score(get_signals(emails[i]))
    print(i, s, get_decision(s))
    
    
results = {}
    
for row in emails:
    decision = get_decision(get_score(get_signals(row)))
    label = truth[row['message_id']]                    
    key = (label, decision)
    results[key] = results.get(key, 0) + 1     

for key in sorted(results):
    print(key, results[key])       
    





