from email.parser import BytesParser 
from email import policy
import re
import hashlib
import os
import json



def load_email(path):
        with open(path, "rb") as file:
            return BytesParser(policy=policy.default).parse(file)

def parse_email(path):
    msg = load_email(path)
    result = {}
    
    result["file"] = os.path.basename(path)
    
    result["from"] = msg['From']
    result["to"] = msg['To']
    result["subject"] = msg['Subject']
    result["reply_to"] = msg['Reply-To'] or '(none)'
    result["return_path"] = msg['Return-Path']
    result["date"] = msg['Date']
    
    auth = msg['Authentication-Results']
    result["spf"] = re.search(r"spf=(\w+)", auth).group(1)
    result["dkim"] = re.search(r"dkim=(\w+)", auth).group(1)
    result["dmarc"] = re.search(r"dmarc=(\w+)", auth).group(1)
    result["sender_ip"] = re.search(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", msg['Received']).group(1)
    
    
    urls = []
    for part in msg.walk():
        if part.get_content_type() == "text/plain" or part.get_content_type() == "text/html":
            urls += re.findall(r"https?://[^\s\"'<>]+", part.get_content() )
    
    
    
    result["urls"] = list(set(urls))
            
            
    attachments = []
    for part in msg.walk():
        if part.get_filename():
            data = part.get_payload(decode=True)
            file_hash = hashlib.sha256( data ).hexdigest()
            attachments.append({
                "name": part.get_filename(),
                "type": part.get_content_type(),
                "sha256": file_hash
            })
    
    result["attachments"] = attachments
    
       
    return result

def get_domain(email_address):
    match = re.search(r"@([\w.-]+)", email_address)
    return match.group(1).lower() if match else None

def red_flags(r):
    flags = []
    from_domain = get_domain(r["from"])
    reply_domain = get_domain(r["reply_to"])
    return_domain = get_domain(r["return_path"])

    if reply_domain and reply_domain != from_domain:
        flags.append("Reply-To domain does not match From domain")
        
    if return_domain and return_domain != from_domain:
        flags.append("Return-Path domain does not match From domain")
    
    if r["dmarc"] == "fail":
        flags.append("DMARC check failed")
    
    if re.search(r"microsoft|office", r["from"], re.IGNORECASE) and from_domain != "microsoft.com":
        flags.append("Email claims to be from Microsoft/Office")
            

    for a in r["attachments"]:
        if a["name"].lower().endswith((".html", ".htm", ".iso", ".zip")):
            flags.append(f"Suspicious attachment: {a['name']}")
            
    return flags

all_results = []




for file in os.listdir("data/eml_samples"):
    if file.endswith(".eml"):
        path = os.path.join("data/eml_samples", file)
        parsed_email = parse_email(path)
        parsed_email["red_flags"] = red_flags(parsed_email)
        all_results.append(parsed_email) 
        print(f"{file}: {parsed_email['red_flags']}")


with open("parsed_emails.json", "w") as f:
    json.dump(all_results, f, indent=2)

print(f"Saved {len(all_results)} emails to parsed_emails.json")




