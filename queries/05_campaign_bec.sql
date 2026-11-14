QUERY = """
SELECT sender, recipient, subject,
    SUM(filter_verdict = 'clean') AS clean_emails,
    SUM(reply_to != '') AS emails_with_reply_to,
    COUNT(DISTINCT sender_ip) AS unique_sender_ips,
    COUNT(*) AS emails, 
    COUNT(DISTINCT recipient) AS victims,
    MIN(timestamp) AS first_seen,
    MAX(timestamp) AS last_seen
FROM emails
WHERE sender_domain = 'andeslogistics.com.ar' AND sender_country = 'NL'


SELECT sender, 
    COUNT(*) AS emails, 
    COUNT(DISTINCT recipient) AS victims,
    MIN(timestamp) AS first_seen,
    MAX(timestamp) AS last_seen
FROM emails
WHERE sender_domain = 'andeslogistics.com.ar' AND sender_country = 'NL'
GROUP BY sender;

SELECT sender, recipient, subject,
    COUNT(*) AS emails, 
    COUNT(DISTINCT recipient) AS victims,
    MIN(timestamp) AS first_seen,
    MAX(timestamp) AS last_seen
FROM emails
WHERE sender_domain = 'andeslogistics.com.ar' AND sender_country = 'NL'
GROUP BY subject;

SELECT sender_country, 
    COUNT(*) AS emails, 
    COUNT(DISTINCT recipient) AS unique_domains,
    MIN(timestamp) AS first_seen,
    MAX(timestamp) AS last_seen
FROM emails
WHERE sender_domain = 'andeslogistics.com.ar' AND sender_country = 'NL'
GROUP BY sender_country;

SELECT sender_country, COUNT(*) AS emails
FROM emails
WHERE sender_domain = 'andeslogistics.com.ar'
GROUP BY sender_country;
"""