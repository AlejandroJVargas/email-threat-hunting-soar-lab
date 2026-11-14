QUERY = """
SELECT sender_domain, COUNT(*) AS blocked
FROM emails
WHERE filter_verdict = 'spam'
GROUP BY sender_domain
ORDER BY blocked DESC;

SELECT recipient, COUNT(*) AS malicious_emails
FROM emails
WHERE subject IN ('Your mailbox storage is full',
                  'Password expires in 24 hours',
                  'Action required: Unusual sign-in attempt blocked')
   OR attachment_type IN ('html', 'zip', 'iso')
   OR (sender_domain = 'andeslogistics.com.ar' AND sender_country = 'NL')
   OR (sender_domain = 'lumenfield.com' AND dmarc = 'fail')
GROUP BY recipient
ORDER BY malicious_emails DESC
LIMIT 10;

"""