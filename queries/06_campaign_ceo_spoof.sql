QUERY = """
SELECT sender , dmarc = 'fail' AS "DMARC Fail", COUNT(*) AS "Count", sender_country AS "Sender Country", reply_to AS "Reply-To", subject AS "Subject", MIN(timestamp) AS "Earliest Timestamp", MAX(timestamp) AS "Latest Timestamp", SUM(filter_verdict = 'clean') AS "clean"
FROM emails
WHERE sender_domain = 'lumenfield.com' AND dmarc = 'fail'
GROUP BY sender, sender_country, reply_to, subject;
"""