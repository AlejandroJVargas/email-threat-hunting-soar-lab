```python
QUERY = """
SELECT subject,
       COUNT(*) AS emails,
       COUNT(DISTINCT sender_domain) AS domains
FROM emails
WHERE filter_verdict = 'clean'
GROUP BY subject
ORDER BY domains DESC
LIMIT 10;
"""

SELECT sender_domain,
       COUNT(*)                  AS emails,
       COUNT(DISTINCT recipient) AS victims,
       MIN(domain_age_days)      AS domain_age,
       MIN(timestamp)            AS first_seen,
       MAX(timestamp)            AS last_seen
FROM emails
WHERE subject IN ('Your mailbox storage is full',
                  'Password expires in 24 hours',
                  'Action required: Unusual sign-in attempt blocked')
GROUP BY sender_domain
ORDER BY first_seen;


SELECT filter_verdict,
       COUNT(*) AS emails
FROM emails
WHERE subject IN ('Your mailbox storage is full',
                  'Password expires in 24 hours',
                  'Action required: Unusual sign-in attempt blocked')
GROUP BY filter_verdict;



SELECT COUNT(*)                  AS emails,
       COUNT(DISTINCT recipient) AS victims
FROM emails
WHERE subject IN ('Your mailbox storage is full',
                  'Password expires in 24 hours',
                  'Action required: Unusual sign-in attempt blocked');
```

