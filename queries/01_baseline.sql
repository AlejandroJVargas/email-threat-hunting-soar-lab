QUERY = '''
SELECT COUNT(*) AS total_emails,
       MIN(timestamp) AS first_email,
       MAX(timestamp) AS last_email
FROM emails;

SELECT filter_verdict, COUNT(*) AS total
FROM emails
GROUP BY filter_verdict
ORDER BY total DESC;

SELECT dmarc, COUNT(*) AS total
FROM emails
GROUP BY dmarc
ORDER BY total DESC;

'''