QUERY = """
SELECT sender_domain, substr(timestamp, 1, 10) AS day, COUNT(*) AS total
FROM emails
WHERE substr(timestamp, 1, 10) IN ('2026-10-07', '2026-10-14', '2026-10-21', '2026-10-28')
GROUP BY sender_domain
ORDER BY total DESC
LIMIT 10;
"""