"""
SQL practice on your own emails.csv
-----------------------------------
Loads emails.csv into a small SQL database in memory (sqlite3 comes with Python,
nothing to install), then runs the query you write below.

How to use:
  1. Put this file in the same folder as emails.csv
  2. Change the QUERY text below
  3. Run:  python practice_sql.py
"""

import csv
import sqlite3

# ---- WRITE YOUR QUERY HERE ----
QUERY = """
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
# -------------------------------

# Build the table "emails" from the CSV
db = sqlite3.connect(":memory:")
with open("data/emails_30d.csv", newline="", encoding="utf-8") as file:
    rows = list(csv.DictReader(file))
columns = list(rows[0].keys())
db.execute(f"CREATE TABLE emails ({', '.join(columns)})")
db.executemany(
    f"INSERT INTO emails VALUES ({', '.join('?' for _ in columns)})",
    [tuple(r[c] for c in columns) for r in rows],
)

# Run the query and print the results as a small table
try:
    cursor = db.execute(QUERY)
    headers = [d[0] for d in cursor.description]
    print(" | ".join(headers))
    print("-" * 40)
    for row in cursor.fetchall():
        print(" | ".join(str(value) for value in row))
except sqlite3.Error as error:
    print("SQL error:", error)
