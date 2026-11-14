"""Run this first: python starter/check_setup.py
It only checks that the lab files are in place. It does not solve anything."""
import csv, os

base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
path = os.path.join(base, "data", "emails_30d.csv")

with open(path, newline="", encoding="utf-8") as f:
    rows = sum(1 for _ in csv.DictReader(f))
emls = os.listdir(os.path.join(base, "data", "eml_samples"))

print(f"emails_30d.csv rows: {rows}")
print(f".eml samples: {len(emls)}")
print("Setup OK. Start with Phase 1 in README.md")
