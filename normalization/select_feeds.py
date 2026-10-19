import pandas as pd

INPUT_FILE = "data/raw/feeds/feed_inventory.csv"
OUTPUT_FILE = "config/selected_feeds.csv"

feeds = pd.read_csv(INPUT_FILE)

selected_vendors = [
    "Abuse.ch",
    "OpenPhish",
    "PhishTank",
    "Phishing Army",
    "C2IntelFeeds",
    "Ipsum",
    "Botvrij.eu",
    "ThreatCluster",
    "DigitalSide Threat-Intel",
    "CISA",
    "MalwareBazaar",
    "Alienvault"
]

selected = feeds[
    feeds["vendor"].isin(selected_vendors)
].copy()

selected = selected[
    selected["status"].str.lower() == "active"
]

selected = selected.drop_duplicates(subset=["url"])

selected.to_csv(
    OUTPUT_FILE,
    index=False,
    encoding="utf-8"
)

print("================================")
print("Selected Feed Inventory")
print("================================")
print("Selected feeds:", len(selected))
print("Saved to:", OUTPUT_FILE)

print("\nSelected feeds by vendor:")
print(selected["vendor"].value_counts())

print("\nSelected feeds by category:")
print(selected["category"].value_counts())