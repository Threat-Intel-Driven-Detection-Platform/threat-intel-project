import pandas as pd

BERT_FILE = "data/raw/feeds/bert_jan_feeds.csv"
KRAL_FILE = "data/raw/feeds/kraloveckey_feeds.csv"

OUTPUT_FILE = "data/raw/feeds/feed_inventory.csv"


def load_feed_file(path):
    try:
        df = pd.read_csv(path, sep=";")
    except Exception:
        df = pd.read_csv(path)

    return df


bert = load_feed_file(BERT_FILE)
kral = load_feed_file(KRAL_FILE)

print("Bert-JanP feeds:", len(bert))
print("Kraloveckey feeds:", len(kral))

# Normalize column names
bert.columns = [c.strip().lower() for c in bert.columns]
kral.columns = [c.strip().lower() for c in kral.columns]

# Rename possible URL/status variations
for df in [bert, kral]:
    if "url" not in df.columns and "feedurl" in df.columns:
        df.rename(columns={"feedurl": "url"}, inplace=True)

    if "feedstatus" in df.columns and "status" not in df.columns:
        df.rename(columns={"feedstatus": "status"}, inplace=True)

# Add repository origin
bert["catalog"] = "Bert-JanP"
kral["catalog"] = "Kraloveckey"

# Combine
combined = pd.concat([bert, kral], ignore_index=True)

# Remove exact duplicate feeds by URL
combined = combined.drop_duplicates(subset=["url"])

# Save
combined.to_csv(OUTPUT_FILE, index=False, encoding="utf-8")

print("================================")
print("Feed Inventory Created")
print("================================")
print("Total unique feeds:", len(combined))
print("Saved to:", OUTPUT_FILE)

if "category" in combined.columns:
    print("\nFeeds by category:")
    print(combined["category"].value_counts())

if "status" in combined.columns:
    print("\nFeeds by status:")
    print(combined["status"].value_counts())