
from pathlib import Path
import pandas as pd
from lilly import check_email
from hudson import run_hudson_component


BASE_DIR = Path(__file__).resolve().parent
CSV_FILE = BASE_DIR / "phishing_email_edge_cases.csv"

df = pd.read_csv(CSV_FILE, keep_default_na=False)

print("\n=== EDGE-CASE DATASET ===")
print(f"Total emails loaded: {len(df)}")
print(df[["email_id", "actual_label", "edge_case"]].to_string(index=False))


print("\n=== LILLY'S DETECTION ENGINE ===")

indicator_lists = []

for _, row in df.iterrows():
    indicators = check_email(row)
    indicator_lists.append(indicators)

    print(f"Email {row['email_id']}: {indicators}")

assert len(indicator_lists) == len(df), (
    "The number of indicator lists does not match the dataset."
)

print(f"\nEmails analyzed: {len(indicator_lists)}")
print("Detection engine completed successfully.")


print("\n=== HUDSON'S SCORING AND REPORTING ===")

scored_data, hudson_results = run_hudson_component(
    indicator_lists,
    csv_filename=str(CSV_FILE),
    show_chart=True
)

print("\n=== COMPLETE PIPELINE RESULTS ===")

print(
    scored_data[
        [
            "email_id",
            "risk_score",
            "risk_level",
            "predicted_label"
        ]
    ].to_string(index=False)
)

actual = (
    scored_data["actual_label"]
    .astype(str)
    .str.strip()
    .str.lower()
)

predicted = (
    scored_data["predicted_label"]
    .astype(str)
    .str.strip()
    .str.lower()
)

valid_labels = {"phishing", "legitimate"}

if not set(actual).issubset(valid_labels):
    raise ValueError(
        f"Unexpected actual labels: {set(actual) - valid_labels}"
    )

if not set(predicted).issubset(valid_labels):
    raise ValueError(
        f"Unexpected predicted labels: "
        f"{set(predicted) - valid_labels}"
    )

tp = ((actual == "phishing") & (predicted == "phishing")).sum()
tn = ((actual == "legitimate") & (predicted == "legitimate")).sum()
fp = ((actual == "legitimate") & (predicted == "phishing")).sum()
fn = ((actual == "phishing") & (predicted == "legitimate")).sum()

total = len(scored_data)

accuracy = (tp + tn) / total if total else 0
precision = tp / (tp + fp) if (tp + fp) else 0
recall = tp / (tp + fn) if (tp + fn) else 0

print("\n=== EDGE-CASE PERFORMANCE REPORT ===")
print(f"Total emails: {total}")
print(f"True positives: {tp}")
print(f"True negatives: {tn}")
print(f"False positives: {fp}")
print(f"False negatives: {fn}")
print(f"Accuracy: {accuracy:.2%}")
print(f"Precision: {precision:.2%}")
print(f"Recall: {recall:.2%}")


output_file = BASE_DIR / "edge_case_pipeline_results.csv"
scored_data.to_csv(output_file, index=False)

print(f"\nResults saved to: {output_file}")
print("\nComplete edge-case pipeline finished.")
