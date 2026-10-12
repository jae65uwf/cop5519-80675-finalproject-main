
import pandas as pd

from lilly import analyze_emails
from hudson import run_hudson_component



def main():
    print("Starting Phishing Email Analyzer...\n")

    df = pd.read_csv("email_dataset.csv")
    indicator_lists = analyze_emails(df)

    print("Dataset loaded successfully.")
    print(f"Total emails: {len(df)}")

    indicator_lists = analyze_emails(df)

    scored_data, results = run_hudson_component(indicator_lists)

    print("\nPhishing Email Analyzer completed.")

    return scored_data, results


if __name__ == "__main__":
    main()
