import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

# These indicator names must match the analyzer output.
RISK_WEIGHTS = {
    "suspicious_sender": 20,
    "urgent_language": 15,
    "credential_request": 25,
    "suspicious_url": 25,
    "financial_request": 15
}


def load_and_clean_data(csv_filename="email_dataset.csv"):
    """Load and clean the labeled email dataset."""
    project_folder = Path(__file__).parent
    email_data = pd.read_csv(project_folder / csv_filename)

    email_data["url"] = email_data["url"].fillna("")

    text_columns = ["sender", "subject", "body", "url", "actual_label"]
    for column in text_columns:
        email_data[column] = email_data[column].str.strip()

    email_data["actual_label"] = email_data["actual_label"].str.lower()
    email_data = email_data.drop_duplicates().reset_index(drop=True)

    return email_data


def calculate_risk_score(indicators):
    """Calculate a 0-100 risk score from analyzer indicators."""
    score = 0

    for indicator in indicators:
        if indicator in RISK_WEIGHTS:
            score += RISK_WEIGHTS[indicator]

    return min(score, 100)


def classify_risk(score):
    """Assign a risk level and predicted label."""
    if score >= 60:
        return "High", "phishing"
    elif score >= 30:
        return "Medium", "legitimate"
    else:
        return "Low", "legitimate"


def score_analyzer_results(email_data, indicator_lists):
    """
    Apply Hudson's scoring to analyzer output.

    indicator_lists must contain one list of indicators for each email,
    in the same order as email_data.
    """
    if len(email_data) != len(indicator_lists):
        raise ValueError(
            "The analyzer must return one indicator list for each email."
        )

    results_data = email_data.copy()
    results_data["indicators"] = indicator_lists

    scores = []
    risk_levels = []
    predicted_labels = []

    for indicators in indicator_lists:
        score = calculate_risk_score(indicators)
        risk_level, predicted_label = classify_risk(score)

        scores.append(score)
        risk_levels.append(risk_level)
        predicted_labels.append(predicted_label)

    results_data["risk_score"] = scores
    results_data["risk_level"] = risk_levels
    results_data["predicted_label"] = predicted_labels

    return results_data


def calculate_results(actual_labels, predicted_labels):
    """Calculate classification totals and performance metrics."""
    if len(actual_labels) != len(predicted_labels):
        raise ValueError(
            "Actual and predicted label lists must be the same length."
        )

    total_emails = len(actual_labels)

    if total_emails == 0:
        raise ValueError("Cannot calculate results for an empty dataset.")

    true_positives = 0
    true_negatives = 0
    false_positives = 0
    false_negatives = 0

    for actual, predicted in zip(actual_labels, predicted_labels):
        if actual == "phishing" and predicted == "phishing":
            true_positives += 1
        elif actual == "legitimate" and predicted == "legitimate":
            true_negatives += 1
        elif actual == "legitimate" and predicted == "phishing":
            false_positives += 1
        elif actual == "phishing" and predicted == "legitimate":
            false_negatives += 1

    flagged_emails = true_positives + false_positives
    flagged_percentage = (flagged_emails / total_emails) * 100
    accuracy = ((true_positives + true_negatives) / total_emails) * 100

    precision = (
        true_positives / (true_positives + false_positives) * 100
        if true_positives + false_positives > 0
        else 0
    )

    recall = (
        true_positives / (true_positives + false_negatives) * 100
        if true_positives + false_negatives > 0
        else 0
    )

    return {
        "total_emails": total_emails,
        "flagged_emails": flagged_emails,
        "flagged_percentage": flagged_percentage,
        "true_positives": true_positives,
        "true_negatives": true_negatives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall
    }


def print_report(results):
    """Print the final evaluation report."""
    print("\n--- Phishing Analyzer Report ---")
    print("Total emails:", results["total_emails"])
    print("Flagged emails:", results["flagged_emails"])
    print(f'Percentage flagged: {results["flagged_percentage"]:.2f}%')

    print("\nClassification Results:")
    print("True positives:", results["true_positives"])
    print("True negatives:", results["true_negatives"])
    print("False positives:", results["false_positives"])
    print("False negatives:", results["false_negatives"])

    print("\nPerformance Metrics:")
    print(f'Accuracy: {results["accuracy"]:.2f}%')
    print(f'Precision: {results["precision"]:.2f}%')
    print(f'Recall: {results["recall"]:.2f}%')


def create_results_chart(results):
    """Create a bar chart of classification results."""
    categories = [
        "True Positives",
        "True Negatives",
        "False Positives",
        "False Negatives"
    ]

    values = [
        results["true_positives"],
        results["true_negatives"],
        results["false_positives"],
        results["false_negatives"]
    ]

    plt.figure(figsize=(8, 5))
    plt.bar(categories, values)
    plt.title("Phishing Email Analyzer Results")
    plt.xlabel("Classification Result")
    plt.ylabel("Number of Emails")
    plt.tight_layout()
    plt.show()


def run_hudson_component(indicator_lists, csv_filename="email_dataset.csv",
                         show_chart=True):
    """
    Main entry point for the group project.

    Give this function the analyzer's indicator lists. It loads/cleans the
    dataset, scores every email, calculates final metrics, prints the report,
    and optionally displays the chart.
    """
    email_data = load_and_clean_data(csv_filename)
    scored_data = score_analyzer_results(email_data, indicator_lists)

    results = calculate_results(
        scored_data["actual_label"].tolist(),
        scored_data["predicted_label"].tolist()
    )

    print_report(results)

    if show_chart:
        create_results_chart(results)

    return scored_data, results
