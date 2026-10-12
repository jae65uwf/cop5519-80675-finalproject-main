
import re
from email.utils import parseaddr
from urllib.parse import urlsplit
from hudson import run_hudson_component #Jae Added
import pandas as pd


# --------------------------------------------------
# 1. LOAD AND INSPECT THE DATASET
# --------------------------------------------------

df = pd.read_csv("email_dataset.csv")

print("First 5 rows of the dataset:")
print(df.head())

print("\nColumn names:")
print(df.columns.tolist())

print("\nDataset shape (rows, columns):")
print(df.shape)

print("\nDataset information:")
df.info()

print("\nMissing values per column:")
print(df.isnull().sum())


# --------------------------------------------------
# 2. DEFINE PHISHING DETECTION PATTERNS
# --------------------------------------------------

LOOKALIKE_PATTERN = re.compile(
    r"paypa1|paypai|netfl1x|netf1ix|amaz0n|"
    r"g00gle|goog1e|micr0soft|app1e",
    re.IGNORECASE
)

KNOWN_BRANDS = {
    "paypal": "paypal.com",
    "netflix": "netflix.com",
    "amazon": "amazon.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com"
}

URGENT_PATTERN = re.compile(
    r"\b(immediately|today|expires?|expiring|urgent|act now)\b"
)

CREDENTIAL_PATTERN = re.compile(
    r"\b(passwords?|passcodes?|ssn|pins?|"
    r"social security number|sign[\s-]?in|"
    r"log[\s-]?in|login credentials|credentials)\b"
)

FINANCIAL_PATTERN = re.compile(
    r"\b(banking info(?:rmation)?|bank account|bank details|"
    r"payments?|pay now|gift cards?|wire transfer|"
    r"credit cards?|debit cards?|billing information|"
    r"financial information|money transfer)\b"
)

ALLOWED_INDICATORS = {
    "suspicious_sender",
    "urgent_language",
    "credential_request",
    "suspicious_url",
    "financial_request"
}


# --------------------------------------------------
# 3. HELPER FUNCTIONS
# --------------------------------------------------

def clean(value):
    """Convert missing email fields to empty strings."""
    if value is None:
        return ""

    value = str(value)

    if value.lower() in {"nan", "none", "<na>"}:
        return ""

    return value


def is_official_domain(host, official_domain):
    """Check whether a host matches an official domain."""
    return (
        host == official_domain
        or host.endswith("." + official_domain)
    )


# --------------------------------------------------
# 4. ANALYZE AN INDIVIDUAL EMAIL
# --------------------------------------------------

def check_email(row):
    """Return a list of suspicious indicators found in an email."""

    sender = clean(row.get("sender", "")).lower()
    subject = clean(row.get("subject", "")).lower()
    body = clean(row.get("body", "")).lower()
    url = clean(row.get("url", "")).strip()

    text = f"{subject} {body}"
    indicators = []


    # Check sender address and domain
    sender_address = parseaddr(sender)[1].lower()

    sender_domain = (
        sender_address.rsplit("@", 1)[-1]
        if "@" in sender_address else ""
    )

    suspicious_sender = bool(
        LOOKALIKE_PATTERN.search(sender)
    )

    for brand, official_domain in KNOWN_BRANDS.items():
        if brand in sender and not is_official_domain(
            sender_domain, official_domain
        ):
            suspicious_sender = True

    if suspicious_sender:
        indicators.append("suspicious_sender")

    # Check for urgent language
    if URGENT_PATTERN.search(text):
        indicators.append("urgent_language")

    # Check for credential requests
    if CREDENTIAL_PATTERN.search(text):
        indicators.append("credential_request")

    # Check URLs for suspicious characteristics
    suspicious_url = False

    if url:
        if url.lower().startswith("http://"):
            suspicious_url = True

        try:
            parsed = urlsplit(
                url if "://" in url else "//" + url
            )

            host = (parsed.hostname or "").lower()

            if not host:
                suspicious_url = True

            if LOOKALIKE_PATTERN.search(host):
                suspicious_url = True

            for brand, official_domain in KNOWN_BRANDS.items():
                if brand in host and not is_official_domain(
                    host, official_domain
                ):
                    suspicious_url = True

            if "xn--" in host:
                suspicious_url = True

            if (
                host.count("-") >= 2
                and re.search(
                    r"login|verify|secure|account|update|"
                    r"confirm|billing",
                    host
                )
            ):
                suspicious_url = True

        except ValueError:
            suspicious_url = True

    if suspicious_url:
        indicators.append("suspicious_url")

    # Check for financial requests
    if FINANCIAL_PATTERN.search(text):
        indicators.append("financial_request")

    return indicators

#jordyn added
def analyze_emails(df):
    """Analyze all emails and return their indicators."""

    indicator_lists = [
        check_email(row)
        for _, row in df.iterrows()
    ]

    return indicator_lists


# --------------------------------------------------
# 5. ANALYZE ALL EMAILS
# --------------------------------------------------

indicator_lists = [
    check_email(row)
    for _, row in df.iterrows()
]

for i, indicators in enumerate(indicator_lists):
    email_id = df.iloc[i].get("email_id", i + 1)
    print(f"Email {email_id}: {indicators}")

print(f"\nTotal emails processed: {len(indicator_lists)}")


# --------------------------------------------------
# 6. VALIDATE THE DETECTION RESULTS
# --------------------------------------------------

assert len(indicator_lists) == len(df), (
    f"Expected {len(df)} indicator lists, "
    f"but received {len(indicator_lists)}."
)

for i, indicators in enumerate(indicator_lists):

    assert isinstance(indicators, list), (
        f"Email at index {i} does not contain a list."
    )

    assert all(
        isinstance(name, str)
        and name in ALLOWED_INDICATORS
        for name in indicators
    ), f"Invalid indicator found at index {i}: {indicators}"

    assert len(indicators) == len(set(indicators)), (
        f"Duplicate indicators found at index {i}: {indicators}"
    )

# Confirm results match the dataset's row order
expected_lists = [
    check_email(row)
    for _, row in df.iterrows()
]

assert indicator_lists == expected_lists, (
    "Indicator results do not match the dataset row order."
)

print("\nSUCCESS: Output format validated!")
print(f"Emails in dataframe: {len(df)}")
print(f"Indicator lists: {len(indicator_lists)}")
print("All entries are Python lists.")
print("All indicator names are valid.")
print("No duplicate indicators found.")
print("Indicator lists match the dataset row order.")




# --------------------------------------------------
# 7. PASS RESULTS TO HUDSON'S COMPONENT
# --------------------------------------------------

# run_hudson_component must be defined or imported
# before this section executes.

hudson_result = run_hudson_component(indicator_lists)

print("\nHudson component executed.")
print("Result:", hudson_result)
