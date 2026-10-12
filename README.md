# COP5519 Final Project: Phishing Email Analyzer

## Project Overview

The Phishing Email Analyzer is a Python application that analyzes email data for potential phishing indicators. The project is divided across multiple Python files, with separate components for detection, data processing, risk scoring, reporting, and edge-case testing.

The project includes the following files:

- `hudson.py` — Hudson's project component.
- `lilly.py` — Lilly's email detection component.
- `jordyn_part3.py` — The main entry point that runs the complete project.
- `test_edge_case.py` — Tests for edge cases.
- `email_dataset.csv` — The main labeled email dataset.
- `phishing_email_edge_cases.csv` — A dataset containing phishing-related edge cases.

## Requirements

Make sure Python 3 is installed. The project also requires these Python libraries:

- `pandas`
- `matplotlib`

## Installation

Open a terminal and navigate to the folder containing the project files. For example, if the folder is on your Desktop:

```bash
cd ~/Desktop/COP5519_Final_Project
```

Install the required libraries:

```bash
python3 -m pip install pandas matplotlib
```

If your computer has multiple Python installations, use the same Python interpreter to install the libraries and run the project.

## Run the Complete Project

Once the dependencies are installed, run:

```bash
python3 jordyn_part3.py
```

Run this command from the project folder so the program can locate the CSV files. Keep all six project files together in the same directory unless the code specifies different paths.

## Troubleshooting

- **`ModuleNotFoundError` for pandas or matplotlib:** Install the missing library using `python3 -m pip install pandas matplotlib`. Make sure you run the script with the same Python interpreter where the libraries were installed.
- **CSV file not found:** Confirm that `email_dataset.csv` and `phishing_email_edge_cases.csv` are in the project folder and that your terminal is currently in that folder.
- **Multiple Python installations:** Check which interpreter you are using with `which python3`. In VS Code, use **Command + Shift + P** → **Python: Select Interpreter** to select the intended interpreter.

## Project Files at a Glance

| File | Purpose |
|---|---|
| `hudson.py` | Hudson's component |
| `lilly.py` | Lilly's component |
| `jordyn_part3.py` | Main script for running the full project |
| `test_edge_case.py` | Edge-case testing |
| `email_dataset.csv` | Main email dataset |
| `phishing_email_edge_cases.csv` | Edge-case email dataset |

