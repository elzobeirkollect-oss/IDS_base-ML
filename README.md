
# Machine Learning Based Intrusion Detection System (IDS)

## Overview

This project implements a real-time intrusion detection system using machine learning models to detect and classify network attacks. It leverages the UNSW-NB15 dataset to train models such as Random Forest, Decision Tree, and XGBoost to classify network traffic as either normal or malicious.

## Installation

### Requirements

To run this project, ensure you have the following dependencies installed:

- Python 3.x
- Libraries specified in `requirements.txt`

Install the necessary libraries with the following command:

```bash
pip install -r requirements.txt
```

### Setting Up the Project

1. Clone this repository:

    ```bash
    git clone https://github.com/your-username/ml-ids.git
    cd ml-ids
    ```

2. Install the required packages:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

### Real-Time Intrusion Detection

Run either of the following scripts for real-time intrusion detection:

```bash
python real_time_ids.py
```

OR

```bash
python real_time_ids_drop.py
```

- **`real_time_ids.py`** captures **all traffic passing through all protocols** and classifies unselected services as "unknown."
- **`real_time_ids_drop.py`** captures traffic **only from selected protocols** and ignores others.

### Interface Selection

When running the system, the user will be prompted to choose a network interface from the available options. Example:

```
Available network interfaces:
1. lo
2. eth0
Select the interface number to monitor: 2
Monitoring interface: eth0
Starting packet capture...
```

This allows the user to select the appropriate interface for monitoring network traffic in real time.

### Email Alerts

The system will automatically send an email alert if it detects malicious traffic. Before using the email alert system, you need to configure the email settings:

1. **Sender Email**: Add your sender email (e.g., a Gmail account).
2. **App Password**: If you're using Gmail, you'll need to create an app-specific password for secure authentication. You can generate one [here](https://myaccount.google.com/apppasswords).
3. **Receiver Email**: Add the email address where the alerts will be sent.

Modify the following lines in the script:

```python
sender_email = "your_email@gmail.com"  # Replace with your email
app_password = "your_app_password"  # Replace with your app password
receiver_email = "receiver_email@example.com"  # Replace with the recipient's email
```

Make sure to replace the placeholders with your actual email details to receive the alerts.

## Files

- **`X_train_columns.pkl`**: Preprocessed training data columns used for classification.
- **`best_model.pkl`**: Trained machine learning model.
- **`scaler.pkl`**: Preprocessing model for feature scaling.
- **`label_encoder.pkl`**: Label encoder used for converting categorical labels to numerical values.
