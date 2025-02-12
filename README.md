
# Machine Learning Based Intrusion Detection System (IDS)

## Overview

This project is a real-time intrusion detection system that uses machine learning models to detect and classify network attacks. It uses the UNSW-NB15 dataset to train models like Random Forest, Decision Tree, and XGBoost to classify network traffic as normal or malicious.

## Installation

### Requirements

To run this project, ensure you have the following dependencies installed:

- Python 3.x
- Libraries specified in `requirements.txt`

You can install the necessary libraries by running:

```bash
pip install -r requirements.txt
```

### Setting up the Project

1. Clone this repository:

    ```bash
    git clone https://github.com/your-username/ml-ids.git
    cd ml-ids
    ```

2. Install the required packages:

    ```bash
    pip install -r requirements.txt
    ```

3. Ensure you have the dataset files (`NSW-NB15`) in the correct directory for training.

## Usage

1. **Train the Model:**

    Run the following script to train the machine learning model:
    
    ```bash
    python real_time_ids_drop.py
    ```

    This script preprocesses the data and trains the machine learning models like Random Forest, Decision Tree, and XGBoost, saving the best performing model for later use.

2. **Real-Time Intrusion Detection:**

    Once the model is trained, run the following script for real-time detection:
    
    ```bash
    python real_time_ids.py
    ```

    This script captures network traffic in real time, processes it, and classifies it using the trained model.

    **Note**: 
    - `real_time_ids_drop.py` **captures traffic only from selected protocols** and ignores others.
    - `real_time_ids.py` **captures all traffic passing through all protocols** and classifies unselected services as "unknown."

## Interface Selection

When running the system, the user will be prompted to choose a network interface from the available options. The following is an example of the prompt:

![Interface Selection](data/Screenshot%202025-02-13%20003125.png)

Example:

```
Available network interfaces:
1. lo
2. eth0
Select the interface number to monitor: 2
Monitoring interface: eth0
Starting packet capture...
```

This allows the user to select the appropriate interface for monitoring network traffic in real time.

## Email Alerts

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
