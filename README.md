
# Machine Learning Based Intrusion Detection System (IDS)

## Overview

This project is a real-time intrusion detection system that leverages machine learning models to detect and classify network attacks. It uses the UNSW-NB15 dataset to train multiple machine learning models like Random Forest, Decision Tree, and XGBoost to classify network traffic as normal or malicious. The system includes real-time traffic capture, machine learning-based classification, and an alert system that notifies administrators via email when an attack is detected.

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
## Usage

1. **Train the Model:**

    To train the machine learning model, run the following script:
    
    ```bash
    python real_time_ids_drop.py
    ```

## Interface Selection

When running the system, the user will be prompted to choose a network interface from the available options. The following is an example of the prompt:

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

## Files

- **`real_time_ids.py`**: Real-time intrusion detection script that captures traffic and classifies it using the trained model.
  - This script captures network traffic in real time using a packet-sniffing tool (Scapy), processes the data, and classifies it using the model trained by `real_time_ids_drop.py`.
  - If an attack is detected, it triggers an email alert with details about the threat.

- **`X_train_columns.pkl`**: Preprocessed training data columns used for classification.
- **`best_model.pkl`**: Trained machine learning model.
- **`scaler.pkl`**: Preprocessing model for feature scaling.
- **`label_encoder.pkl`**: Label encoder used for converting categorical labels to numerical values.
