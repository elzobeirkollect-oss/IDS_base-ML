  
import smtplib
import pandas as pd
from scapy.all import sniff, get_if_list
import joblib
from sklearn.preprocessing import StandardScaler
import datetime

# Load necessary files
scaler = joblib.load('scaler.pkl')
model = joblib.load('best_model.pkl')
label_encoder = joblib.load('label_encoder.pkl')
X_train_columns = joblib.load('X_train_columns.pkl')
numerical_features = ['spkts', 'dpkts', 'sbytes', 'dbytes', 'rate', 'dur', 'length', 'direction', 'size_variance']

# Email configuration
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
EMAIL = "FYP2_imp_send@gmail.com"  # Replace with your email
APP_PASSWORD = "aybo mvmr mrfz gfib"  # Provided app-specific password
RECIPIENT = "FYP2_imp_recipient@gmail.com"  # Replace with recipient email

# Initialize SMTP server
server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
server.starttls()
server.login(EMAIL, APP_PASSWORD)

# Function to send email alerts
def send_alert(alert_details):
    subject = f"Intrusion Alert: {alert_details['attack_type']} Detected!"
    body = (
        f"Subject: {subject}\n\n"
        f"A malicious traffic pattern has been detected.\n\n"
        f"Details:\n"
        f"- Type of Attack: {alert_details['attack_type']}\n"
        f"- Time of Detection: {alert_details['timestamp']}\n"
        f"- Protocol: {alert_details['protocol']}\n"
        f"- Service: {alert_details['service']}\n"
        f"- Packets Sent: {alert_details['spkts']}\n"
        f"- Packets Received: {alert_details['dpkts']}\n"
        f"- Data Sent: {alert_details['sbytes']} bytes\n"
        f"- Data Received: {alert_details['dbytes']} bytes\n"
        f"- Duration: {alert_details['dur']} seconds\n"
        f"- Data Rate: {alert_details['rate']} bytes/second\n"
        f"- Traffic Direction Ratio: {alert_details['direction']}\n"
        f"- Size Variance: {alert_details['size_variance']}\n\n"
        f"Please investigate this activity immediately!"
    )
    server.sendmail(EMAIL, RECIPIENT, body)
    print(f"Alert email sent for {alert_details['attack_type']}!")

# Function to preprocess and predict packet data
def process_packet(packet):
    if packet.haslayer('IP'):  # Ensure the packet contains an IP layer
        # Protocol detection
        if packet.haslayer('TCP'):
            proto = 'tcp'
        elif packet.haslayer('UDP'):
            proto = 'udp'
        elif packet.haslayer('ICMP'):
            proto = 'icmp'
        else:
            proto = 'unknown'

        # Service detection based on port numbers
        def detect_service(packet):
            if packet.haslayer('TCP'):
                if packet['TCP'].dport == 80 or packet['TCP'].sport == 80:
                    return 'http'
                elif packet['TCP'].dport == 443 or packet['TCP'].sport == 443:
                    return 'https'
                elif packet['TCP'].dport == 21 or packet['TCP'].sport == 21:
                    return 'ftp'
                elif packet['TCP'].dport == 25 or packet['TCP'].sport == 25:
                    return 'smtp'
                elif packet['TCP'].dport == 22 or packet['TCP'].sport == 22:
                    return 'ssh'
                elif packet['TCP'].dport == 445 or packet['TCP'].sport == 445:
                    return 'smb'
                elif packet['TCP'].dport == 3389 or packet['TCP'].sport == 3389:
                    return 'rdp'
                elif packet['TCP'].dport == 23 or packet['TCP'].sport == 23:
                    return 'telnet'
            elif packet.haslayer('UDP'):
                if packet['UDP'].dport == 53 or packet['UDP'].sport == 53:
                    return 'dns'
                elif packet['UDP'].dport == 123 or packet['UDP'].sport == 123:
                    return 'ntp'
            return 'unknown'

        service = detect_service(packet)

        # Extract features
        spkts = 1
        dpkts = 1
        sbytes = len(packet['IP'].payload)
        dbytes = len(packet)
        rate = (sbytes + dbytes) / 1.0  # Assuming real-time rate approximation
        dur = 1.0  # Assume fixed duration for single packet processing
        length = sbytes + dbytes
        direction = spkts / dpkts if dpkts > 0 else 0
        size_variance = (sbytes - dbytes) ** 2

        # Prepare real-time data
        real_time_data = pd.DataFrame([{
            'proto': proto, 'service': service, 'spkts': spkts, 'dpkts': dpkts,
            'sbytes': sbytes, 'dbytes': dbytes, 'rate': rate, 'dur': dur,
            'length': length, 'direction': direction, 'size_variance': size_variance
        }])

        # Debugging: Print extracted features
        print(f"Extracted Features for Prediction:\n{real_time_data}")

        # One-hot encode and align columns
        real_time_data_encoded = pd.get_dummies(real_time_data, columns=['proto', 'service'])
        missing_cols = set(X_train_columns) - set(real_time_data_encoded.columns)
        missing_data = pd.DataFrame(0, index=real_time_data_encoded.index, columns=list(missing_cols))
        real_time_data_encoded = pd.concat([real_time_data_encoded, missing_data], axis=1)
        real_time_data_encoded = real_time_data_encoded[X_train_columns]

        # Normalize numerical features
        real_time_data_encoded[numerical_features] = scaler.transform(real_time_data_encoded[numerical_features])

        # Predict attack type
        attack_type_encoded = model.predict(real_time_data_encoded)[0]
        attack_type = label_encoder.inverse_transform([attack_type_encoded])[0]

        # Check and alert for malicious traffic
        if attack_type != "Normal":  # Malicious traffic
            alert_details = {
                'attack_type': attack_type,
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'protocol': proto,
                'service': service,
                'spkts': spkts,
                'dpkts': dpkts,
                'sbytes': sbytes,
                'dbytes': dbytes,
                'dur': dur,
                'rate': rate,
                'direction': direction,
                'size_variance': size_variance,
            }
            print(f"Malicious traffic detected: {alert_details}")
            send_alert(alert_details)
        else:
            print("Normal traffic detected.")

# List available interfaces
interfaces = get_if_list()
print("Available network interfaces:")
for idx, iface in enumerate(interfaces):
    print(f"{idx + 1}. {iface}")
selected_idx = int(input("Select the interface number to monitor: ")) - 1
selected_iface = interfaces[selected_idx]
print(f"Monitoring interface: {selected_iface}")

# Start sniffing
print("Starting packet capture...")
sniff(iface=selected_iface, prn=process_packet, store=False)
