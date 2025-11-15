# DDoS and DoS Mitigation Tool Using AI

An intelligent network monitoring and threat detection system that uses machine learning to identify and mitigate DoS attacks in real-time.

## Overview

This project is a comprehensive network security tool that monitors network traffic, detects potential DoS (Denial of Service) attacks using artificial intelligence, and automatically blocks malicious IP addresses. The system features a modern graphical interface built with CustomTkinter and provides real-time visualization of network traffic patterns.

The tool combines packet capture, machine learning, and automated response mechanisms to protect networks from attack traffic while providing administrators with detailed monitoring capabilities and instant email notifications.

## Key Features

### Security Features
- Real-time DoS attack detection using Random Forest Classifier
- Automatic IP blocking via iptables firewall rules
- Threshold-based traffic analysis (default: 200 packets/second)
- Continuous monitoring of network interfaces
- Automatic threat response system

### Monitoring Capabilities
- Live packet capture from multiple network interfaces
- Real-time traffic visualization with dynamic graphs
- Detailed packet information display (source, destination, protocol, length)
- Packet per second tracking
- Historical traffic data analysis

### User Interface
- Secure login system with SHA-224 password hashing
- Network interface selection (wlan0, eth0, enp0s3, etc.)
- Interactive packet capture controls (start/stop)
- Live traffic graph window
- Blocked IP address management interface
- Color-coded alert system

### Alert System
- Automated email notifications when attacks are detected
- Visual warnings in the GUI
- Detailed attack information including timestamp and source IP
- Real-time blocked IP list updates

## Technical Architecture

### Machine Learning Component
- Algorithm: Random Forest Classifier with 10 estimators
- Training: Synthetic dataset generation for attack pattern recognition
- Prediction: Real-time classification of incoming traffic patterns
- Threshold: Classifies traffic exceeding 200 packets as potential attack

### Network Monitoring
- Packet capture engine: Scapy
- Supported protocols: IP, Ethernet, TCP, UDP, ICMP
- Multi-threaded packet processing for non-blocking operation
- Per-IP packet counting and analysis

### Firewall Integration
- Direct iptables command integration
- Automatic DROP rule creation for malicious IPs
- Firewall rule cleanup on application exit
- Real-time blocked IP retrieval from iptables

## Technology Stack

### GUI and Visualization
- CustomTkinter 5.2.2 - Modern themed GUI framework
- Pillow 10.2.0 - Image processing for login interface
- Matplotlib 3.8.2 - Real-time graph plotting
- Seaborn 0.13.2 - Enhanced data visualization

### Networking and Security
- Scapy 2.5.0 - Packet capture and network analysis
- iptables - Linux firewall management
- smtplib with SSL - Secure email notifications

### Machine Learning
- scikit-learn 1.3.0 - Random Forest implementation
- NumPy 1.26.4 - Numerical computations
- Pandas 2.1.4 - Data manipulation

### Optional Deep Learning
- TensorFlow 2.15.0 - Deep learning framework
- Keras 2.15.0 - Neural network API

## Installation

### System Requirements
- Linux operating system (required for iptables)
- Python 3.8 or higher
- Root/sudo privileges (required for packet capture and firewall management)
- Active network interface

### Step 1: Clone the Repository
```bash
git clone https://github.com/KrItHiCk007/DDOS-and-DOS-mitigation-tool-using-AI.git
cd DDOS-and-DOS-mitigation-tool-using-AI
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

Note: Some packages like scapy may require additional system libraries. On Ubuntu/Debian:
```bash
sudo apt-get install python3-dev libpcap-dev
```

### Step 3: Configure Email Alerts
Edit main.py and add your email credentials:
```python
sender = "your-email@gmail.com"
password = "your-app-password"
receiver = "admin-email@gmail.com"
```

For Gmail, you need to use an App Password (not your regular password).

### Step 4: Add User Images
Ensure you have the following images in the images/ directory:
- user.png - User icon for login screen
- login.png - Login button icon

## Usage

### Starting the Application

1. Run with sudo privileges (required for packet capture):
```bash
sudo python3 main.py
```

2. Login credentials:
   - Username: admin
   - Password: admin

### Selecting Network Interface

After login, choose your network interface:
- Select from predefined interfaces (wlan0, eth0, enp0s3, etc.)
- Or manually enter your interface name
- Click "Select" to proceed

### Monitoring Traffic

1. Click "Start Capture" to begin monitoring
2. View captured packets in real-time
3. Watch for red alert messages indicating blocked IPs
4. Click "Show Graph" to view traffic visualization
5. Click "Blocked IPs" to see all blocked addresses
6. Click "Stop Capture" when done

### Understanding the Interface

Packet Display Columns:
- Time: Timestamp of packet capture
- Source: Origin IP address
- Destination: Target IP address
- Protocol: Network protocol used
- Length: Packet size in bytes
- Details: Additional packet information

## How It Works

### Attack Detection Process

1. Packet Capture
   - Scapy monitors the selected network interface
   - Each packet is analyzed for source IP, destination, protocol, and size
   - Packet counts are maintained per source IP address

2. AI Analysis
   - Packet count per IP is fed to the Random Forest model
   - Model predicts if traffic pattern indicates attack (1) or normal (0)
   - Threshold: More than 200 packets from single IP triggers classification

3. Automated Response
   - If attack detected, IP is immediately added to iptables DROP rule
   - GUI displays warning message with blocked IP
   - Email notification sent to administrator
   - IP added to blocked list for monitoring

4. Continuous Monitoring
   - System updates blocked IP list every 3 seconds
   - Real-time graph shows incoming packet trends
   - All captured packets logged in scrollable interface

## Security Considerations

### Password Security
- Passwords are hashed using SHA-224 before comparison
- Default credentials should be changed in production
- Consider implementing more robust authentication

### Email Security
- Uses SSL/TLS for secure email transmission
- Requires app-specific passwords for Gmail
- Email credentials stored in code (consider environment variables)

### Network Security
- Requires root access - use with caution
- Firewall rules affect all system traffic
- Always test in controlled environment first
- Clear iptables rules on exit to prevent lockout

## Known Limitations

- Requires Linux system with iptables
- Simple threshold-based detection may cause false positives
- Email credentials stored in plaintext in code
- Limited to analyzing packet count rather than deep packet inspection
- Random Forest model trained on synthetic data
- No whitelist functionality for trusted IPs
- Cannot detect sophisticated distributed attacks

## Future Enhancements

- Implement IP whitelist to prevent blocking trusted sources
- Add support for Windows firewall
- Use deep packet inspection for better threat analysis
- Implement user management system
- Add database for historical attack logging
- Create API for integration with other security tools
- Implement rate limiting instead of complete blocking
- Add support for IPv6 addresses
- Improve ML model with real attack data
- Add exportable reports and analytics

## Troubleshooting

### Permission Errors
```bash
sudo python3 main.py  # Always run with sudo
```

### Interface Not Found
Check available interfaces:
```bash
ip link show
```

### Email Not Sending
- Verify Gmail app password is correct
- Check internet connectivity
- Enable "Less secure app access" if needed

### Blocked Out of Network
Clear iptables rules:
```bash
sudo iptables -F INPUT
```

## Project Structure

```
DDOS-and-DOS-mitigation-tool-using-AI/
├── main.py              # Main application file
├── requirements.txt     # Python dependencies
├── images/             
│   ├── login.png       # Login interface icon
│   └── user.png        # User profile icon
└── README.md           # This file
```

## Contributing

Contributions are welcome to improve this security tool. Please test thoroughly before submitting pull requests, especially changes affecting firewall rules or packet capture.

## Author

KrItHiCk007

Developed by: Krithick A

## License

This project is intended for educational and research purposes. Use responsibly and only on networks you own or have explicit permission to monitor.

## Acknowledgments

- Scapy community for the powerful packet manipulation library
- CustomTkinter developers for the modern GUI framework
- scikit-learn team for machine learning tools
