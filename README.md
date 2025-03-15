AI-Based Network Monitoring & Threat Detection System 🚀
Real-Time Packet Monitoring, DoS Attack Prevention & Automated Alert System

🔹 Project Description
This project implements an AI-powered network monitoring system using Flask, Scapy, and Machine Learning to detect DoS attacks, unauthorized access, and suspicious network activity in real-time. The system:

✔ Monitors live network traffic

✔ Identifies & blocks malicious IPs using AI

✔ Sends real-time email alerts when threats are detected

✔ Provides a GUI-based interface for monitoring

✔ Visualizes network traffic trends with dynamic graphs



🔹 Features
✅ User Authentication → Secure login system using hashlib

✅ Interface Selection → Choose network interface dynamically

✅ Real-Time Packet Capture → Uses Scapy to analyze network traffic

✅ DoS Attack Detection → AI model (RandomForestClassifier) detects threats

✅ Automated IP Blocking → Uses iptables to block suspicious IPs

✅ Email Alerts → Sends instant alerts to admins

✅ Graphical Traffic Monitoring → Uses matplotlib for real-time visualization

✅ Blocked IP List → View & manage blocked IPs

✅ Web-Based UI → Built using CustomTkinter


🔹 Tech Stack Used

Frontend (GUI Interface)

Python GUI → CustomTkinter

Data Visualization → matplotlib, seaborn

Backend (Packet Capture & AI Processing)

Network Traffic Monitoring → Scapy

Machine Learning → scikit-learn, RandomForestClassifier

AI Model Training → NumPy, Pandas

Security & Alerts

Firewall & Blocking → iptables

Email Alerts → smtplib, ssl


🔹 System Workflow (How It Works?)
1️⃣ User logs in → Selects network interface

2️⃣ AI starts monitoring packets → Uses Scapy for packet capture

3️⃣ Machine Learning model detects anomalies → Identifies DoS attacks

4️⃣ If suspicious activity is found:

🚫 IP is blocked using iptables

📩 Email alert is sent to admin

5️⃣ User can view traffic graphs & blocked IPs


🔹 Installation Guide
Prerequisites

🔹 Python 3.8+

🔹 pip (Package Manager)

🔹 Admin privileges (For IP blocking)



Step 1: Clone the Repository

git clone
 https://github.com/yourusername/network-monitoring-ai.git

cd network-monitoring-ai

Step 2: Install Dependencies

pip install -r requirements.txt

Step 3: Run the Application

sudo python main.py
