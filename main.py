from PIL import Image, ImageTk
from tkinter import messagebox
import hashlib
import sys
import os
import smtplib
import time
import numpy as np
import threading
import customtkinter as ctk
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import defaultdict
from scapy.all import sniff, Ether, IP
from sklearn.ensemble import RandomForestClassifier
import random
from email.message import EmailMessage
import ssl
# Global Variables
packet_count = defaultdict(int)
incoming_packets = defaultdict(int)
threshold = 200
sniffing = False
captured_packets = []
graph_window = None
x_data = []
incoming_graph = []
time_counter = 0
packet_list_frame = None
warning_label = None
blocked_ips = set()
update_interval = 3000  # 3 seconds for blocked IP updates

# Initialize the main window
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")
root = ctk.CTk()
root.geometry("1920x1080")

# Tkinter variables
interface1 = ctk.StringVar(value="wlan0")

def train_model():
    X_train = np.array([[random.randint(1, 500)] for _ in range(100)])
    y_train = np.array([1 if x[0] > 200 else 0 for x in X_train])
    model = RandomForestClassifier(n_estimators=10, random_state=42)
    model.fit(X_train, y_train)
    return model

rf_model = train_model()

# Initialize matplotlib figure
fig, ax = plt.subplots()
ax.set_title("Live Incoming Packet Monitor")
ax.set_xlabel("Time (seconds)")
ax.set_ylabel("Packets per second")
line_in, = ax.plot([], [], 'g-', label="Incoming Packets")
ax.legend()

def load_interface():
    for widget in root.winfo_children():
        widget.destroy()
    interface_page()

def login():
    username = username_entry.get()
    user_password = password_entry.get()
    password = "admin"
    hashed_password = hashlib.sha224(user_password.encode('utf-8')).hexdigest()
    plain_text_password = hashlib.sha224(password.encode('utf-8')).hexdigest()

    if username == "admin" and plain_text_password == hashed_password:
        load_interface()
    else:
        messagebox.showwarning("Warning", "Invalid credentials")

def setup_login_page():
    global username_entry, password_entry

    main_frame = ctk.CTkFrame(master=root, width=1900, height=990, fg_color="#252727")
    main_frame.grid(row=0, column=0, padx=10, pady=10)

    login_frame = ctk.CTkFrame(master=main_frame, width=1000, height=790, corner_radius=30,
                               border_width=1, border_color="white")
    login_frame.place(relx=0.5, rely=0.5, anchor="center")

    user_image = Image.open("images/user.png").resize((100, 100))
    login_image = Image.open("images/login.png").resize((50, 50))
    tk_user_image = ImageTk.PhotoImage(user_image)
    tk_login_image = ImageTk.PhotoImage(login_image)

    image_label = ctk.CTkLabel(master=login_frame, image=tk_user_image, text="", corner_radius=7)
    image_label.place(relx=0.5, rely=0.2, anchor="center")

    ctk.CTkLabel(master=login_frame, text="SIGN IN", text_color="white",
                 font=("Arial", 16, "bold")).place(relx=0.5, rely=0.3, anchor="center")

    username_entry = ctk.CTkEntry(master=login_frame, width=300, height=40, placeholder_text="Username",
                                  corner_radius=15, border_color="white", border_width=2, text_color="white")
    username_entry.place(relx=0.5, rely=0.4, anchor="center")

    password_entry = ctk.CTkEntry(master=login_frame, width=300, height=40, placeholder_text="Password",
                                  corner_radius=15, show="*", border_color="white", border_width=2, text_color="white")
    password_entry.place(relx=0.5, rely=0.5, anchor="center")

    login_button = ctk.CTkButton(master=login_frame, width=200, height=40, text="Login",
                                 corner_radius=15, border_width=2, border_color="white", text_color="white",
                                 command=login,font=("airel",16,"bold"))
    login_button.place(relx=0.5, rely=0.6, anchor="center")

    ctk.CTkLabel(master=login_frame, text_color="white", text="Developed by : Krithick A",
                 font=("Arial", 16, "bold")).place(relx=0.5, rely=0.7, anchor="center")

    image_label.image = tk_user_image

def interface_page():
    main_frame = ctk.CTkFrame(master=root, height=1060, width=1900, fg_color="#202525")
    main_frame.grid(row=0, column=0, padx=10, pady=10)

    title_frame = ctk.CTkFrame(master=main_frame, width=1880, height=100, border_width=2, border_color="white",
                               corner_radius=20)
    title_frame.grid(row=0, column=0, padx=10, pady=10)

    interface_frame = ctk.CTkFrame(master=main_frame, width=1560, height=850, border_width=2,
                                   border_color="white", corner_radius=20)
    interface_frame.grid(row=1, column=0, padx=10, pady=10)

    ctk.CTkLabel(master=title_frame, text="SELECT THE INTERFACE", text_color="white",
                 font=("Arial", 20, "bold")).place(relx=0.5, rely=0.5, anchor="center")

    interfaces = ["wlan0", "wlan1", "eth0", "enp0s3", "Ethernet", "wlo1"]
    y_position = 0.1

    for iface in interfaces:
        ctk.CTkRadioButton(master=interface_frame, text_color="white", text=iface,
                           font=("Arial", 20, "bold"), variable=interface1,
                           value=iface).place(relx=0.1, rely=y_position)
        y_position += 0.1

    ctk.CTkLabel(master=interface_frame, text_color="white", text="Enter The Interface Name :",
                 font=("Arial", 20, "bold")).place(relx=0.1, rely=0.7)

    entry_interface = ctk.CTkEntry(master=interface_frame, width=200, height=30, text_color="white",
                                   textvariable=interface1, font=("Arial", 16, "bold"))
    entry_interface.place(relx=0.3, rely=0.7)

    ctk.CTkButton(master=interface_frame, text_color="white", text="Exit",
                  font=("Arial", 20, "bold"), command=exit_app).place(relx=0.7, rely=0.9)

    ctk.CTkButton(master=interface_frame, text_color="white", text="Select",
                  font=("Arial", 20, "bold"), command=select_interface).place(relx=0.8, rely=0.9)

def exit_app():
    os.system("sudo iptables -F INPUT")
    sys.exit()

def select_interface():
    selected_interface = interface1.get()
    messagebox.showinfo("Interface Selected", f"Selected: {selected_interface}")
    start_packet_monitor(selected_interface)

def start_packet_monitor(interface):
    global sniffing, packet_list_frame, warning_label

    for widget in root.winfo_children():
        widget.destroy()

    main_frame = ctk.CTkFrame(master=root, width=1920, height=1080)
    main_frame.pack(fill="both", expand=True, padx=10, pady=10)

    packet_list_frame = ctk.CTkScrollableFrame(
        master=main_frame, width=1900, height=700,
        label_text="Captured Packets", label_font=("Arial", 16, "bold"),
        border_width=5,border_color="white",corner_radius=15
    )
    packet_list_frame.pack(padx=10, pady=10)
    add_column_headers()

    ctk.CTkButton(master=main_frame, text="Start Capture",
                  font=("Arial", 16, "bold"), command=start_packet_capture).place(relx=0.1, rely=0.9, anchor="center")

    ctk.CTkButton(master=main_frame, text="Stop Capture",
                  font=("Arial", 16, "bold"), command=stop_packet_capture).place(relx=0.2, rely=0.9, anchor="center")

    ctk.CTkButton(master=main_frame, text="Show Graph",
                  font=("Arial", 16, "bold"), command=open_graph_window).place(relx=0.9, rely=0.9, anchor="center")

    blocked_ip_button = ctk.CTkButton(master=main_frame, text="Blocked IPs",
                                      font=("Arial", 16, "bold"), command=open_blocked_ip_window)
    blocked_ip_button.place(relx=0.8, rely=0.9, anchor="center")

    warning_label = ctk.CTkLabel(master=main_frame, text="", font=("Arial", 20, "bold"), text_color="red")
    warning_label.place(relx=0.5, rely=0.95, anchor="center")

    sniffing = False
    update_blocked_ips()  # Start IP update cycle

def add_column_headers():
    headers = ["Time", "Source", "Destination", "Protocol", "Length", "Details"]
    column_widths = [200, 300, 300, 150, 150, 450]

    for i, header in enumerate(headers):
        ctk.CTkLabel(master=packet_list_frame, text=header,
                     font=("Arial", 20, "bold"), text_color="white",
                     width=column_widths[i], anchor="center").grid(row=0, column=i, padx=5, pady=5, sticky="nsew")

def start_packet_capture():
    global sniffing
    sniffing = True
    threading.Thread(target=capture_packets, daemon=True).start()

def stop_packet_capture():
    global sniffing
    sniffing = False

def capture_packets():
    def process_packet(packet):
        if Ether in packet and IP in packet:
            timestamp = time.strftime("%H:%M:%S")
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet.sprintf("%IP.proto%")
            packet_length = len(packet)
            info = str(packet.summary())

            packet_count[src_ip] += 1
            incoming_packets[dst_ip] += 1

            if rf_model.predict([[packet_count[src_ip]]])[0] == 1:
                if src_ip not in blocked_ips:
                    block_ip(src_ip)
                    update_warning(f"🚨 Blocked attack from {src_ip}")
                    threading.Thread(target=send_email, args=(src_ip,), daemon=True).start()

            root.after(0, update_graph_data, time_counter, incoming_packets[dst_ip])
            root.after(0, add_packet_to_list, timestamp, src_ip, dst_ip, protocol, packet_length, info)

    sniff(iface=interface1.get(), prn=process_packet, stop_filter=lambda x: not sniffing)

def block_ip(ip):
    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
    blocked_ips.add(ip)

def update_graph_data(x, y):
    global x_data, incoming_graph
    x_data.append(x)
    incoming_graph.append(y)
    if len(x_data) > 60:
        x_data = x_data[-60:]
        incoming_graph = incoming_graph[-60:]

def add_packet_to_list(timestamp, src_ip, dst_ip, protocol, length, info):
    row = len(captured_packets) + 1
    data = [timestamp, src_ip, dst_ip, protocol, length, info]
    column_widths = [200, 300, 300, 150, 150, 450]

    for i, value in enumerate(data):
        ctk.CTkLabel(master=packet_list_frame, text=value,
                     font=("Arial", 16, "bold"), text_color="white",
                     width=column_widths[i], anchor="w", wraplength=column_widths[i]).grid(
            row=row, column=i, padx=5, pady=5, sticky="nsew")

    captured_packets.append(data)

def update_warning(msg):
    warning_label.configure(text=msg)
    root.after(10000, lambda: warning_label.configure(text=""))

def send_email(src_ip):
    sender = ""
    password = ""  # Add your app password here
    receiver = ""

    subject = "🚨 Network Attack Detected"
    body = f"""\
    Security Alert!

    Detected potential DoS attack from: {src_ip}
    Time: {time.strftime('%Y-%m-%d %H:%M:%S')}

    IP {src_ip} has been automatically blocked.
    """

    em = EmailMessage()
    em["From"] = sender
    em["To"] = receiver
    em["Subject"] = subject  # 'subject' should be capitalizeda
    em.set_content(body)

    context = ssl.create_default_context()  # Fixed typo in 'context'

    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as smtp:  # Fixed variable name
        smtp.login(sender, password)
        smtp.sendmail(sender, receiver, em.as_string())

def get_blocked_ips():
    result = os.popen("sudo iptables -L INPUT -n | grep DROP").read()
    ips = [line.split()[3] for line in result.split('\n') if "DROP" in line]
    return ips

def update_blocked_ips():
    current_blocked = set(get_blocked_ips())
    added = current_blocked - blocked_ips
    removed = blocked_ips - current_blocked

    blocked_ips.clear()
    blocked_ips.update(current_blocked)

    root.after(update_interval, update_blocked_ips)

def open_blocked_ip_window():
    blocked_window = ctk.CTkToplevel(root)
    blocked_window.title("Currently Blocked IPs")
    blocked_window.geometry("600x400")

    frame = ctk.CTkScrollableFrame(blocked_window, width=580, height=380)
    frame.pack(padx=10, pady=10)

    def refresh_list():
        for widget in frame.winfo_children():
            widget.destroy()
        ips = get_blocked_ips()
        for ip in ips:
            ctk.CTkLabel(frame, text=ip, font=("Arial", 14)).pack(pady=2)

    # Button frame for Refresh and Back
    button_frame = ctk.CTkFrame(blocked_window)
    button_frame.pack(pady=5)

    ctk.CTkButton(button_frame, text="Refresh", command=refresh_list).pack(side="left", padx=5)
    ctk.CTkButton(button_frame, text="Back", command=blocked_window.destroy).pack(side="left", padx=5)

    refresh_list()
    blocked_window.after(update_interval, refresh_list)

def open_graph_window():
    global graph_window

    if graph_window is None or not graph_window.winfo_exists():
        graph_window = ctk.CTkToplevel(root)
        graph_window.title("Network Traffic Monitor")
        graph_window.geometry("1000x600")

        canvas = FigureCanvasTkAgg(fig, master=graph_window)
        canvas.get_tk_widget().pack(fill="both", expand=1)

        # Back button for graph window
        back_button = ctk.CTkButton(graph_window, text="Back", command=graph_window.destroy)
        back_button.pack(side="bottom", pady=10)

        ani = animation.FuncAnimation(fig, animate_graph, interval=1000)
        canvas.draw()

def animate_graph(frame):
    line_in.set_data(range(len(x_data)), incoming_graph)
    ax.relim()
    ax.autoscale_view()
    return line_in,

# Initial setup
setup_login_page()
root.mainloop()