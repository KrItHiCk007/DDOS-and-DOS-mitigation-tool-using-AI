import customtkinter as ctk
from scapy.all import sniff, Ether, IP, TCP, UDP
import threading
import time



ctk.set_appearance_mode("dark")  # Black theme
ctk.set_default_color_theme("dark-blue")  # Dark blue accent

class PacketAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("MONITOR")
        self.root.geometry("1920x1080")

        # Main Frames
        self.main_frame = ctk.CTkFrame(master=root, width=1920, height=1080, fg_color="black")
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)


        self.packet_list_frame = ctk.CTkScrollableFrame(
            master=self.main_frame,
            width=1900,
            height=800,
            label_text="Captured Packets",
            label_font=("Arial", 16, "bold"),
            fg_color="black",
            border_width=5
        )
        self.packet_list_frame.pack(padx=10, pady=10)


        self.add_column_headers()


        self.start_button = ctk.CTkButton(
            master=self.main_frame,
            text="Start Capture",
            font=("Arial", 16, "bold"),
            command=self.start_packet_capture
        )
        self.start_button.pack(padx=10, pady=10)

        self.stop_button = ctk.CTkButton(
            master=self.main_frame,
            text="Stop Capture",
            font=("Arial", 16, "bold"),
            command=self.stop_packet_capture
        )
        self.stop_button.pack(padx=10, pady=10)


        self.sniffing = False
        self.captured_packets = []

    def add_column_headers(self):

        headers = ["Time", "Source", "Destination", "Protocol", "MAC", "Details"]
        column_widths = [200, 300, 300, 150, 300, 550]

        for i, header in enumerate(headers):
            label = ctk.CTkLabel(
                master=self.packet_list_frame,
                text=header,
                font=("Arial", 20, "bold"),
                text_color="white",
                width=column_widths[i],
                anchor="center"
            )
            label.grid(row=0, column=i, padx=5, pady=5, sticky="nsew")

    def start_packet_capture(self):

        self.sniffing = True
        self.capture_thread = threading.Thread(target=self.capture_packets)
        self.capture_thread.start()

    def stop_packet_capture(self):

        self.sniffing = False

    def capture_packets(self):

        def process_packet(packet):
            if Ether in packet:
                timestamp = time.strftime("%H:%M:%S", time.localtime())
                src_ip = packet[IP].src if IP in packet else "N/A"
                dst_ip = packet[IP].dst if IP in packet else "N/A"
                protocol = packet.sprintf("%IP.proto%") if IP in packet else "N/A"
                mac_addr = packet[Ether].src
                info = str(packet.summary())


                self.add_packet_to_list(timestamp, src_ip, dst_ip, protocol, mac_addr, info)
                self.captured_packets.append(packet)

        sniff(iface="wlo1",prn=process_packet, stop_filter=lambda x: not self.sniffing)

    def add_packet_to_list(self, timestamp, src_ip, dst_ip, protocol, mac_addr, info):

        row = len(self.captured_packets) + 1
        data = [timestamp, src_ip, dst_ip, protocol, mac_addr, info]
        column_widths = [200, 300, 300, 150, 300, 550]

        for i, value in enumerate(data):
            label = ctk.CTkLabel(
                master=self.packet_list_frame,
                text=value,
                font=("Arial", 16, "bold"),
                text_color="white",
                width=column_widths[i],
                anchor="w",
                wraplength=column_widths[i]
            )
            label.grid(row=row, column=i, padx=5, pady=5, sticky="nsew")


root = ctk.CTk()
app = PacketAnalyzerApp(root)
root.mainloop()
