import customtkinter# Ensure test.py is in the same directory or Python path
import sys
customtkinter.set_appearance_mode("dark")
root = customtkinter.CTk()
root.geometry("1600x800")
root.title("INTERFACE")

interface = customtkinter.StringVar(value="wlan0")
def main():
    pass
def interface_page():
    main_frame = customtkinter.CTkFrame(master=root, height=780, width=1580, fg_color="gray")
    main_frame.grid(row=0, column=0, padx=10, pady=10)

    title_frame = customtkinter.CTkFrame(master=main_frame, width=1560, height=100)
    title_frame.grid(row=0, column=0, padx=10, pady=10)

    interface_frame = customtkinter.CTkFrame(master=main_frame, width=1560, height=630)
    interface_frame.grid(row=1, column=0, padx=10, pady=10)

    title = customtkinter.CTkLabel(
        master=title_frame,
        text="       SELECT THE INTERFACE  ",
        text_color="white",
        font=("airel", 20, "bold")
    )
    title.place(relx=0.4, rely=0.1)

    interfaces = ["wlan0", "wlan1", "eth0", "enp0s3", "Ethernet", "Wi-Fi"]
    y_position = 0.1

    for iface in interfaces:
        customtkinter.CTkRadioButton(
            master=interface_frame,
            text_color="white",
            text=iface,
            font=("airel", 20, "bold"),
            variable=interface,
            value=iface
        ).place(relx=0.1, rely=y_position)
        y_position += 0.1

    entry_label = customtkinter.CTkLabel(
        master=interface_frame,
        text_color="white",
        text="Enter The Interface Name :",
        font=("airel", 20, "bold")
    )
    entry_label.place(relx=0.1, rely=0.7)

    entry_interface = customtkinter.CTkEntry(
        master=interface_frame,
        width=200,
        height=30,
        text_color="white",
        textvariable=interface,
        font=("airel", 16, "bold")
    )
    entry_interface.place(relx=0.3, rely=0.7)

    def back():
        sys.exit()

    back_button = customtkinter.CTkButton(
        master=interface_frame,
        text_color="white",
        text="Exit",
        font=("airel", 20, "bold"),
        command=back
    )
    back_button.place(relx=0.7, rely=0.9)

# Ensure `test.py` has a `monitor` function

    capture_button = customtkinter.CTkButton(
        master=interface_frame,
        text_color="white",
        text="Monitor",
        font=("airel", 20, "bold"),
        command=main()
    )
    capture_button.place(relx=0.8, rely=0.9)

interface_page()
root.mainloop()
