import customtkinter
from PIL import Image, ImageTk
from tkinter import messagebox
import hashlib
root = customtkinter.CTk()
root.title("Login")
root.geometry("1200x800")
customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("blue")
def login():
    username=username_entry.get()
    user_password=password_entry.get()
    password="admin"
    hashed_password=hashlib.sha224(user_password.encode('utf-8')).hexdigest()
    plain_text_password=hashlib.sha224(password.encode('Utf-8')).hexdigest()
    if username == "admin" and plain_text_password== hashed_password:
        return
    else:
        messagebox.showwarning("Warning","Invalied username and password ")
main_frame = customtkinter.CTkFrame(master=root, width=1180, height=780)
main_frame.grid(row=0, column=0, padx=10, pady=10)
user_image = Image.open("images/user.png")
user_image = user_image.resize((100, 100))
login_image=Image.open("images/login.png")
login_image=login_image.resize((50,50))
tk_user_image = ImageTk.PhotoImage(user_image)
tk_login_image=ImageTk.PhotoImage(login_image)
image_label = customtkinter.CTkLabel(master=main_frame, image=tk_user_image, text="",corner_radius=7)
image_label.place(relx=0.5, rely=0.3, anchor="center")

admin_label=customtkinter.CTkLabel(master=main_frame,text="SIGN IN",text_color="white",
                                   font=("airel",16,"bold"))
admin_label.place(relx=0.5,rely=0.4,anchor="center")

username_entry=customtkinter.CTkEntry(master=main_frame,width=300,height=40,placeholder_text="Username",corner_radius=15)

username_entry.place(relx=0.5,rely=0.5,anchor="center")
password_entry=customtkinter.CTkEntry(master=main_frame,width=300,height=40,placeholder_text="Password",corner_radius=15,show="*")
password_entry.place(relx=0.5,rely=0.6,anchor="center")
login_button=customtkinter.CTkButton(master=main_frame,image=tk_login_image,width=200,height=5,text="",command=login)
login_button.place(relx=0.5,rely=0.7,anchor="center")
image_label.image = tk_user_image


root.mainloop()