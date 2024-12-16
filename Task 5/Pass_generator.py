import tkinter as tk
from tkinter import messagebox
import string
import random

def generate_password():
    try:
        length = int(length_entry.get())
        if length < 4:
            messagebox.showerror("Error", "Password length should be at least 4 characters.")
            return

        characters = ""
        if upper_var.get():
            characters += string.ascii_uppercase
        if lower_var.get():
            characters += string.ascii_lowercase
        if number_var.get():
            characters += string.digits
        if special_var.get():
            characters += string.punctuation

        if not characters:
            messagebox.showerror("Error", "Select at least one character set.")
            return

        password = "".join(random.choice(characters) for _ in range(length))
        password_entry.delete(0, tk.END)
        password_entry.insert(0, password)
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid number for password length.")

def copy_to_clipboard():
    password = password_entry.get()
    if password:
        root.clipboard_clear()
        root.clipboard_append(password)
        root.update()
        messagebox.showinfo("Success", "Password copied to clipboard.")
    else:
        messagebox.showwarning("Warning", "No password to copy.")

# Initialize the main window
root = tk.Tk()
root.title("Password Generator")
root.geometry("700x500")
root.resizable(False, False)

# Title Label
title_label = tk.Label(root, text="Password Generator", font=("Helvetica", 16, "bold"))
title_label.pack(pady=10)

# Password length frame
length_frame = tk.Frame(root)
length_frame.pack(pady=10)

length_label = tk.Label(length_frame, text="Password Length:")
length_label.pack(side=tk.LEFT, padx=5)

length_entry = tk.Entry(length_frame, width=5)
length_entry.pack(side=tk.LEFT)

# Options frame
options_frame = tk.LabelFrame(root, text="Character Options", padx=10, pady=10)
options_frame.pack(pady=10, fill="x")

upper_var = tk.BooleanVar()
lower_var = tk.BooleanVar()
number_var = tk.BooleanVar()
special_var = tk.BooleanVar()

upper_check = tk.Checkbutton(options_frame, text="Include Uppercase", variable=upper_var)
upper_check.pack(anchor="w")

lower_check = tk.Checkbutton(options_frame, text="Include Lowercase", variable=lower_var)
lower_check.pack(anchor="w")

number_check = tk.Checkbutton(options_frame, text="Include Numbers", variable=number_var)
number_check.pack(anchor="w")

special_check = tk.Checkbutton(options_frame, text="Include Special Characters", variable=special_var)
special_check.pack(anchor="w")

# Password display frame
password_frame = tk.Frame(root)
password_frame.pack(pady=10)

password_label = tk.Label(password_frame, text="Generated Password:")
password_label.pack(side=tk.LEFT, padx=5)

password_entry = tk.Entry(password_frame, width=25)
password_entry.pack(side=tk.LEFT)

copy_button = tk.Button(password_frame, text="Copy", command=copy_to_clipboard)
copy_button.pack(side=tk.LEFT, padx=5)

# Generate button
generate_button = tk.Button(root, text="Generate Password", command=generate_password, bg="blue", fg="white")
generate_button.pack(pady=10)

# Run the main loop
root.mainloop()

        
