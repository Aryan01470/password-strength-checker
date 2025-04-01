import tkinter as tk
from tkinter import messagebox
import bcrypt
import math
import string

# Function to calculate password entropy
def calculate_entropy(password):
    length = len(password)
    character_set = 0

    if any(char.islower() for char in password):
        character_set += 26
    if any(char.isupper() for char in password):
        character_set += 26
    if any(char.isdigit() for char in password):
        character_set += 10
    if any(char in string.punctuation for char in password):
        character_set += len(string.punctuation)

    if character_set == 0:
        return 0

    return length * math.log2(character_set)

# Function to hash a password
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

# Function to verify a password against a hash
def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

# Function to process password input
def check_password_strength():
    password = entry_password.get()

    if not password:
        messagebox.showwarning("Input Error", "Please enter a password!")
        return

    # Calculate entropy
    entropy = calculate_entropy(password)

    if entropy < 40:
        strength = "🔴 Weak Password"
        color = "red"
    elif entropy < 60:
        strength = "🟠 Moderate Password"
        color = "orange"
    else:
        strength = "🟢 Strong Password"
        color = "green"

    label_entropy.config(text=f"Entropy: {entropy:.2f} bits", fg=color)
    label_strength.config(text=strength, fg=color)

    # Hash password
    hashed = hash_password(password)
    entry_hashed_password.delete(0, tk.END)
    entry_hashed_password.insert(0, hashed)

# Function to verify password
def verify_password():
    original_password = entry_password.get()
    hashed_password = entry_hashed_password.get()

    if not original_password or not hashed_password:
        messagebox.showwarning("Input Error", "Please enter both password and hashed password!")
        return

    if check_password(original_password, hashed_password):
        messagebox.showinfo("Success", "✅ Password Matched!")
    else:
        messagebox.showerror("Error", "❌ Password Mismatch!")

# Create the main window
root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("400x400")
root.configure(bg="#f4f4f4")

# Title Label
label_title = tk.Label(root, text="🔐 Password Strength Checker", font=("Arial", 14, "bold"), bg="#f4f4f4")
label_title.pack(pady=10)

# Password Entry
label_password = tk.Label(root, text="Enter Password:", font=("Arial", 12), bg="#f4f4f4")
label_password.pack()
entry_password = tk.Entry(root, show="*", width=30)
entry_password.pack()

# Check Strength Button
btn_check = tk.Button(root, text="Check Strength", command=check_password_strength, bg="#28a745", fg="white", font=("Arial", 12))
btn_check.pack(pady=10)

# Display Entropy
label_entropy = tk.Label(root, text="Entropy: N/A", font=("Arial", 12), bg="#f4f4f4")
label_entropy.pack()

# Display Strength
label_strength = tk.Label(root, text="Strength: N/A", font=("Arial", 12, "bold"), bg="#f4f4f4")
label_strength.pack()

# Hashed Password Label & Entry
label_hashed_password = tk.Label(root, text="Hashed Password:", font=("Arial", 12), bg="#f4f4f4")
label_hashed_password.pack()
entry_hashed_password = tk.Entry(root, width=40)
entry_hashed_password.pack()

# Verify Password Button
btn_verify = tk.Button(root, text="Verify Password", command=verify_password, bg="#007bff", fg="white", font=("Arial", 12))
btn_verify.pack(pady=10)

# Run the GUI
root.mainloop()
