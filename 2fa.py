"""OTP Python app

Generated via generative AI: ChatGPT, Poe Claude+

Caution:
========
This script is intended solely for my personal testing environment.
It may not be sufficiently stable or secure for use in a serious production environment.

Use at your own risk.
"""

import base64
import hashlib
import json
import os
import sys
import time
import pyotp
from cryptography.fernet import Fernet, InvalidToken

import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from tkinter import simpledialog
from tkinter import ttk

# Define the ACCOUNTS_KV file path and encryption key
ENCRYPT_ACCOUNT_FILE = "encrypted_accounts.json"
RAW_DECRYPTED_ACCOUNT_FILE = "raw_decrypted_accounts.json"
ENCRYPTION_KEY_PASSWORD = b'It will be generated with generate_encrypt_key(your_password)'
ACCOUNTS_KV = {}

# Create the main application window
root = tk.Tk()
root.title("Authenticator OPT")


# Define the function to save the ACCOUNTS_KV to encrypted file
def save_accounts(account_kv):
    # Encrypt the ACCOUNTS_KV dictionary and save it to file
    f = Fernet(ENCRYPTION_KEY_PASSWORD)
    encrypted_secrets = f.encrypt(json.dumps(account_kv).encode())
    with open(ENCRYPT_ACCOUNT_FILE, "wb") as file:
        file.write(encrypted_secrets)


def copy_text(text):
    root.clipboard_clear()
    root.clipboard_append(text)
    messagebox.showinfo(
        "Copy OK", f"Copied:\n{root.clipboard_get()}")


def gen_encrypt_key(password):
    salt = b'saltvaluehere'
    kdf_iterations = 100_000
    key_length = 32
    # Generate a key using PBKDF2
    key = hashlib.pbkdf2_hmac(
        'sha256', password.encode(), salt, kdf_iterations, key_length)

    # Encode the key using base64
    encoded_key = base64.urlsafe_b64encode(key)
    return encoded_key


def load_account_kv():
    global ENCRYPTION_KEY_PASSWORD, ACCOUNTS_KV

    if not os.path.exists(ENCRYPT_ACCOUNT_FILE):
        while True:
            password = tk.simpledialog.askstring("SETUP NEW PASSWORD",
                                                 "If you forget this password.\nYou will lose your accounts FOREVER!\nEnter a new password:",
                                                 show='*')
            password_confirm = tk.simpledialog.askstring(
                "Confirm New Password", "Confirm new password:", show='*')
            if password == password_confirm:
                ENCRYPTION_KEY_PASSWORD = gen_encrypt_key(
                    password + "mindful")

                ACCOUNTS_KV = {}
                with open(ENCRYPT_ACCOUNT_FILE, 'w') as config_file:
                    config_file.write(Fernet(ENCRYPTION_KEY_PASSWORD).encrypt(
                        json.dumps(ACCOUNTS_KV).encode()).decode())
                messagebox.showinfo("No accounts found",
                                    f"Please add accounts manually or Import accounts")
                return ACCOUNTS_KV
            else:
                messagebox.showerror(
                    "Password Mismatch", "Passwords do not match. Please try again.")
    else:
        while True:
            password = tk.simpledialog.askstring("Enter password",
                                                 "Please enter password",
                                                 show='*')
            if password is None:
                raise SystemExit("User cancelled password prompt.")

            ENCRYPTION_KEY_PASSWORD = gen_encrypt_key(
                password + "mindful")

            with open(ENCRYPT_ACCOUNT_FILE, 'r') as config_file:
                encoded_config = config_file.read().encode()
                try:
                    decoded_config = Fernet(ENCRYPTION_KEY_PASSWORD).decrypt(
                        encoded_config).decode()
                    decoded_account_dict = json.loads(decoded_config)
                    account_keys = sorted(decoded_account_dict.keys())

                    ACCOUNTS_KV = {key: decoded_account_dict[key] for key in sorted(account_keys)}
                    return ACCOUNTS_KV

                except InvalidToken:
                    messagebox.showerror(
                        "Password Mismatch", "Passwords do not match. Please try again.")


def restart_app():
    python = sys.executable
    os.execl(python, python, *sys.argv)


def import_key():
    global ACCOUNTS_KV
    # Ask the user to select a raw ACCOUNTS_KV file
    file_path = tk.filedialog.askopenfilename(
        title="Select a raw ACCOUNTS_KV file")
    if not file_path:
        return

    # Load the raw ACCOUNTS_KV file
    with open(file_path, "r") as file:
        raw_secrets = json.load(file)

    for label, secret_key in raw_secrets.items():
        raw_secrets[label] = secret_key

    save_accounts(raw_secrets)
    messagebox.showinfo("The app will restart now",
                        f"It will try to restart the app. If failed please exit the app and restart it.")
    restart_app()


def export_key():
    global ACCOUNTS_KV
    # Save the ACCOUNTS_KV dictionary to file in JSON format
    with open(RAW_DECRYPTED_ACCOUNT_FILE, "w") as file:
        json.dump(ACCOUNTS_KV, file, indent=4)
        messagebox.showinfo("Export Success",
                            f"{RAW_DECRYPTED_ACCOUNT_FILE} is not encrypted. Delete it immediately after use!")


# Define the function to generate a new key and add it to the ACCOUNTS_KV
def add_account():
    global ACCOUNTS_KV
    # Ask the user for the account name and secret
    while True:
        key_name = tk.simpledialog.askstring(
            "Account name", "Enter account name:")
        if not key_name:
            # The user clicked Cancel or entered an empty string
            messagebox.showerror("Account name error",
                                 "The account name is empty.")
            return

        # Check if the account name already exists in the ACCOUNTS_KV
        if key_name in ACCOUNTS_KV:
            messagebox.showerror(
                "Account name", f"The account name '{key_name}' already exists.")
        else:
            # The account name is valid
            break

    while True:
        key_secret = tk.simpledialog.askstring(
            "Key secret", "Enter the key secret:")
        if not key_secret:
            # The user clicked Cancel or entered an empty string
            messagebox.showerror("Key secret error",
                                 "They key secret is empty.")
            return

        # Check if the key secret is a valid Base32 string
        try:
            # Encode the key as a bytes object
            key_bytes = key_secret.encode('utf-8')

            # Decode the key from base32 to bytes
            decoded_key_bytes = base64.b32decode(key_bytes)
            del decoded_key_bytes
        except Exception:
            messagebox.showerror(
                "Key secret", "Invalid key secret. Please enter a valid Base32 string.")
        else:
            # The key secret is valid
            break

    # Add the key to the ACCOUNTS_KV
    ACCOUNTS_KV[key_name] = key_secret
    save_accounts(ACCOUNTS_KV)

    # Show a message box to confirm the key has been added
    messagebox.showinfo(
        "New Key", f"The key '{key_name}' has been added successfully.")
    generate_codes()


# Define the function to remove a key from the ACCOUNTS_KV
def remove_account():
    global ACCOUNTS_KV
    # Ask the user for the account name to remove
    while True:
        key_name = tk.simpledialog.askstring(
            "Account name", "Enter account name to remove:")
        if not key_name:
            # The user clicked Cancel or entered an empty string
            messagebox.showerror("Account name error",
                                 "The account name is empty.")
            return

        # Check if the account name exists in the ACCOUNTS_KV
        if key_name not in ACCOUNTS_KV:
            messagebox.showerror(
                "Account name", f"The account name '{key_name}' does not exist.")
        else:
            # The account name is valid
            break

    # Remove the key from the ACCOUNTS_KV
    del ACCOUNTS_KV[key_name]
    save_accounts(ACCOUNTS_KV)

    # Show a message box to confirm the key has been removed
    messagebox.showinfo(
        "Remove Key", f"The key '{key_name}' has been removed successfully.")
    generate_codes()


# Define the function to rename a key in the ACCOUNTS_KV
def rename_account():
    global ACCOUNTS_KV
    # Ask the user for the account name to rename
    while True:
        old_key_name = tk.simpledialog.askstring(
            "Account name", "Enter account name to rename:")
        if not old_key_name:
            # The user clicked Cancel or entered an empty string
            messagebox.showerror("Account name error",
                                 "The account name is empty.")
            return

        # Check if the account name exists in the ACCOUNTS_KV
        if old_key_name not in ACCOUNTS_KV:
            messagebox.showerror(
                "Account name", f"The account name '{old_key_name}' does not exist.")
        else:
            # The account name is valid
            break

    # Ask the user for the new account name
    while True:
        new_key_name = tk.simpledialog.askstring(
            "New account name", "Enter the new account name:")
        if not new_key_name:
            # The user clicked Cancel or entered an empty string
            messagebox.showerror("Account name error",
                                 "The account name is empty.")
            return

        # Check if the new account name already exists in the ACCOUNTS_KV
        if new_key_name in ACCOUNTS_KV:
            messagebox.showerror(
                "New account name", f"The account name '{new_key_name}' already exists.")
        else:
            # The new account name is valid
            break

    # Rename the key in the ACCOUNTS_KV
    ACCOUNTS_KV[new_key_name] = ACCOUNTS_KV.pop(old_key_name)
    save_accounts(ACCOUNTS_KV)

    # Show a message box to confirm the key has been renamed
    messagebox.showinfo(
        "Rename Key", f"The key '{old_key_name}' has been renamed to '{new_key_name}' successfully.")
    generate_codes()


def update_account():
    global ACCOUNTS_KV
    # Ask the user for the account name to edit
    while True:
        key_name = tk.simpledialog.askstring(
            "Account name", "Enter account name to edit:")
        if not key_name:
            # The user clicked Cancel or entered an empty string
            messagebox.showerror("Account name error",
                                 "The account name is empty.")
            return

        # Check if the account name exists in the ACCOUNTS_KV
        if key_name not in ACCOUNTS_KV:
            messagebox.showerror(
                "Account name", f"The account name '{key_name}' does not exist.")
        else:
            # The account name is valid
            break

    # Ask the user for the new key secret
    while True:
        new_key_secret = tk.simpledialog.askstring(
            "New key secret", "Enter the new key secret:")
        if not new_key_secret:
            # The user clicked Cancel or entered an empty string
            messagebox.showerror("New key secret error",
                                 "The new key secret is empty.")
            return

        # Check if the new key secret is a valid Base32 string
        try:
            # Encode the key as a bytes object
            key_bytes = new_key_secret.encode('utf-8')

            # Decode the key from base32 to bytes
            decoded_key_bytes = base64.b32decode(key_bytes)
            del decoded_key_bytes
        except Exception:
            messagebox.showerror(
                "New key secret", "Invalid new key secret. Please enter a valid Base32 string.")
        else:
            # The new key secret is valid
            break

    # Update the key secret in the ACCOUNTS_KV
    ACCOUNTS_KV[key_name] = new_key_secret
    save_accounts(ACCOUNTS_KV)

    # Show a message box to confirm the key has been updated
    messagebox.showinfo(
        "Edit Key", f"The key '{key_name}' has been updated successfully.")
    generate_codes()


# Define the function to generate the codes for all keys

def generate_codes():
    # Clear the codes frame
    for widget in code_frame.winfo_children():
        widget.destroy()

    # Cancel the previous scheduled call, if any
    try:
        root.after_cancel(generate_codes.after_id)
    except AttributeError:
        pass

    # Loop through all the ACCOUNTS_KV and generate the codes
    refresh_button = tk.Button(
        code_frame, text="Refresh code now", command=generate_codes, background="green")
    refresh_button.pack()

    instruction_label = tk.Label(
        code_frame, text=f"There are {len(ACCOUNTS_KV)} accounts. It will auto refresh after 10s")
    instruction_label.pack(pady=10, padx=10)

    divider = ttk.Separator(code_frame, orient="horizontal")
    divider.pack(fill="x", pady=10)

    for key_name, key_secret in ACCOUNTS_KV.items():
        totp = pyotp.TOTP(key_secret)
        code = totp.now()
        seconds_left = totp.interval - int(time.time()) % totp.interval

        # Add copy label button
        copy_key_button = tk.Button(code_frame, text="Copy name",
                                    command=lambda this_keyname=key_name: copy_text(this_keyname))
        copy_key_button.pack()

        code_formatted = ' '.join(code[i:i + 3]
                                  for i in range(0, len(code), 3))
        label = tk.Label(
            code_frame, text=f"{key_name}: {code_formatted} (valid in: {seconds_left}s)")

        label.config(font=("Arial", 18))  # increase font size to 18
        label.pack()

        # Add copy code button
        copy_code_button = tk.Button(code_frame, text="Copy OTP code",
                                     command=lambda this_code=code: copy_text(this_code))
        copy_code_button.pack()

        divider = ttk.Separator(code_frame, orient="horizontal")
        divider.pack(fill="x", pady=10)

    refresh_button_end = tk.Button(
        code_frame, text="Refresh code now", command=generate_codes, background="green")
    refresh_button_end.pack()

    instruction_label_end = tk.Label(
        code_frame, text=f"There are {len(ACCOUNTS_KV)} accounts. It will auto refresh after 10s")
    instruction_label_end.pack(pady=10, padx=10)

    # Schedule a new call to the function and save the ID
    generate_codes.after_id = root.after(10000, generate_codes)


def main_app_init():
    global ACCOUNTS_KV
    load_account_kv()

    # Show the codes
    generate_codes()

    # Enable menus after successful password
    menu_bar.entryconfig("Add account", state="normal")
    menu_bar.entryconfig("Rename account", state="normal")
    menu_bar.entryconfig("Import accounts", state="normal")
    menu_bar.entryconfig("Update account", state="normal")
    menu_bar.entryconfig("CAREFUL", state="normal")
    # menu_bar.entryconfig("Remove account", state="normal")
    # menu_bar.entryconfig("Export accounts", state="normal")


# Set icon
# root.tk.call('wm', 'iconphoto', root._w, tk.PhotoImage(file='icon-512-maskable.png'))

root.geometry("800x600")

# This scrollbar (step 1-5) is adapted from this tut https://www.youtube.com/watch?v=0WafQCaok6g
# 1. Create a main frame
main_frame = tk.Frame(root)
main_frame.pack(fill=tk.BOTH, expand=1)

# 2. Create a canvas
code_canvas = tk.Canvas(main_frame)
code_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=1)

# 3. Add a Scrollbar to the canvas
code_scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=code_canvas.yview)
code_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# 4. Configure the canvas
code_canvas.configure(yscrollcommand=code_scrollbar.set)
code_canvas.bind('<Configure>', lambda e: code_canvas.configure(scrollregion=code_canvas.bbox("all")))

# 5. create another frame inside the canvas
code_frame = tk.Frame(code_canvas)
# add that new frame to a window in the canvas
code_canvas.create_window((0, 0), window=code_frame, anchor="nw")

# Create the menu bar
menu_bar = tk.Menu(root)
menu_bar.add_command(label="Exit", command=root.quit, background="red")
menu_bar.add_command(label="Add account",
                     command=add_account, state="disabled")
menu_bar.add_command(label="Rename account",
                     command=rename_account, state="disabled")
menu_bar.add_command(label="Update account",
                     command=update_account, state="disabled")
menu_bar.add_command(label="Import accounts",
                     command=import_key, state="disabled")

dangerous_menu = tk.Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="CAREFUL", menu=dangerous_menu, state="disabled")
dangerous_menu.add_command(label="Export accounts",
                           command=export_key)
dangerous_menu.add_separator()
dangerous_menu.add_command(label="Remove account",
                           command=remove_account)

root.config(menu=menu_bar)

# Call the function to ask for the password and show the codes
main_app_init()

# Start the main loop
root.mainloop()
