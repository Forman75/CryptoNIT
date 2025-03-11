import customtkinter as ctk
from tkinter import filedialog, messagebox, END, simpledialog
from Crypto.Cipher import AES, PKCS1_OAEP, ChaCha20
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import base64
import qrcode
import cv2
import pickle
import logging
import time
import os
import hashlib
import threading
import hmac
from icon_base64 import icon_data

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

USER_DATA_FILE = "users.pickle"

aes_mode = "EAX"
chacha_new_nonce_each_time = True

KEY_STORE_FILE = "key_store.pickle"

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

class LimitedToplevel(ctk.CTkToplevel):
    open_window_count = 0
    MAX_WINDOWS = 4

    def __init__(self, *args, **kwargs):
        if LimitedToplevel.open_window_count >= LimitedToplevel.MAX_WINDOWS:
            messagebox.showerror("Error", f"Only {LimitedToplevel.MAX_WINDOWS} windows can be opened!")
            return

        super().__init__(*args, **kwargs)
        LimitedToplevel.open_window_count += 1

        self.attributes("-topmost", True)

        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        LimitedToplevel.open_window_count -= 1
        self.destroy()

icon_bytes = base64.b64decode(icon_data)
with open("temp_icon.ico", "wb") as temp_icon:
    temp_icon.write(icon_bytes)
root = ctk.CTk()
root.iconbitmap("temp_icon.ico")
root.title("CryptoNIT")
root.geometry("1050x500")

def set_status(message, duration=5000):
    status_label.configure(text=message)
    if duration:
        root.after(duration, lambda: status_label.configure(text=""))


def validate_key(key, algo):
    try:
        data = base64.b64decode(key)
    except:
        return False
    if algo == "AES":
        return len(data) == 32
    elif algo == "RSA":
        try:
            RSA.import_key(data)
            return True
        except:
            return False
    elif algo == "ChaCha20":
        return len(data) == 32+12
    return False

def generate_random_key():
    algo = algorithm_var.get()
    password = simpledialog.askstring("Protection", "Enter the password to encrypt the key:", show='*')

    if not password:
        messagebox.showwarning("Error", "The password has not been entered! The key will not be encrypted.")
        return

    if algo == "AES":
        key = base64.b64encode(get_random_bytes(32)).decode()
    elif algo == "ChaCha20":
        key_bytes = get_random_bytes(32)
        nonce_bytes = get_random_bytes(12) if chacha_new_nonce_each_time else b"\x00" * 12
        key = base64.b64encode(key_bytes + nonce_bytes).decode()
    elif algo == "RSA":
        rsa_key = RSA.generate(2048)
        private_key = base64.b64encode(rsa_key.export_key(format="DER")).decode()
        public_key = base64.b64encode(rsa_key.publickey().export_key(format="DER")).decode()

        with open("public_key.pem", "w") as f:
            f.write(public_key)

        set_status("The public key is saved to a public_key.pem")

        key = private_key

    encrypted_key = encrypt_key(key, password)

    entry_key.delete(0, ctk.END)
    entry_key.insert(0, encrypted_key)

    set_status(f"The key for {algo} is generated and encrypted.")
    messagebox.showinfo("Key generation", f"The key for {algo} is encrypted and inserted in the field.")

def decrypt_key_from_entry():
    encrypted_key = entry_key.get()
    if not encrypted_key:
        messagebox.showwarning("Error", "The key field is empty!")
        return

    password = simpledialog.askstring("Enter the password", "Enter the password to decrypt the key:", show='*')
    if not password:
        messagebox.showwarning("Error", "The password has not been entered!")
        return

    decrypted_key = decrypt_key(encrypted_key, password)
    if decrypted_key:
        entry_key.delete(0, ctk.END)
        entry_key.insert(0, decrypted_key)
        set_status("The key has been successfully decrypted.")

        threading.Thread(target=clear_entry_after_delay, daemon=True).start()

def clear_entry_after_delay():
    time.sleep(30)
    entry_key.delete(0, ctk.END)
    set_status("The private key has been deleted from memory.")

def load_public_key_from_file():
    file_path = filedialog.askopenfilename(
        title="Select the file with the public key",
        filetypes=[("Public Key", "*.pem"), ("All Files", "*.*")]
    )
    if file_path:
        try:
            with open(file_path, "r") as f:
                public_key_data = f.read().strip()

            try:
                rsa_key = RSA.import_key(base64.b64decode(public_key_data))
            except ValueError:
                messagebox.showerror("Error", "The file does not contain a valid RSA public key.")
                return

            entry_key.delete(0, ctk.END)
            entry_key.insert(0, public_key_data)
            set_status(f"The public key is downloaded from the {file_path}")

        except Exception as e:
            messagebox.showerror("Error", f"Couldn't upload the key: {str(e)}")

def generate_qr_code():
    algo = algorithm_var.get()
    if algo == "RSA":
        messagebox.showerror("Error", "The creation of QR codes for RSA is not supported.")
        return

    key = entry_key.get()
    if not key:
        messagebox.showerror("Error", "The key was not found to create a QR code.")
        return

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(key)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')

    file_path = filedialog.asksaveasfilename(
        defaultextension=".png",
        filetypes=[("PNG Image", "*.png")],
        title="Save the QR code as"
    )
    if file_path:
        img.save(file_path)
        set_status(f"QR code saved: {file_path}")


def scan_qr_code_from_file():
    algo = algorithm_var.get()
    if algo == "RSA":
        messagebox.showerror("Error", "QR code scanning for RSA is not supported.")
        return

    file_path = filedialog.askopenfilename(
        title="Select the QR code file",
        filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")]
    )
    if file_path:
        img = cv2.imread(file_path)
        detector = cv2.QRCodeDetector()
        data, _, _ = detector.detectAndDecode(img)
        if data and isinstance(data, str):
            entry_key.delete(0, ctk.END)
            entry_key.insert(0, data)
            set_status("The key was successfully read from the QR code")
        else:
            messagebox.showerror("Error", "The QR code is not recognized or is empty.")


def clear_key_field():
    entry_key.delete(0, ctk.END)
    set_status("The key field has been cleared.")

def encrypt_key(key, password):
    salt = os.urandom(16)
    password_hash = PBKDF2(password, salt, dkLen=32, count=100000)

    cipher = AES.new(password_hash, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(key.encode())

    return base64.b64encode(salt + cipher.nonce + tag + ciphertext).decode()

def decrypt_key(encrypted_key, password):
    try:
        data = base64.b64decode(encrypted_key)
        salt, nonce, tag, ciphertext = data[:16], data[16:32], data[32:48], data[48:]

        password_hash = PBKDF2(password, salt, dkLen=32, count=100000)

        cipher = AES.new(password_hash, AES.MODE_EAX, nonce=nonce)
        decrypted_key = cipher.decrypt_and_verify(ciphertext, tag).decode()

        try:
            rsa_key = RSA.import_key(base64.b64decode(decrypted_key))
            decrypted_key = base64.b64encode(rsa_key.export_key(format="DER")).decode()
        except ValueError:
            pass

        return decrypted_key

    except Exception:
        messagebox.showerror("Error", "Incorrect password or corrupted key!")
        return None

def encrypt_text_aes(text, key, mode):
    data = base64.b64decode(key)
    if mode == "EAX":
        cipher = AES.new(data, AES.MODE_EAX)
    else:
        cipher = AES.new(data, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()


def decrypt_text_aes(encrypted_text, key, mode):
    data = base64.b64decode(encrypted_text)
    if mode == "EAX":
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    elif mode == "GCM":
        nonce, tag, ciphertext = data[:16], data[16:16 + AES.block_size], data[16 + AES.block_size:]
    k = base64.b64decode(key)
    if mode == "EAX":
        cipher = AES.new(k, AES.MODE_EAX, nonce=nonce)
    else:
        cipher = AES.new(k, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()


def encrypt_text_rsa(text, key):
    try:
        rsa_key = RSA.import_key(base64.b64decode(key))

        if rsa_key.has_private():
            messagebox.showerror("Error", "It cannot be encrypted using a private key!")
            return None

        cipher = PKCS1_OAEP.new(rsa_key)
        ciphertext = cipher.encrypt(text.encode())

        return base64.b64encode(ciphertext).decode()

    except ValueError:
        messagebox.showerror("Error", "Invalid public key!")
        return None
    except Exception as e:
        messagebox.showerror("Error", f"Encryption error: {str(e)}")
        return None

def decrypt_text_rsa(encrypted_text, key):
    rsa_key = RSA.import_key(base64.b64decode(key))
    cipher = PKCS1_OAEP.new(rsa_key)
    ciphertext = base64.b64decode(encrypted_text)
    decrypted = cipher.decrypt(ciphertext)
    return decrypted.decode()


def encrypt_text_chacha20(text, key):
    data = base64.b64decode(key)
    if len(data) != 32 + 12:
        raise ValueError("Incorrect key length for ChaCha20")
    chacha_key, chacha_nonce = data[:32], data[32:]
    cipher = ChaCha20.new(key=chacha_key, nonce=chacha_nonce)
    ciphertext = cipher.encrypt(text.encode())
    return base64.b64encode(ciphertext).decode()


def decrypt_text_chacha20(encrypted_text, key):
    data = base64.b64decode(key)
    chacha_key = data[:32]
    chacha_nonce = data[32:]
    ciphertext = base64.b64decode(encrypted_text)
    cipher = ChaCha20.new(key=chacha_key, nonce=chacha_nonce)
    decrypted = cipher.decrypt(ciphertext)
    return decrypted.decode()


def perform_with_progress(func):
    progress_bar.set(0)
    set_status("Processing...")
    root.update_idletasks()
    result = func()
    for i in range(0, 101, 20):
        time.sleep(0.05)
        progress_bar.set(i/100)
        root.update_idletasks()
    progress_bar.set(1.0)
    set_status("The operation is completed.")
    return result


def display_result(text):
    MAX_LENGTH = 100
    if len(text) > MAX_LENGTH:
        open_text_editor(initial_text=text, read_only=True, show_copy_button=True)
    else:
        entry_result.delete(0, ctk.END)
        entry_result.insert(0, text)


def handle_encrypt_text():
    text = entry_text.get()
    key = entry_key.get()
    algo = algorithm_var.get()

    if not text:
        messagebox.showerror("Error", "Enter the text to encrypt!")
        return

    if not key:
        messagebox.showerror("Error", "Enter or upload the key!")
        return

    if algo == "RSA":
        encrypted = encrypt_text_rsa(text, key)
    elif algo == "AES":
        encrypted = encrypt_text_aes(text, key, aes_mode)
    elif algo == "ChaCha20":
        encrypted = encrypt_text_chacha20(text, key)
    else:
        messagebox.showerror("Error", "Unknown algorithm!")
        return

    if encrypted:
        display_result(encrypted)
        set_status("The text has been successfully encrypted.")


    def encrypt_func():
        if algo == "AES":
            return encrypt_text_aes(text, key, aes_mode)
        elif algo == "RSA":
            return encrypt_text_rsa(text, key)
        elif algo == "ChaCha20":
            return encrypt_text_chacha20(text, key)

    encrypted = perform_with_progress(encrypt_func)
    if encrypted:
        display_result(encrypted)


def handle_decrypt_text():

    text = entry_text.get()
    key = entry_key.get()
    algo = algorithm_var.get()

    if not validate_key(key, algo):
        messagebox.showerror("Error", "Incorrect key format for the selected algorithm.")
        set_status("Error: Invalid key.")
        return

    def decrypt_func():
        if algo == "AES":
            return decrypt_text_aes(text, key, aes_mode)
        elif algo == "RSA":
            return decrypt_text_rsa(text, key)
        elif algo == "ChaCha20":
            return decrypt_text_chacha20(text, key)

    decrypted = perform_with_progress(decrypt_func)
    if decrypted:
        display_result(decrypted)


def copy_to_clipboard(text):
    root.clipboard_clear()
    root.clipboard_append(text)
    set_status("The text is copied to the clipboard.")


def paste_from_clipboard(entry):
    entry.delete(0, ctk.END)
    try:
        clipboard_content = root.clipboard_get()
        entry.insert(0, clipboard_content)
        set_status("The text is pasted from the clipboard.")
    except Exception:
        set_status("Error: the clipboard is empty or unavailable.")
    set_status("The text is pasted from the clipboard.")


def open_search_replace_window(editor_textbox):
    sr_window = LimitedToplevel(root)
    sr_window.title("Search and Replace")

    ctk.CTkLabel(sr_window, text="Search:").grid(row=0, column=0, padx=5, pady=5)
    search_entry = ctk.CTkEntry(sr_window, width=200)
    search_entry.grid(row=0, column=1, padx=5, pady=5)

    ctk.CTkLabel(sr_window, text="Replace with:").grid(row=1, column=0, padx=5, pady=5)
    replace_entry = ctk.CTkEntry(sr_window, width=200)
    replace_entry.grid(row=1, column=1, padx=5, pady=5)

    def replace_all():
        search_text = search_entry.get()
        replace_text = replace_entry.get()
        if search_text:
            content = editor_textbox.get("1.0", "end-1c")
            new_content = content.replace(search_text, replace_text)
            editor_textbox.delete("1.0", "end")
            editor_textbox.insert("1.0", new_content)
            set_status("Replacement completed.")

    btn_replace_all = ctk.CTkButton(sr_window, text="Replace all", command=replace_all)
    btn_replace_all.grid(row=2, column=0, columnspan=2, padx=5, pady=5)


def open_text_editor(initial_text=None, read_only=False, show_copy_button=False):
    editor_window = LimitedToplevel(root)
    editor_window.title("Built-in text editor")

    editor_textbox = ctk.CTkTextbox(editor_window, width=600, height=400)
    editor_textbox.pack(padx=10, pady=10, fill="both", expand=True)

    char_count_label = ctk.CTkLabel(editor_window, text="Number of characters: 0")
    char_count_label.pack(padx=10, pady=5)

    if initial_text:
        editor_textbox.insert("1.0", initial_text)

    if read_only:
        editor_textbox.configure(state="disabled")

    def update_char_count(_event=None):
        content = editor_textbox.get("1.0", "end-1c")
        char_count_label.configure(text=f"Number of characters: {len(content)}")

    editor_textbox.bind("<<Modified>>", lambda e: (editor_textbox.tk.call(editor_textbox._textbox._w, "edit", "modified", 0), update_char_count()))
    update_char_count()

    def paste_from_clipboard():
        clipboard_text = root.clipboard_get()
        editor_textbox.insert("insert", clipboard_text)
        set_status("The text is pasted from the clipboard.")

    if not read_only:
        btn_paste_text = ctk.CTkButton(editor_window, text="Paste", command=paste_from_clipboard)
        btn_paste_text.pack(padx=10, pady=10)

        btn_search_replace = ctk.CTkButton(editor_window, text="Search and Replace",
                                           command=lambda: open_search_replace_window(editor_textbox))
        btn_search_replace.pack(padx=5, pady=5)

        def insert_editor_content():
            content = editor_textbox.get("1.0", "end-1c")
            entry_text.delete(0, ctk.END)
            entry_text.insert(0, content)
            set_status("The text from the editor has been transferred to the main field.")

        btn_insert_content = ctk.CTkButton(editor_window, text="Send the text in the input field", command=insert_editor_content)
        btn_insert_content.pack(padx=10, pady=10)

    if show_copy_button or read_only:
        def copy_editor_content():
            content = editor_textbox.get("1.0", "end-1c")
            copy_to_clipboard(content)

        btn_copy_text = ctk.CTkButton(editor_window, text="Copy Text", command=copy_editor_content)
        btn_copy_text.pack(padx=5, pady=5)

def show_encryption_settings():
    settings_window = LimitedToplevel(root)
    settings_window.title("Encryption Settings")

    ctk.CTkLabel(settings_window, text="AES Mode:").grid(row=0, column=0, padx=10, pady=10)
    aes_mode_var = ctk.StringVar(value=aes_mode)
    aes_option = ctk.CTkOptionMenu(settings_window, values=["EAX", "GCM"], variable=aes_mode_var)
    aes_option.grid(row=0, column=1, padx=10, pady=10)

    chacha_nonce_var = ctk.BooleanVar(value=chacha_new_nonce_each_time)
    chacha_checkbox = ctk.CTkCheckBox(settings_window, text="Generate a new nonce for ChaCha20",
                                      variable=chacha_nonce_var)
    chacha_checkbox.grid(row=1, column=0, columnspan=2, padx=10, pady=10)

    def apply_settings():
        global aes_mode, chacha_new_nonce_each_time
        aes_mode = aes_mode_var.get()
        chacha_new_nonce_each_time = chacha_nonce_var.get()
        set_status("The encryption settings are applied.")
        settings_window.destroy()

    btn_apply = ctk.CTkButton(settings_window, text="Применить", command=apply_settings)
    btn_apply.grid(row=2, column=0, columnspan=2, padx=10, pady=10)


def show_help():
    help_window = LimitedToplevel(root)
    help_window.title("FAQ")

    help_text = (
        "Welcome to Cryptonite, a Cryptographic Native Information Transformer!\n\n"
        "In this program, you can:\n"
        "- Enter the text, select an algorithm (AES, RSA, ChaCha20) and perform encryption or decryption.\n"
        "- Generate keys, manage them through encrypted storage with a master password.\n"
        "- Use QR codes for quick key transfer (except RSA).\n"
        "- Use the built-in text editor to work with long messages.\n"
        "- Configure encryption settings (AES mode, nonce for ChaCha20).\n\n"
        "For detailed information on specific functions, click on the 'ℹ' icon next to the interface elements.\n\n\n"
        "Program Developer: Forman75 (https://github.com/Forman75)\n"
    )

    help_label = ctk.CTkLabel(help_window, text=help_text, justify="left")
    help_label.pack(padx=20, pady=20)


def export_rsa_public_key():
    key = entry_key.get()
    if not validate_key(key, "RSA"):
        messagebox.showerror("Error", "Invalid RSA key.")
        return
    rsa_key = RSA.import_key(base64.b64decode(key))
    pub_key = rsa_key.publickey().export_key()
    file_path = filedialog.asksaveasfilename(defaultextension=".pub", filetypes=[("Public Key", "*.pub")])
    if file_path:
        with open(file_path, "wb") as f:
            f.write(pub_key)
        set_status(f"The public key is saved in {file_path}")


def derive_key_from_master_password(master_password: str, salt=b"static_salt"):
    return hashlib.pbkdf2_hmac("sha256", master_password.encode("utf-8"), salt, 100000)


def encrypt_key_store(keys: dict, master_key: bytes):
    cipher = AES.new(master_key, AES.MODE_EAX)
    data = pickle.dumps(keys)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    mac = hmac.new(master_key, ciphertext, hashlib.sha256).digest()

    return cipher.nonce + tag + mac + ciphertext


def decrypt_key_store(data: bytes, master_key: bytes):
    try:
        nonce, tag, mac, ciphertext = data[:16], data[16:32], data[32:64], data[64:]

        expected_mac = hmac.new(master_key, ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("The storage file has been changed!")

        cipher = AES.new(master_key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        return pickle.loads(plaintext)

    except ValueError as e:
        messagebox.showerror("Error", str(e))
        return None

def load_key_store(master_password: str):
    if not os.path.exists(KEY_STORE_FILE):
        return {}

    try:
        with open(KEY_STORE_FILE, "rb") as f:
            encrypted_data = f.read()

        master_key = derive_key_from_master_password(master_password)
        keys = decrypt_key_store(encrypted_data, master_key)

        decrypted_keys = {name: decrypt_key(value, master_password) for name, value in keys.items()}

        return decrypted_keys

    except ValueError:
        messagebox.showerror("Error", "Incorrect master password or corrupted keystore.")
        return None

    except FileNotFoundError:
        messagebox.showerror("Error", "The storage file was not found.")
        return None

    except Exception as e:
        messagebox.showerror("Error", f"Failed to load storage: {str(e)}")
        return None

def save_key_store(keys: dict, master_password: str):
    master_key = derive_key_from_master_password(master_password)

    encrypted_keys = {name: encrypt_key(value, master_password) for name, value in keys.items()}

    encrypted_data = encrypt_key_store(encrypted_keys, master_key)
    with open(KEY_STORE_FILE, "wb") as f:
        f.write(encrypted_data)


def open_key_store():
    master_password = simpledialog.askstring("Master password", "Enter the master password for the vaults:")
    if master_password is None:
        return
    keys = load_key_store(master_password)
    if keys is None:
        messagebox.showerror("Error", "Incorrect master password or corrupted storage.")
        return

    store_window = LimitedToplevel(root)
    store_window.title("Key Storage")

    ctk.CTkLabel(store_window, text="Select the key to download:").pack(padx=10, pady=10)

    if len(keys) == 0:
        ctk.CTkLabel(store_window, text="The storage is empty.").pack(padx=10, pady=10)
        return

    key_names = list(keys.keys())
    selected_key_var = ctk.StringVar(value=key_names[0])
    key_dropdown = ctk.CTkOptionMenu(store_window, values=key_names, variable=selected_key_var)
    key_dropdown.pack(padx=10, pady=10)

    def load_selected_key():
        selected = selected_key_var.get()
        if selected in keys:
            entry_key.delete(0, END)
            entry_key.insert(0, keys[selected])
            set_status(f"Key '{selected}' is loaded from storage.")
        else:
            messagebox.showerror("Error", "Select the correct key name.")

    btn_load = ctk.CTkButton(store_window, text="Upload the key", command=load_selected_key)
    btn_load.pack(pady=10)

def save_key_to_store():
    master_password = simpledialog.askstring("Master password", "Enter the master password for the storage:")
    if master_password is None:
        return
    keys = load_key_store(master_password)
    if keys is None:
        keys = {}
    key = entry_key.get()
    if not key:
        messagebox.showerror("Error", "There is no key to save to the storage.")
        return
    name = simpledialog.askstring("Key name", "Enter a name for the key you want to save:")
    if name is None or not name.strip():
        return
    keys[name.strip()] = key
    save_key_store(keys, master_password)
    set_status(f"Key '{name}' is stored in the vault.")


def show_info_window(title, text):
    info_win = LimitedToplevel(root)
    info_win.title(title)
    label = ctk.CTkLabel(info_win, text=text, justify="left")
    label.pack(padx=20, pady=20)


def create_info_button(parent, row, column, title, text):
    btn_help_icon = ctk.CTkButton(parent, text="ℹ", width=20, command=lambda: show_info_window(title, text))
    btn_help_icon.grid(row=row, column=column, padx=5)


footer_frame = ctk.CTkFrame(root)
footer_frame.pack(side="bottom", fill="x")
status_label = ctk.CTkLabel(footer_frame, text="", font=("Arial", 10))
status_label.pack(side="left", padx=10)

main_frame = ctk.CTkFrame(root)
main_frame.pack(pady=20, padx=20)

ctk.CTkLabel(main_frame, text="Enter the text:").grid(row=0, column=0, padx=10, pady=10)
entry_text = ctk.CTkEntry(main_frame, width=300)
entry_text.grid(row=0, column=1, padx=10, pady=10)

algorithm_var = ctk.StringVar(value="AES")
algorithm_dropdown = ctk.CTkOptionMenu(main_frame, values=["AES", "RSA", "ChaCha20"], variable=algorithm_var)
algorithm_dropdown.grid(row=0, column=2, padx=10, pady=10)

create_info_button(
    main_frame, 0, 3, "Choosing an algorithm",
    "Algorithms:\n"
    "- AES: Symmetric single-key block cipher.\n"
    "- RSA: an asymmetric cipher with public and private keys.\n"
    "- ChaCha20: Symmetric stream cipher.\n\n"
    "Select an algorithm, then enter or generate a key to encrypt or decrypt the text."
)

btn_copy_text = ctk.CTkButton(main_frame, text="Copy Text", command=lambda: copy_to_clipboard(entry_text.get()))
btn_copy_text.grid(row=0, column=4, padx=5, pady=5)

ctk.CTkLabel(main_frame, text="Enter the key:").grid(row=1, column=0, padx=10, pady=10)
entry_key = ctk.CTkEntry(main_frame, width=300)
entry_key.grid(row=1, column=1, padx=10, pady=10)

btn_generate_key = ctk.CTkButton(main_frame, text="Generate a key", command=generate_random_key)
btn_generate_key.grid(row=1, column=2, padx=10, pady=10)

btn_paste_key = ctk.CTkButton(main_frame, text="Insert a key", command=lambda: paste_from_clipboard(entry_key))
btn_paste_key.grid(row=1, column=3, padx=5, pady=5)

btn_encrypt = ctk.CTkButton(main_frame, text="Encrypt it", command=handle_encrypt_text)
btn_encrypt.grid(row=2, column=0, padx=10, pady=10)

btn_decrypt = ctk.CTkButton(main_frame, text="Decrypt", command=handle_decrypt_text)
btn_decrypt.grid(row=2, column=1, padx=10, pady=10)

btn_decrypt_key = ctk.CTkButton(main_frame, text="Decrypt the key", command=decrypt_key_from_entry)
btn_decrypt_key.grid(row=6, column=2, padx=10, pady=10)


ctk.CTkLabel(main_frame, text="Result:").grid(row=3, column=0, padx=10, pady=10)
entry_result = ctk.CTkEntry(main_frame, width=300)
entry_result.grid(row=3, column=1, padx=10, pady=10)

btn_copy_result = ctk.CTkButton(main_frame, text="Copy the result",
                                command=lambda: copy_to_clipboard(entry_result.get()))
btn_copy_result.grid(row=3, column=2, padx=5, pady=5)

btn_generate_qr = ctk.CTkButton(main_frame, text="Create a QR code", command=generate_qr_code)
btn_generate_qr.grid(row=4, column=0, padx=10, pady=10)
btn_scan_qr_from_file = ctk.CTkButton(main_frame, text="Scan a QR code", command=scan_qr_code_from_file)
btn_scan_qr_from_file.grid(row=4, column=1, padx=10, pady=10)

create_info_button(
    main_frame, 4, 2, "QR codes",
    "QR codes allow you to quickly transfer the key between devices.\n"
    "QR codes can be created and scanned for AES and ChaCha20.\n"
    "Creation and scanning are not available for RSA.\n"
    "Save QR codes to a file and upload them to extract the keys.."
)
btn_clear_key = ctk.CTkButton(main_frame, text="Clear the key field", command=clear_key_field)
btn_clear_key.grid(row=2, column=3, padx=10, pady=10)

btn_open_editor = ctk.CTkButton(main_frame, text="Open the editor", command=lambda: open_text_editor())
btn_open_editor.grid(row=6, column=0, padx=10, pady=10)

btn_load_pub = ctk.CTkButton(main_frame, text="Download the public key from a file", command=load_public_key_from_file)
btn_load_pub.grid(row=6, column=1, padx=10, pady=10)

create_info_button(
    main_frame, 6, 3, "The RSA public key",
    "The RSA public key can be distributed freely. It is needed to\n"
    "anyone could encrypt a message to you that only you can\n"
    "decrypt it with your private key.\n"
    "The public key also allows you to verify signatures made with a private key."
)

btn_settings = ctk.CTkButton(main_frame, text="Encryption Settings", command=show_encryption_settings)
btn_settings.grid(row=7, column=0, padx=10, pady=10)

create_info_button(
    main_frame, 7, 1, "Encryption Settings",
    "Here you can select the AES mode (EAX or GCM) and control the nonce for the ChaCha20.\n"
    "This affects the security and some encryption properties.\n"
    "For example, GCM provides authentication, and EAX also offers AEAD.\n"
    "For ChaCha20, you can generate a new nonce every time (recommended)."
)

btn_help = ctk.CTkButton(main_frame, text="FAQ", command=show_help)
btn_help.grid(row=7, column=2, padx=10, pady=10)

btn_open_store = ctk.CTkButton(main_frame, text="Open the keystore", command=open_key_store)
btn_open_store.grid(row=9, column=0, padx=10, pady=10)

btn_save_to_store = ctk.CTkButton(main_frame, text="Save the key to the vault", command=save_key_to_store)
btn_save_to_store.grid(row=9, column=1, padx=10, pady=10)

create_info_button(
    main_frame, 9, 2, "Key Storage",
    "A keystore is an encrypted file accessible by a master password.\n"
    "You can save keys in it and then upload them to the program.\n"
    "This way you can safely store multiple keys without the risk of losing them."
)

progress_bar = ctk.CTkProgressBar(main_frame, width=200)
progress_bar.grid(row=8, column=0, columnspan=2, padx=10, pady=10)
progress_bar.set(0)

root.mainloop()