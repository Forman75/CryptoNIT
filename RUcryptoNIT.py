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
            messagebox.showerror("Ошибка", f"Можно открыть только {LimitedToplevel.MAX_WINDOWS} окна!")
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
root.title("КриптоНИТ")
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
    password = simpledialog.askstring("Защита", "Введите пароль для шифрования ключа:", show='*')

    if not password:
        messagebox.showwarning("Ошибка", "Пароль не введен! Ключ не будет зашифрован.")
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

        set_status("Публичный ключ сохранен в public_key.pem")

        key = private_key

    encrypted_key = encrypt_key(key, password)

    entry_key.delete(0, ctk.END)
    entry_key.insert(0, encrypted_key)

    set_status(f"Ключ для {algo} сгенерирован и зашифрован.")
    messagebox.showinfo("Генерация ключа", f"Ключ для {algo} зашифрован и вставлен в поле.")

def decrypt_key_from_entry():
    encrypted_key = entry_key.get()
    if not encrypted_key:
        messagebox.showwarning("Ошибка", "Поле ключа пустое!")
        return

    password = simpledialog.askstring("Введите пароль", "Введите пароль для расшифровки ключа:", show='*')
    if not password:
        messagebox.showwarning("Ошибка", "Пароль не введен!")
        return

    decrypted_key = decrypt_key(encrypted_key, password)
    if decrypted_key:
        entry_key.delete(0, ctk.END)
        entry_key.insert(0, decrypted_key)
        set_status("Ключ успешно расшифрован.")

        threading.Thread(target=clear_entry_after_delay, daemon=True).start()

def clear_entry_after_delay():
    time.sleep(30)
    entry_key.delete(0, ctk.END)
    set_status("Приватный ключ удален из памяти.")

def load_public_key_from_file():
    file_path = filedialog.askopenfilename(
        title="Выберите файл с публичным ключом",
        filetypes=[("Public Key", "*.pem"), ("All Files", "*.*")]
    )
    if file_path:
        try:
            with open(file_path, "r") as f:
                public_key_data = f.read().strip()

            try:
                rsa_key = RSA.import_key(base64.b64decode(public_key_data))
            except ValueError:
                messagebox.showerror("Ошибка", "Файл не содержит корректный RSA-публичный ключ.")
                return

            entry_key.delete(0, ctk.END)
            entry_key.insert(0, public_key_data)
            set_status(f"Публичный ключ загружен из {file_path}")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось загрузить ключ: {str(e)}")

def generate_qr_code():
    algo = algorithm_var.get()
    if algo == "RSA":
        messagebox.showerror("Ошибка", "Создание QR-кодов для RSA не поддерживается.")
        return

    key = entry_key.get()
    if not key:
        messagebox.showerror("Ошибка", "Ключ не найден для создания QR-кода")
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
        title="Сохранить QR-код как"
    )
    if file_path:
        img.save(file_path)
        set_status(f"QR-код сохранен: {file_path}")


def scan_qr_code_from_file():
    algo = algorithm_var.get()
    if algo == "RSA":
        messagebox.showerror("Ошибка", "Сканирование QR-кодов для RSA не поддерживается.")
        return

    file_path = filedialog.askopenfilename(
        title="Выберите файл с QR-кодом",
        filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")]
    )
    if file_path:
        img = cv2.imread(file_path)
        detector = cv2.QRCodeDetector()
        data, _, _ = detector.detectAndDecode(img)
        if data and isinstance(data, str):
            entry_key.delete(0, ctk.END)
            entry_key.insert(0, data)
            set_status("Ключ успешно считан из QR-кода")
        else:
            messagebox.showerror("Ошибка", "QR-код не распознан или пуст.")


def clear_key_field():
    entry_key.delete(0, ctk.END)
    set_status("Поле ключа очищено.")

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
        messagebox.showerror("Ошибка", "Неверный пароль или поврежденный ключ!")
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
            messagebox.showerror("Ошибка", "Нельзя шифровать с использованием приватного ключа!")
            return None

        cipher = PKCS1_OAEP.new(rsa_key)
        ciphertext = cipher.encrypt(text.encode())

        return base64.b64encode(ciphertext).decode()

    except ValueError:
        messagebox.showerror("Ошибка", "Некорректный публичный ключ!")
        return None
    except Exception as e:
        messagebox.showerror("Ошибка", f"Ошибка при шифровании: {str(e)}")
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
        raise ValueError("Некорректная длина ключа для ChaCha20")
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
    set_status("Обработка...")
    root.update_idletasks()
    result = func()
    for i in range(0, 101, 20):
        time.sleep(0.05)
        progress_bar.set(i/100)
        root.update_idletasks()
    progress_bar.set(1.0)
    set_status("Операция завершена.")
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
        messagebox.showerror("Ошибка", "Введите текст для шифрования!")
        return

    if not key:
        messagebox.showerror("Ошибка", "Введите или загрузите ключ!")
        return

    if algo == "RSA":
        encrypted = encrypt_text_rsa(text, key)
    elif algo == "AES":
        encrypted = encrypt_text_aes(text, key, aes_mode)
    elif algo == "ChaCha20":
        encrypted = encrypt_text_chacha20(text, key)
    else:
        messagebox.showerror("Ошибка", "Неизвестный алгоритм!")
        return

    if encrypted:
        display_result(encrypted)
        set_status("Текст успешно зашифрован.")


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
        messagebox.showerror("Ошибка", "Неверный формат ключа для выбранного алгоритма.")
        set_status("Ошибка: Некорректный ключ.")
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
    set_status("Текст скопирован в буфер обмена.")


def paste_from_clipboard(entry):
    entry.delete(0, ctk.END)
    try:
        clipboard_content = root.clipboard_get()
        entry.insert(0, clipboard_content)
        set_status("Текст вставлен из буфера обмена.")
    except Exception:
        set_status("Ошибка: буфер обмена пуст или недоступен.")
    set_status("Текст вставлен из буфера обмена.")


def open_search_replace_window(editor_textbox):
    sr_window = LimitedToplevel(root)
    sr_window.title("Поиск и замена")

    ctk.CTkLabel(sr_window, text="Поиск:").grid(row=0, column=0, padx=5, pady=5)
    search_entry = ctk.CTkEntry(sr_window, width=200)
    search_entry.grid(row=0, column=1, padx=5, pady=5)

    ctk.CTkLabel(sr_window, text="Заменить на:").grid(row=1, column=0, padx=5, pady=5)
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
            set_status("Замена завершена.")

    btn_replace_all = ctk.CTkButton(sr_window, text="Заменить все", command=replace_all)
    btn_replace_all.grid(row=2, column=0, columnspan=2, padx=5, pady=5)


def open_text_editor(initial_text=None, read_only=False, show_copy_button=False):
    editor_window = LimitedToplevel(root)
    editor_window.title("Встроенный текстовый редактор")

    editor_textbox = ctk.CTkTextbox(editor_window, width=600, height=400)
    editor_textbox.pack(padx=10, pady=10, fill="both", expand=True)

    char_count_label = ctk.CTkLabel(editor_window, text="Количество символов: 0")
    char_count_label.pack(padx=10, pady=5)

    if initial_text:
        editor_textbox.insert("1.0", initial_text)

    if read_only:
        editor_textbox.configure(state="disabled")

    def update_char_count(_event=None):
        content = editor_textbox.get("1.0", "end-1c")
        char_count_label.configure(text=f"Количество символов: {len(content)}")

    editor_textbox.bind("<<Modified>>", lambda e: (editor_textbox.tk.call(editor_textbox._textbox._w, "edit", "modified", 0), update_char_count()))
    update_char_count()

    def paste_from_clipboard():
        clipboard_text = root.clipboard_get()
        editor_textbox.insert("insert", clipboard_text)
        set_status("Текст вставлен из буфера обмена.")

    if not read_only:
        btn_paste_text = ctk.CTkButton(editor_window, text="Вставить", command=paste_from_clipboard)
        btn_paste_text.pack(padx=10, pady=10)

        btn_search_replace = ctk.CTkButton(editor_window, text="Поиск и замена",
                                           command=lambda: open_search_replace_window(editor_textbox))
        btn_search_replace.pack(padx=5, pady=5)

        def insert_editor_content():
            content = editor_textbox.get("1.0", "end-1c")
            entry_text.delete(0, ctk.END)
            entry_text.insert(0, content)
            set_status("Текст из редактора передан в основное поле.")

        btn_insert_content = ctk.CTkButton(editor_window, text="Передать текст в поле ввода", command=insert_editor_content)
        btn_insert_content.pack(padx=10, pady=10)

    if show_copy_button or read_only:
        def copy_editor_content():
            content = editor_textbox.get("1.0", "end-1c")
            copy_to_clipboard(content)

        btn_copy_text = ctk.CTkButton(editor_window, text="Копировать текст", command=copy_editor_content)
        btn_copy_text.pack(padx=5, pady=5)

def show_encryption_settings():
    settings_window = LimitedToplevel(root)
    settings_window.title("Настройки шифрования")

    ctk.CTkLabel(settings_window, text="Режим AES:").grid(row=0, column=0, padx=10, pady=10)
    aes_mode_var = ctk.StringVar(value=aes_mode)
    aes_option = ctk.CTkOptionMenu(settings_window, values=["EAX", "GCM"], variable=aes_mode_var)
    aes_option.grid(row=0, column=1, padx=10, pady=10)

    chacha_nonce_var = ctk.BooleanVar(value=chacha_new_nonce_each_time)
    chacha_checkbox = ctk.CTkCheckBox(settings_window, text="Генерировать новый nonce для ChaCha20",
                                      variable=chacha_nonce_var)
    chacha_checkbox.grid(row=1, column=0, columnspan=2, padx=10, pady=10)

    def apply_settings():
        global aes_mode, chacha_new_nonce_each_time
        aes_mode = aes_mode_var.get()
        chacha_new_nonce_each_time = chacha_nonce_var.get()
        set_status("Настройки шифрования применены.")
        settings_window.destroy()

    btn_apply = ctk.CTkButton(settings_window, text="Применить", command=apply_settings)
    btn_apply.grid(row=2, column=0, columnspan=2, padx=10, pady=10)


def show_help():
    help_window = LimitedToplevel(root)
    help_window.title("FAQ")

    help_text = (
        "Добро пожаловать в КриптоНИТ - Криптографический Нативный Информационный Трансформатор!\n\n"
        "В этой программе вы можете:\n"
        "- Ввести текст, выбрать алгоритм (AES, RSA, ChaCha20) и выполнить шифрование или расшифровку.\n"
        "- Генерировать ключи, управлять ими через зашифрованное хранилище с мастер-паролем.\n"
        "- Использовать QR-коды для быстрого переноса ключей (кроме RSA).\n"
        "- Пользоваться встроенным текстовым редактором для работы с длинными сообщениями.\n"
        "- Настраивать параметры шифрования (режим AES, nonce для ChaCha20).\n\n"
        "Для получения подробной информации по конкретным функциям нажимайте на значок 'ℹ' рядом с элементами интерфейса.\n\n\n"
        "Разработчик программы: Forman75 (https://github.com/Forman75)\n"
    )

    help_label = ctk.CTkLabel(help_window, text=help_text, justify="left")
    help_label.pack(padx=20, pady=20)


def export_rsa_public_key():
    key = entry_key.get()
    if not validate_key(key, "RSA"):
        messagebox.showerror("Ошибка", "Некорректный RSA ключ.")
        return
    rsa_key = RSA.import_key(base64.b64decode(key))
    pub_key = rsa_key.publickey().export_key()
    file_path = filedialog.asksaveasfilename(defaultextension=".pub", filetypes=[("Public Key", "*.pub")])
    if file_path:
        with open(file_path, "wb") as f:
            f.write(pub_key)
        set_status(f"Публичный ключ сохранен в {file_path}")


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
            raise ValueError("Файл хранилища изменен!")

        cipher = AES.new(master_key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        return pickle.loads(plaintext)

    except ValueError as e:
        messagebox.showerror("Ошибка", str(e))
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
        messagebox.showerror("Ошибка", "Неверный мастер-пароль или повреждено хранилище ключей.")
        return None

    except FileNotFoundError:
        messagebox.showerror("Ошибка", "Файл хранилища не найден.")
        return None

    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось загрузить хранилище: {str(e)}")
        return None

def save_key_store(keys: dict, master_password: str):
    master_key = derive_key_from_master_password(master_password)
    encrypted_keys = {name: encrypt_key(value, master_password) for name, value in keys.items()}
    encrypted_data = encrypt_key_store(encrypted_keys, master_key)
    with open(KEY_STORE_FILE, "wb") as f:
        f.write(encrypted_data)

def open_key_store():
    master_password = simpledialog.askstring("Мастер-пароль", "Введите мастер-пароль для хранилища:")
    if master_password is None:
        return
    keys = load_key_store(master_password)
    if keys is None:
        messagebox.showerror("Ошибка", "Неверный мастер-пароль или повреждено хранилище.")
        return

    store_window = LimitedToplevel(root)
    store_window.title("Хранилище ключей")

    ctk.CTkLabel(store_window, text="Выберите ключ для загрузки:").pack(padx=10, pady=10)

    if len(keys) == 0:
        ctk.CTkLabel(store_window, text="Хранилище пусто.").pack(padx=10, pady=10)
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
            set_status(f"Ключ '{selected}' загружен из хранилища.")
        else:
            messagebox.showerror("Ошибка", "Выберите корректное имя ключа.")

    btn_load = ctk.CTkButton(store_window, text="Загрузить ключ", command=load_selected_key)
    btn_load.pack(pady=10)


def save_key_to_store():
    master_password = simpledialog.askstring("Мастер-пароль", "Введите мастер-пароль для хранилища:")
    if master_password is None:
        return
    keys = load_key_store(master_password)
    if keys is None:
        keys = {}
    key = entry_key.get()
    if not key:
        messagebox.showerror("Ошибка", "Нет ключа для сохранения в хранилище.")
        return
    name = simpledialog.askstring("Имя ключа", "Введите имя для сохраняемого ключа:")
    if name is None or not name.strip():
        return
    keys[name.strip()] = key
    save_key_store(keys, master_password)
    set_status(f"Ключ '{name}' сохранен в хранилище.")


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

ctk.CTkLabel(main_frame, text="Введите текст:").grid(row=0, column=0, padx=10, pady=10)
entry_text = ctk.CTkEntry(main_frame, width=300)
entry_text.grid(row=0, column=1, padx=10, pady=10)

algorithm_var = ctk.StringVar(value="AES")
algorithm_dropdown = ctk.CTkOptionMenu(main_frame, values=["AES", "RSA", "ChaCha20"], variable=algorithm_var)
algorithm_dropdown.grid(row=0, column=2, padx=10, pady=10)

create_info_button(
    main_frame, 0, 3, "Выбор алгоритма",
    "Алгоритмы:\n"
    "- AES: симметричный блочный шифр с одним ключом.\n"
    "- RSA: асимметричный шифр с публичным и приватным ключами.\n"
    "- ChaCha20: симметричный потоковый шифр.\n\n"
    "Выберите алгоритм, затем введите или сгенерируйте ключ, чтобы зашифровать или расшифровать текст."
)

btn_copy_text = ctk.CTkButton(main_frame, text="Копировать текст", command=lambda: copy_to_clipboard(entry_text.get()))
btn_copy_text.grid(row=0, column=4, padx=5, pady=5)

ctk.CTkLabel(main_frame, text="Введите ключ:").grid(row=1, column=0, padx=10, pady=10)
entry_key = ctk.CTkEntry(main_frame, width=300)
entry_key.grid(row=1, column=1, padx=10, pady=10)

btn_generate_key = ctk.CTkButton(main_frame, text="Сгенерировать ключ", command=generate_random_key)
btn_generate_key.grid(row=1, column=2, padx=10, pady=10)

btn_paste_key = ctk.CTkButton(main_frame, text="Вставить ключ", command=lambda: paste_from_clipboard(entry_key))
btn_paste_key.grid(row=1, column=3, padx=5, pady=5)

btn_encrypt = ctk.CTkButton(main_frame, text="Зашифровать", command=handle_encrypt_text)
btn_encrypt.grid(row=2, column=0, padx=10, pady=10)

btn_decrypt = ctk.CTkButton(main_frame, text="Расшифровать", command=handle_decrypt_text)
btn_decrypt.grid(row=2, column=1, padx=10, pady=10)

btn_decrypt_key = ctk.CTkButton(main_frame, text="Расшифровать ключ", command=decrypt_key_from_entry)
btn_decrypt_key.grid(row=6, column=2, padx=10, pady=10)


ctk.CTkLabel(main_frame, text="Результат:").grid(row=3, column=0, padx=10, pady=10)
entry_result = ctk.CTkEntry(main_frame, width=300)
entry_result.grid(row=3, column=1, padx=10, pady=10)

btn_copy_result = ctk.CTkButton(main_frame, text="Копировать результат",
                                command=lambda: copy_to_clipboard(entry_result.get()))
btn_copy_result.grid(row=3, column=2, padx=5, pady=5)

btn_generate_qr = ctk.CTkButton(main_frame, text="Создать QR-код", command=generate_qr_code)
btn_generate_qr.grid(row=4, column=0, padx=10, pady=10)
btn_scan_qr_from_file = ctk.CTkButton(main_frame, text="Сканировать QR-код", command=scan_qr_code_from_file)
btn_scan_qr_from_file.grid(row=4, column=1, padx=10, pady=10)

create_info_button(
    main_frame, 4, 2, "QR-коды",
    "QR-коды позволяют быстро перенести ключ между устройствами.\n"
    "Для AES и ChaCha20 можно создавать и сканировать QR-коды.\n"
    "Для RSA создание и сканирование недоступны.\n"
    "Сохраняйте QR-коды в файл и загружайте их для извлечения ключей."
)

btn_clear_key = ctk.CTkButton(main_frame, text="Очистить поле ключа", command=clear_key_field)
btn_clear_key.grid(row=2, column=3, padx=10, pady=10)

btn_open_editor = ctk.CTkButton(main_frame, text="Открыть редактор", command=lambda: open_text_editor())
btn_open_editor.grid(row=6, column=0, padx=10, pady=10)

btn_load_pub = ctk.CTkButton(main_frame, text="Загрузить публичный ключ из файла", command=load_public_key_from_file)
btn_load_pub.grid(row=6, column=1, padx=10, pady=10)

create_info_button(
    main_frame, 6, 3, "Публичный ключ RSA",
    "Публичный ключ RSA можно распространять свободно. Он нужен, чтобы\n"
    "любой желающий мог зашифровать вам сообщение, которое сможете\n"
    "расшифровать только вы, владея приватным ключом.\n"
    "Также публичный ключ позволяет проверять подписи, сделанные приватным ключом."
)

btn_settings = ctk.CTkButton(main_frame, text="Настройки шифрования", command=show_encryption_settings)
btn_settings.grid(row=7, column=0, padx=10, pady=10)

create_info_button(
    main_frame, 7, 1, "Настройки шифрования",
    "Здесь можно выбрать режим AES (EAX или GCM) и управлять nonce для ChaCha20.\n"
    "Это влияет на безопасность и некоторые свойства шифрования.\n"
    "Например, GCM обеспечивает аутентификацию, а EAX тоже предлагает AEAD.\n"
    "Для ChaCha20 можно генерировать новый nonce каждый раз (рекомендуется)."
)

btn_help = ctk.CTkButton(main_frame, text="FAQ", command=show_help)
btn_help.grid(row=7, column=2, padx=10, pady=10)

btn_open_store = ctk.CTkButton(main_frame, text="Открыть хранилище ключей", command=open_key_store)
btn_open_store.grid(row=9, column=0, padx=10, pady=10)

btn_save_to_store = ctk.CTkButton(main_frame, text="Сохранить ключ в хранилище", command=save_key_to_store)
btn_save_to_store.grid(row=9, column=1, padx=10, pady=10)

create_info_button(
    main_frame, 9, 2, "Хранилище ключей",
    "Хранилище ключей - это зашифрованный файл, доступный по мастер-паролю.\n"
    "Вы можете сохранять в нём ключи, а затем загружать их в программу.\n"
    "Так можно безопасно хранить множество ключей без риска их потери."
)

progress_bar = ctk.CTkProgressBar(main_frame, width=200)
progress_bar.grid(row=8, column=0, columnspan=2, padx=10, pady=10)
progress_bar.set(0)

root.mainloop()