import tkinter as tk
from tkinter import filedialog
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import tkinter.messagebox as messagebox

class FileEncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Encryption App")

        self.encrypt_button = tk.Button(root, text="Enkripsi File", command=self.encrypt_file)
        self.encrypt_button.pack(pady=10)

        self.decrypt_button = tk.Button(root, text="Dekripsi File", command=self.decrypt_file)
        self.decrypt_button.pack(pady=5)

    def generate_key(self, password):
        # Menggunakan SHA-256 untuk menghasilkan kunci dengan panjang 32 byte
        sha256 = hashlib.sha256()
        sha256.update(password.encode())
        return sha256.digest()

    def display_encryption_key(self, encryption_key):
        key_window = tk.Toplevel(self.root)
        key_window.title("Kunci Enkripsi")

        key_label = tk.Label(key_window, text="Kunci Enkripsi:")
        key_label.pack()

        key_text = tk.Text(key_window, height=4, width=40)
        key_text.insert(tk.END, encryption_key.hex())
        key_text.config(state=tk.DISABLED)
        key_text.pack()

    def encrypt_file(self):
        password_window = tk.Toplevel(self.root)
        password_window.title("Masukkan Password")

        password_label = tk.Label(password_window, text="Password:")
        password_label.pack()

        password_entry = tk.Entry(password_window, show="*")
        password_entry.pack()

        encrypt_button = tk.Button(password_window, text="Enkripsi", command=lambda: self.perform_encryption(password_entry.get()))
        encrypt_button.pack()

    def perform_encryption(self, password):
        encryption_key = self.generate_key(password)

        file_path = filedialog.askopenfilename()
        if file_path:
            print("Kunci enkripsi yang digunakan:", encryption_key.hex())  # Menampilkan kunci enkripsi dalam bentuk hex
            cipher = AES.new(encryption_key, AES.MODE_CBC)

            with open(file_path, 'rb') as file:
                file_data = file.read()
                encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))

            save_path = filedialog.asksaveasfilename(defaultextension=".enc")
            if save_path:
                with open(save_path, 'wb') as file:
                    file.write(cipher.iv)
                    file.write(encrypted_data)

                print("File berhasil dienkripsi!")
                self.display_encryption_key(encryption_key)

    def decrypt_file(self):
        decryption_window = tk.Toplevel(self.root)
        decryption_window.title("Masukkan Kunci Enkripsi")

        key_label = tk.Label(decryption_window, text="Kunci Enkripsi (Hex):")
        key_label.pack()

        key_entry = tk.Entry(decryption_window)
        key_entry.pack()

        decrypt_button = tk.Button(decryption_window, text="Dekripsi", command=lambda: self.perform_decryption(key_entry.get()))
        decrypt_button.pack()

    def perform_decryption(self, encryption_key_hex):
        encryption_key = bytes.fromhex(encryption_key_hex)

        file_path = filedialog.askopenfilename()
        if file_path:
            with open(file_path, 'rb') as file:
                iv = file.read(16)
                encrypted_data = file.read()

            try:
                cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
                decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

                save_path = filedialog.asksaveasfilename(defaultextension="")
                if save_path:
                    with open(save_path, 'wb') as file:
                        file.write(decrypted_data)

                    print("File berhasil didekripsi!")
            except ValueError:
                messagebox.showerror("Kunci Salah", "Kunci enkripsi salah!")

    def generate_key(self, password):
        # Menggunakan SHA-256 untuk menghasilkan kunci dengan panjang 32 byte
        sha256 = hashlib.sha256()
        sha256.update(password.encode())
        return sha256.digest()

root = tk.Tk()
app = FileEncryptionApp(root)
root.mainloop()
