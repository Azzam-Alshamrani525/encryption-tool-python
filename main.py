# -*- coding: utf-8 -*-
"""
File Encryption Tool (AES-GCM, PBKDF2)
GUI ONLY (No CLI): This build removes all command-line interface code.
واجهة رسومية فقط بدون سطر أوامر.
"""

# ======= Imports =======
import os                      # التعامل مع الملفات والمسارات
import struct                  # بناء/تفكيك ترويسة الملف المشفَّر
import tkinter as tk           # واجهة المستخدم الرسومية
from tkinter import filedialog, messagebox  # مربعات حوار ورسائل

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # اشتقاق مفتاح
from cryptography.hazmat.primitives import hashes                 # خوارزميات الهاش
from cryptography.hazmat.primitives.ciphers.aead import AESGCM    # AES-GCM

# ======= Format constants =======
MAGIC = b'FENC'      # تعريف ملف الأداة
VERSION = 1          # إصدار الصيغة
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32         # AES-256
PBKDF2_ITERS = 200_000  # يمكنك زيادته لأمان أعلى (وأبطأ)

# ======= Bilingual strings (AR/EN) =======
I18N = {
    "ar": {
        "title": "أداة تشفير الملفات - AES-GCM",
        "ui_title": "تشفير الملفات (AES‑GCM)",
        "browse": "اختيار ملف",
        "show_pw": "إظهار كلمة المرور",
        "encrypt": "تشفير",
        "decrypt": "فك التشفير",
        "choose_first": "اختر ملفًا أولاً",
        "enter_pw": "أدخل كلمة المرور",
        # Errors
        "ERR_NOT_FILE": "لم يتم العثور على الملف. تأكد من اختيار المسار الصحيح.",
        "ERR_TOO_SHORT": "الملف المختار لا يبدو مشفّرًا بصيغة الأداة (قصير جدًا). اختر ملف .enc الناتج من الأداة.",
        "ERR_BAD_MAGIC": "الملف المختار ليس بصيغة الأداة (الترويسة غير صحيحة). اختر ملف .enc الناتج من الأداة.",
        "ERR_BAD_VERSION": "إصدار الملف غير مدعوم من هذه النسخة.",
        "ERR_SAME_PATH": "مسار الإخراج لا يجب أن يساوي مسار الإدخال.",
        "ERR_AUTH": "فشل فك التشفير. كلمة المرور غير صحيحة أو الملف تالف.",
        "ERR_UNKNOWN": "حدث خطأ غير متوقع.",
        "done_enc": "تم التشفير إلى:",
        "done_dec": "تم فك التشفير إلى:",
        "ok": "تم"
    },
    "en": {
        "title": "File Encryption Tool - AES-GCM",
        "ui_title": "File Encryption (AES‑GCM)",
        "browse": "Browse",
        "show_pw": "Show password",
        "encrypt": "Encrypt",
        "decrypt": "Decrypt",
        "choose_first": "Choose a file first",
        "enter_pw": "Enter password",
        # Errors
        "ERR_NOT_FILE": "Input file not found. Please select a valid path.",
        "ERR_TOO_SHORT": "Selected file does not look encrypted by this tool (too short). Please select a .enc produced by the tool.",
        "ERR_BAD_MAGIC": "Selected file is not in this tool's format (invalid header). Please select a .enc produced by the tool.",
        "ERR_BAD_VERSION": "This encrypted file version is not supported by this build.",
        "ERR_SAME_PATH": "Output path must be different from input path.",
        "ERR_AUTH": "Decryption failed. Wrong password or file is corrupted.",
        "ERR_UNKNOWN": "An unexpected error occurred.",
        "done_enc": "Encrypted to:",
        "done_dec": "Decrypted to:",
        "ok": "OK"
    }
}

# ======= Crypto helpers =======
def _derive_key(password: str, salt: bytes) -> bytes:
    """اشتقاق مفتاح ثابت الطول من كلمة المرور باستخدام PBKDF2-HMAC-SHA256."""
    if not password:
        raise ValueError("Password required")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERS
    )
    return kdf.derive(password.encode("utf-8"))

def encrypt_file(path_in: str, password: str, path_out: str = None) -> str:
    """تشفير ملف: يكتب ترويسة + بيانات AES-GCM. يعيد مسار الناتج."""
    if not os.path.isfile(path_in):
        raise FileNotFoundError("ERR_NOT_FILE")
    if path_out and os.path.abspath(path_out) == os.path.abspath(path_in):
        raise ValueError("ERR_SAME_PATH")

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)

    with open(path_in, "rb") as f:
        plaintext = f.read()

    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    header = MAGIC + bytes([VERSION]) + salt + nonce
    out_path = path_out or (path_in + ".enc")
    with open(out_path, "wb") as f:
        f.write(header + ciphertext)
    return out_path

def decrypt_file(path_in: str, password: str, path_out: str = None) -> str:
    """فك تشفير ملف بصيغة الأداة. يعيد مسار الملف المفكوك."""
    if not os.path.isfile(path_in):
        raise FileNotFoundError("ERR_NOT_FILE")
    with open(path_in, "rb") as f:
        data = f.read()

    min_len = 4 + 1 + SALT_LEN + NONCE_LEN + 16  # +tag
    if len(data) < min_len:
        raise ValueError("ERR_TOO_SHORT")
    if data[:4] != MAGIC:
        raise ValueError("ERR_BAD_MAGIC")
    version = data[4]
    if version != VERSION:
        raise ValueError("ERR_BAD_VERSION")

    salt = data[5:5+SALT_LEN]
    nonce = data[5+SALT_LEN:5+SALT_LEN+NONCE_LEN]
    ciphertext = data[5+SALT_LEN+NONCE_LEN:]

    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("ERR_AUTH")

    if path_out is None:
        path_out = path_in[:-4] if path_in.endswith(".enc") else (path_in + ".dec")
    if os.path.abspath(path_out) == os.path.abspath(path_in):
        raise ValueError("ERR_SAME_PATH")
    with open(path_out, "wb") as f:
        f.write(plaintext)
    return path_out

# ======= GUI App =======
class App(tk.Tk):
    """واجهة رسومية بسيطة بثنائية اللغة (ar/en)."""
    def __init__(self):
        super().__init__()
        self.lang = tk.StringVar(value="ar")
        self.path_var = tk.StringVar()
        self.pass_var = tk.StringVar()
        self.show_pass = tk.BooleanVar(value=False)

        self.configure(bg="#2d2d2d")
        self.geometry("720x440")
        self.resizable(False, False)

        self._build_ui()
        self._update_lang()

    def _build_ui(self):
        top = tk.Frame(self, bg="#2d2d2d")
        top.pack(anchor="ne", padx=16, pady=(12, 0))
        tk.Label(top, text="اللغة / Language:", fg="#eaeaea", bg="#2d2d2d").pack(side="left", padx=(0,6))
        tk.OptionMenu(top, self.lang, "ar", "en", command=lambda _: self._update_lang()).pack(side="left")

        self.title_lbl = tk.Label(self, font=("Segoe UI", 18, "bold"), fg="#39c07a", bg="#2d2d2d")
        self.title_lbl.pack(pady=(8, 6))

        fr = tk.Frame(self, bg="#2d2d2d")
        fr.pack(fill="x", padx=24, pady=(8, 4))
        self.path_entry = tk.Entry(fr, textvariable=self.path_var, width=68)
        self.path_entry.pack(side="left", padx=(0,8), ipady=4)
        self.browse_btn = tk.Button(fr, command=self._choose_file, bg="#3a3a3a", fg="#eaeaea")
        self.browse_btn.pack(side="left")

        frp = tk.Frame(self, bg="#2d2d2d")
        frp.pack(fill="x", padx=24, pady=(8, 0))
        self.pass_entry = tk.Entry(frp, textvariable=self.pass_var, show="•", width=45)
        self.pass_entry.pack(side="left", padx=(0,8), ipady=4)
        self.show_chk = tk.Checkbutton(frp, variable=self.show_pass, command=self._toggle_pw,
                                       bg="#2d2d2d", fg="#eaeaea", activebackground="#2d2d2d", selectcolor="#2d2d2d")
        self.show_chk.pack(side="left")

        btns = tk.Frame(self, bg="#2d2d2d")
        btns.pack(pady=16)
        self.enc_btn = tk.Button(btns, width=16, bg="#1f8a5f", fg="#ffffff", command=self._encrypt_gui)
        self.dec_btn = tk.Button(btns, width=16, bg="#1f5f8a", fg="#ffffff", command=self._decrypt_gui)
        self.enc_btn.grid(row=0, column=0, padx=10, pady=4)
        self.dec_btn.grid(row=0, column=1, padx=10, pady=4)

        self.out = tk.Text(self, height=10, bg="#202020", fg="#eaeaea")
        self.out.pack(fill="both", expand=True, padx=24, pady=(8, 16))

    def _update_lang(self):
        L = I18N[self.lang.get()]
        self.title(L["title"])
        self.title_lbl.config(text=L["ui_title"])
        self.browse_btn.config(text=L["browse"])
        self.show_chk.config(text=L["show_pw"])
        self.enc_btn.config(text=L["encrypt"])
        self.dec_btn.config(text=L["decrypt"])

    def _choose_file(self):
        p = filedialog.askopenfilename()
        if p:
            self.path_var.set(p)

    def _toggle_pw(self):
        self.pass_entry.config(show="" if self.show_pass.get() else "•")

    def _log(self, msg: str):
        self.out.insert("end", msg + "\n")
        self.out.see("end")

    def _friendly(self, err_code: str) -> str:
        L = I18N[self.lang.get()]
        return L.get(err_code, L["ERR_UNKNOWN"])

    def _encrypt_gui(self):
        L = I18N[self.lang.get()]
        path = self.path_var.get().strip()
        pw = self.pass_var.get()
        if not path:
            messagebox.showerror("Error", L["choose_first"]); return
        if not pw:
            messagebox.showerror("Error", L["enter_pw"]); return
        try:
            outp = encrypt_file(path, pw)
            self._log(f"✔️ {L['done_enc']} {outp}")
            messagebox.showinfo(L["ok"], f"{L['done_enc']} {outp}")
        except FileNotFoundError as e:
            messagebox.showerror("Error", self._friendly(str(e)))
        except ValueError as e:
            messagebox.showerror("Error", self._friendly(str(e)))
        except Exception:
            messagebox.showerror("Error", L["ERR_UNKNOWN"])

    def _decrypt_gui(self):
        L = I18N[self.lang.get()]
        path = self.path_var.get().strip()
        pw = self.pass_var.get()
        if not path:
            messagebox.showerror("Error", L["choose_first"]); return
        if not pw:
            messagebox.showerror("Error", L["enter_pw"]); return
        try:
            outp = decrypt_file(path, pw)
            self._log(f"✔️ {L['done_dec']} {outp}")
            messagebox.showinfo(L["ok"], f"{L['done_dec']} {outp}")
        except FileNotFoundError as e:
            messagebox.showerror("Error", self._friendly(str(e)))
        except ValueError as e:
            messagebox.showerror("Error", self._friendly(str(e)))
        except Exception:
            messagebox.showerror("Error", L["ERR_UNKNOWN"])

# ======= Entrypoint (GUI only) =======
if __name__ == "__main__":
    app = App()
    app.mainloop()
