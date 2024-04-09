# FileCipher - Made by V / Lou du Poitou (c) 2024 - V.1 #
## Vencryption (c) 2024 - Made by V / Lou du Poitou ##
##
# GitHub => https://github.com/Lou-du-Poitou/
# Python => https://pypi.org/user/lou_du_poitou/
# Link => https://encryption.nexcord.pro/
##
## V / Lou du Poitou : https://encryption.nexcord.pro/lou-du-poitou ##

# --- --- --- #
import tkinter as tk
from tkinter.font import Font
from sys import executable, argv
from tkinter import messagebox, filedialog, ttk

import hashlib
import threading

import vencryption
# --- --- --- #

# --- --- --- #
app = tk.Tk()
app.geometry("325x75")
app.title("FileCipher")
app.iconbitmap(executable)
app.resizable(False, False)
app.attributes("-topmost", True)
app.config(background="#CEEACC")
# --- --- --- #

# --- --- --- #
def break_text(text:str | bytes, size:int) -> tuple:
    result = [text[i:i+size] for i in range(0, len(text), size)]
    return tuple(result)

def set_file(file:str=None):
    if file == None and run.get() == False:
        file = filedialog.askopenfilename()
    if file != "" and file != None:
        cd.set(file)
        file_name.set(file.split("/")[-1])

def setoptions():
    # --- --- --- #
    if run.get() == False:
        def crypt_data():
            clone.destroy()
            run.set(True)
            if cd.get() == "":
                load.stop()
                run.set(False)
                messagebox.showwarning("Warn", "You have not selected a file!")
            else:
                try:
                    with open(cd.get(), "rb") as f:
                        data = break_text(f.read(), 16+key1.get()*key2.get())
                    f.close()
                    result = list()
                    for text in data:
                        e = vencryption.crypt(text, hashlib.sha256(f"{key1.get()}{keytext.get()}{key2.get()}".encode()).hexdigest())
                        result.append(e)
                    result = b"".join(tuple(result))
                    result = vencryption.crypt(result, hashlib.sha256(keytext.get().encode()).hexdigest())
                    with open(cd.get(), "wb") as f:
                        f.write(result)
                        f.close()
                    load.stop()
                    run.set(False)
                    messagebox.showinfo("Info", "Your file has just been fully encrypted!")
                except Exception as e:
                    load.stop()
                    run.set(False)
                    messagebox.showerror("Error", "An error has occurred !")

        def decrypt_data():
            clone.destroy()
            run.set(True)
            if cd.get() == "":
                load.stop()
                run.set(False)
                messagebox.showwarning("Warn", "You have not selected a file!")
            else:
                try:
                    with open(cd.get(), "rb") as f:
                        data = vencryption.decrypt(f.read(), hashlib.sha256(keytext.get().encode()).hexdigest())
                        data = break_text(data, 16+key1.get()*key2.get())
                    f.close()
                    result = list()
                    for text in data:
                        e = vencryption.decrypt(text, hashlib.sha256(f"{key1.get()}{keytext.get()}{key2.get()}".encode()).hexdigest())
                        result.append(e)
                    result = b"".join(tuple(result))
                    with open(cd.get(), "wb") as f:
                        f.write(result)
                        f.close()
                    load.stop()
                    run.set(False)
                    messagebox.showinfo("Info", "Your file has just been fully decrypted!")
                except Exception as e:
                    load.stop()
                    run.set(False)
                    messagebox.showerror("Error", "An error has occurred !")
        # --- --- --- #
        
        # --- --- --- # 
        clone = tk.Toplevel()
        clone.geometry("200x120")
        clone.grab_set()
        clone.resizable(False, False)
        clone.iconbitmap(executable)
        clone.attributes("-topmost", True)
        clone.config(background="#CEEACC")
        # --- --- --- #
        
        # --- --- --- #
        entry1 = tk.Entry(clone, borderwidth=2, textvariable=keytext, state="normal", font=Font(family="Arial", size=15), justify="center", background="#F4FFE2")
        entry1.pack()
        
        values = (2, 3, 4, 5, 6, 7, 8, 9)
        
        option2 = tk.OptionMenu(clone, key2, 1, *values)
        option2.pack(side=tk.BOTTOM, expand=True, fill=tk.X, anchor=tk.W)
        option2.config(background="#CEEACC", activebackground="#CEEACC")
        
        option1 = tk.OptionMenu(clone, key1, 1, *values)
        option1.pack(side=tk.BOTTOM, expand=True, fill=tk.X, anchor=tk.W)
        option1.config(background="#CEEACC", activebackground="#CEEACC")
        
        crypt = tk.Button(clone, text="CRYPT", font=Font(family="Arial", size=10, weight="bold", slant="italic"), command=lambda: [load.start(), threading.Thread(target=crypt_data).start()], width=3, background="#CEEACC", activebackground="#CEEACC")
        crypt.pack(side=tk.LEFT, anchor=tk.NE, fill=tk.X, expand=True)
        decrypt = tk.Button(clone, text="DECRYPT", font=Font(family="Arial", size=10, weight="bold", slant="italic"), command=lambda: [load.start(), threading.Thread(target=decrypt_data).start()], width=3, background="#CEEACC", activebackground="#CEEACC")
        decrypt.pack(side=tk.LEFT, anchor=tk.NE, fill=tk.X, expand=True)
        # --- --- --- #
    else:
        pass
# --- --- --- #

# --- --- --- #
file_name = tk.StringVar()
cd = tk.StringVar()

keytext = tk.StringVar()

key1 = tk.IntVar(value=1)
key2 = tk.IntVar(value=1)

run = tk.BooleanVar(value=False)
# --- --- --- #

# --- --- --- #
load = ttk.Progressbar(app, orient="horizontal", mode="indeterminate", length=280)
load.pack(side=tk.BOTTOM, padx=(5,5), pady=(1,5), fill=tk.BOTH)

file = tk.Button(app, text="CHOOSE FILE", font=Font(family="Arial", size=10, weight="bold", slant="italic"), command=set_file, background="#CEEACC", activebackground="#CEEACC")
file.pack(side=tk.LEFT, padx=(5,1), pady=(5,5), fill=None, anchor=tk.N)

options = tk.Button(app, text="≡", font=Font(family="Arial", size=10), command=setoptions, background="#CEEACC", activebackground="#CEEACC")
options.pack(side=tk.LEFT, padx=(0,1), pady=(5,5), fill=None, anchor=tk.N)

path = tk.Entry(app, borderwidth=2, textvariable=file_name, state="disabled", font=Font(family="Arial", size=15), background="#CEEACC")
path.pack(side=tk.LEFT, padx=(5,5), pady=(5,1), fill=tk.X, anchor=tk.N)
# --- --- --- #

# --- --- --- #
try:
    script, file = argv
    set_file(file)
except:
    pass
# --- --- --- #

# --- --- --- #
app.mainloop()
# --- --- --- #

# Text Editor - Made by V / Lou du Poitou (c) 2024 - V.2 #
## Vencryption (c) 2024 - Made by V / Lou du Poitou ##
## V / Lou du Poitou : https://encryption.nexcord.pro/lou-du-poitou ##