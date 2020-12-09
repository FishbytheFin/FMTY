import base64
import os
from datetime import datetime
from tkinter import *
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

now = datetime.now()
isDecrypted = False

def encrypter():
    if isDecrypted:
        password = password_provided.encode()

        salt = b'\xb0\xa2\x99g\xb6n\x9d+l\x98\x14\xeb\xb6\x8d\x03\xf2'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        with open("list.txt", "w") as f:
            f.write(outputBox.get(1.0, END))
        with open("list.txt", "rb") as f:
            data = f.read()
        fkey = Fernet(key)
        encrypted = fkey.encrypt(data)
        with open("list.txt", "wb") as f:
            f.write(encrypted)
    window.destroy()


def decrypter():
    global isDecrypted
    global password_provided
    try:
        password_provided = textEntry.get()
        password = password_provided.encode()

        salt = b'\xb0\xa2\x99g\xb6n\x9d+l\x98\x14\xeb\xb6\x8d\x03\xf2'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        with open("list.txt", "rb") as f:
            data = f.read()
        fkey = Fernet(key)
        decrypted = fkey.decrypt(data)
        with open("list.txt", "wb") as f:
            f.write(decrypted)
        isDecrypted = True
        textEntry.grid_forget()
        
        submitButton.grid_forget()

        passLable = Label(window, text="From Me, To You:", bg="white", fg="black")
        passLable.grid(row=0, column=0, padx=10, pady=10, sticky=NW)
        global outputBox
        
        outputBox = Text(window, width=50, height=10, wrap=WORD, background="white")
        outputBox.grid(row=0, column=0, padx=10, pady=30, sticky=NW)
        outputBox.delete(0.0, END)
        outputBox.insert(END, decrypted)
        global newPass
        global confirmPass
        newPassLabel = Label(window, text="Enter New Password: ", bg="white")
        newPassLabel.grid(row=0, column=0, padx=10, pady=210, sticky=NW)
        newPass = Entry(window, width=20, show="*", bg="white")
        newPass.grid(row=0, column=0, padx=10, pady=230, sticky=NW)
        confirmPassLabel = Label(window, text="Confirm Password:", bg="white")
        confirmPassLabel.grid(row=0, column=0, padx=10, pady=260, sticky=NW)
        confirmPass = Entry(window, width=20, show="*", bg="white")
        confirmPass.grid(row=0, column=0, padx=10, pady=280, sticky=NW)

        changeButton = Button(window, text="Change Password", width=12, command=changePass)
        changeButton.grid(row=0, column=0, padx=200, pady=280, sticky=NW)

    except:
        with open("log.txt", "a+") as f:
            f.write("\nPassword: "+textEntry.get()+" Time: "+now.strftime("%Y-%m-%d %H:%M:%S"))
        passLable = Label(window, text="Wrong Password!", bg="white", fg="red")
        passLable.grid(row=0, column=0, padx=10, pady=10, sticky=NW)
def changePass():
    global password_provided
    if newPass.get() == confirmPass.get():
        password_provided = newPass.get()
        Label(window, text="Password Was Changed", bg="white", fg="black").grid(row=0, column=0, padx=10, pady=310, sticky=NW)
    else:
        Label(window, text="Password Not Changed!", bg="white", fg="red").grid(row=0, column=0, padx=10, pady=310, sticky=NW)
window = Tk()
window.title("From Me, To You")
window.configure(background="white")
window.geometry("500x500")
window.resizable(0,0)

santaphoto = PhotoImage(file="images/santa.png")
Label(window, image=santaphoto, bg="white", justify=CENTER).grid(row=0, column=0)

passLable = Label(window, text="Enter Password:", bg="white", fg="black")
passLable.grid(row=0, column=0, padx=10, pady=10, sticky=NW)

textEntry = Entry(window, width=20, show="*", bg="white")
textEntry.grid(row=0, column=0, padx=10, pady=30, sticky=NW)

submitButton = Button(window, text="SUBMIT", width=6, command=decrypter)
submitButton.grid(row=0, column=0, padx=190, pady=25, sticky=NW)


window.protocol("WM_DELETE_WINDOW", encrypter)
window.mainloop()
