import base64
from tkinter import *
from tkinter.filedialog import *

root = Tk()
root.title("Encrypt/Decrypt Text")
root.geometry("600x400")

def xor_encrypt_decrypt(text, secret_key):
    key_length = len(secret_key)
    blocks = [text[i:i + key_length] for i in range(0, len(text), key_length)]
    
    if len(blocks[-1]) < key_length:
        blocks[-1] = blocks[-1].ljust(key_length)
    
    processed_blocks = []
    for block in blocks:
        processed_block = ''.join(chr(ord(block_char) ^ ord(secret_key[i % key_length])) for i, block_char in enumerate(block))
        processed_blocks.append(processed_block)
    
    processed_text = ''.join(processed_blocks)
    return processed_text

def process_input():
    plain_text = txt.get()
    secret_key = key.get()
    try:
        decoded_text = base64.b64decode(plain_text).decode()
        decrypted_text = xor_encrypt_decrypt(decoded_text, secret_key)
        result_var.set(decrypted_text)
    except (base64.binascii.Error, UnicodeDecodeError):
        encrypted_text = xor_encrypt_decrypt(plain_text, secret_key)
        encrypted_text_base64 = base64.b64encode(encrypted_text.encode()).decode()
        result_var.set(encrypted_text_base64)
    
    open_result_window()

def copy_to_clipboard():
    root.clipboard_clear()
    root.clipboard_append(result_var.get())
    root.update()

def select_file():
    file_open = askopenfilename()
    if file_open:
        with open(file_open, encoding="utf-8") as file:
            file_content = file.read()
        file_name = file_open.split("/")[-1]  # Extract the file name from the file path
        file_label.config(text=file_name)
        Input_text_space.config(state="normal")
        txt.set(file_content)
        Input_text_space.config(state="disabled")

def reset_fields(result_window=None):
    txt.set("")
    key.set("")
    result_var.set("")
    file_label.config(text="No file selected")
    Input_text_space.config(state="normal")
    if result_window:
        result_window.destroy()


def open_result_window():
    result_window = Toplevel(root)
    result_window.title("Result")
    result_window.geometry("400x300")

    Label(result_window, text="Cipher Text:", font=("Helvetica", 16)).pack(pady=10)
    Label(result_window, textvariable=result_var, font=("Helvetica", 16)).pack(pady=10, padx=10)

    Button(result_window, text="Copy", command=copy_to_clipboard, font=("Helvetica", 16)).pack(pady=10)
    Button(result_window, text="Reset", command=lambda:reset_fields(result_window), font=("Helvetica", 16)).pack(pady=10)

txt = StringVar()
key = StringVar()
result_var = StringVar()

Label(root, text="Plain Text:", font=("Helvetica", 16)).pack()
Input_text_space = Entry(root, textvariable=txt, width=50, font=("Helvetica", 16), justify=CENTER)
Input_text_space.pack(pady=10, padx=10)

file_label = Label(root, text="No file selected", font=("Helvetica", 16))
file_label.pack(pady=10)

Button(root, text="Select File", command=select_file, font=("Helvetica", 16)).pack()

Label(root, text="Secret Key:", font=("Helvetica", 16)).pack()
key_text_input = Entry(root, textvariable=key, width=50, font=("Helvetica", 16), justify=CENTER)
key_text_input.pack(pady=10, padx=10)

Button(root, text="Process", command=process_input, font=("Helvetica", 16)).pack(pady=10)

root.mainloop()
