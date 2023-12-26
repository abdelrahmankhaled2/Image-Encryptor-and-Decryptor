import binascii
import tkinter as tk

def encrypt():
    plaintext = plaintext_entry.get()
    key = key_entry.get()

    # Divide plaintext into two-element chunks
    plaintext_result = []
    for i in range(0, len(plaintext), 2):
        plaintext_result.append(plaintext[i:i+2])

    # Convert plaintext chunks to ASCII codes
    plaintext_ascii = []
    for element_list, ascii_list in [(plaintext_result, plaintext_ascii)]:
        for element in element_list:
            ascii_codes = [str(ord(char)) for char in element]
            ascii_list.extend(ascii_codes)

    # Convert plaintext ASCII codes to hexadecimal
    hex_plaintext = []
    for ascii_list, hex_list in [(plaintext_ascii, hex_plaintext)]:
        for ascii_code in ascii_list:
            hex_value = hex(int(ascii_code))[2:].zfill(2)
            hex_list.append(hex_value)

    # Convert plaintext hexadecimal to binary
    bin_plaintext = []
    for hex_list, bin_list in [(hex_plaintext, bin_plaintext)]:
        for hex_value in hex_list:
            bin_value = bin(int(hex_value, 16))[2:].zfill(8)
            bin_list.append(bin_value)

    # Convert key to binary
    bin_key = bin(int(key, 16))[2:].zfill(8)

    # Apply the key with every element in plaintext and append the result to a list
    cipher_list = []
    cipher_text = ""
    for x in bin_plaintext:
        for index, bit in enumerate(x):
            cipher_text += str(int(bit) ^ int(bin_key[index]))
        cipher_list.append(cipher_text)
        cipher_text = ""

    # Convert the XOR results to hexadecimal
    cipher_text_hex_list = []
    for cipher_text in cipher_list:
        cipher_text_hex = hex(int(cipher_text, 2))[2:].zfill(2)
        cipher_text_hex_list.append(cipher_text_hex)

    cipher_text_bytes = binascii.unhexlify(''.join(cipher_text_hex_list))
    cipher_text_result.config(text="Ciphertext Message: " + cipher_text_bytes.decode())

def decrypt():
    ciphertext = ciphertext_entry.get()
    key = key_entry.get()

    # Convert ciphertext to hexadecimal
    hex_ciphertext = binascii.hexlify(ciphertext.encode()).decode()

    # Convert ciphertext hexadecimal to binary
    bin_ciphertext = []
    for index in range(0, len(hex_ciphertext), 2):
        hex_value = hex_ciphertext[index:index+2]
        bin_value = bin(int(hex_value, 16))[2:].zfill(8)
        bin_ciphertext.append(bin_value)

    # Convert key to binary
    bin_key = bin(int(key, 16))[2:].zfill(8)

    # Decrypt the ciphertext using the key
    decrypted_list = []
    decrypted_text = ""
    for cipher_text in bin_ciphertext:
        for index, bit in enumerate(cipher_text):
            decrypted_text += str(int(bit) ^ int(bin_key[index]))
        decrypted_list.append(decrypted_text)
        decrypted_text = ""

    # Convert the decrypted binary to plaintext
    decrypted_text_list = []
    for decrypted_text in decrypted_list:
        decrypted_text_hex =hex(int(decrypted_text, 2))[2:].zfill(2)
        decrypted_text_list.append(decrypted_text_hex)

    # Convert the decrypted hexadecimal to bytes
    decrypted_text_bytes = binascii.unhexlify(''.join(decrypted_text_list))

    decrypted_text_result.config(text="Original Message: " + decrypted_text_bytes.decode())

# Create the GUI
root = tk.Tk()
root.geometry("400x300")
root.title("ECB Algorithm")

# Create the plaintext label and entry
plaintext_label = tk.Label(root, text="Enter Your Password:")
plaintext_label.pack()
plaintext_entry = tk.Entry(root)
plaintext_entry.pack()

# Create the key label and entry
key_label = tk.Label(root, text="Enter Your Key:")
key_label.pack()
key_entry = tk.Entry(root)
key_entry.pack()

# Create the encrypt button
encrypt_button = tk.Button(root, text="Encrypt", command=encrypt)
encrypt_button.pack()

# Create the ciphertext label and result
cipher_text_label = tk.Label(root, text="Encrypt Password:")
cipher_text_label.pack()
cipher_text_result = tk.Label(root, text="")
cipher_text_result.pack()

# Create the ciphertext label and entry
ciphertext_label = tk.Label(root, text="Enter Your Encrypted Password:")
ciphertext_label.pack()
ciphertext_entry = tk.Entry(root)
ciphertext_entry.pack()

# Create the decrypt button
decrypt_button = tk.Button(root, text="Decrypt", command=decrypt)
decrypt_button.pack()

# Create the decrypted text label and result
decrypted_text_label = tk.Label(root, text="Original Password:")
decrypted_text_label.pack()
decrypted_text_result = tk.Label(root, text="")
decrypted_text_result.pack()

# Start the GUI
root.mainloop()