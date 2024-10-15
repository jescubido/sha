import tkinter as tk
from tkinter import scrolledtext

# SHA-256 Constants
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c48, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa11, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

# Right rotate function
def right_rotate(value, amount):
    return ((value >> amount) | (value << (32 - amount))) & 0xFFFFFFFF

# Perform SHA-256 padding on input message
def sha256_pad(message):
    byte_msg = message.encode('utf-8')
    bit_length = len(byte_msg) * 8

    # Add the '1' bit to the message
    byte_msg += b'\x80'

    # Pad with zeros until length is 64 bits shy of a multiple of 512
    while (len(byte_msg) * 8) % 512 != 448:
        byte_msg += b'\x00'

    # Append original length as a 64-bit integer
    byte_msg += bit_length.to_bytes(8, 'big')

    return byte_msg

# Main SHA-256 algorithm that showcases each round
def sha256_showcase(message, display_widget):
    padded_msg = sha256_pad(message)
    blocks = [padded_msg[i:i + 64] for i in range(0, len(padded_msg), 64)]

    # Initial hash values
    h = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]

    for block in blocks:
        # Break block into sixteen 32-bit words
        w = [int.from_bytes(block[i:i + 4], 'big') for i in range(0, 64, 4)]

        # Extend the sixteen 32-bit words into sixty-four 32-bit words
        for i in range(16, 64):
            s0 = right_rotate(w[i - 15], 7) ^ right_rotate(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = right_rotate(w[i - 2], 17) ^ right_rotate(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF)

        # Initialize hash value for this chunk
        a, b, c, d, e, f, g, h0 = h

        # Main loop
        for i in range(64):
            S1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h0 + S1 + ch + K[i] + w[i]) & 0xFFFFFFFF
            S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF

            # Update the hash values
            temp0 = (temp1 + temp2) & 0xFFFFFFFF  # Define temp0 here
            h0 = (g + temp1) & 0xFFFFFFFF
            g = f
            f = e
            e = (d + temp0) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

            # Display the current round state
            display_widget.insert(
                tk.END,
                f"Round {i + 1}:\n"
                f"A = {a:08x}, B = {b:08x}, C = {c:08x}, "
                f"D = {d:08x}, E = {e:08x}, F = {f:08x}, "
                f"G = {g:08x}, H = {h0:08x}\n\n"
            )
            display_widget.see(tk.END)  # Scroll to the latest output
            display_widget.update()  # Refresh the GUI

        # Add this chunk's hash to the result so far
        h = [(x + y) & 0xFFFFFFFF for x, y in zip(h, [a, b, c, d, e, f, g, h0])]

    # Final hash value (hexadecimal format)
    final_hash = ''.join(f"{x:08x}" for x in h)

    # Display the final hash at the end of the rounds
    display_widget.insert(tk.END, f"Final SHA-256 Hash: {final_hash}\n")
    display_widget.see(tk.END)  # Scroll to the latest output

# GUI setup
def create_gui():
    # Main window
    window = tk.Tk()
    window.title("SHA-256 Hash Generator")
    window.geometry("600x400")

    # Input field
    input_label = tk.Label(window, text="Enter Text:")
    input_label.pack(pady=5)
    input_entry = tk.Entry(window, width=50)
    input_entry.pack(pady=5)

    # Display area for rounds
    display = scrolledtext.ScrolledText(window, width=70, height=15)
    display.pack(pady=10)

    # Generate button
    generate_button = tk.Button(
        window, text="Generate SHA-256", 
        command=lambda: sha256_showcase(input_entry.get(), display)
    )
    generate_button.pack(pady=5)

    # Start the GUI loop
    window.mainloop()

# Run the GUI
if __name__ == "__main__":
    create_gui()
