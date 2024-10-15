import tkinter as tk
from tkinter import scrolledtext

# SHA-1 Constants
H0 = 0x67452301
H1 = 0xEFCDAB89
H2 = 0x98BADCFE
H3 = 0x10325476
H4 = 0xC3D2E1F0

# Rotate left function
def rotate_left(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

# Perform SHA-1 padding on input message
def sha1_pad(message):
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

# Main SHA-1 algorithm that showcases each round
def sha1_showcase(message, display_widget):
    padded_msg = sha1_pad(message)
    blocks = [padded_msg[i:i + 64] for i in range(0, len(padded_msg), 64)]

    h0, h1, h2, h3, h4 = H0, H1, H2, H3, H4

    for block in blocks:
        # Break block into sixteen 32-bit words
        w = [int.from_bytes(block[i:i + 4], 'big') for i in range(0, 64, 4)]
        
        # Extend the sixteen 32-bit words into eighty 32-bit words
        for i in range(16, 80):
            w.append(rotate_left(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))

        # Initialize hash value for this chunk
        a, b, c, d, e = h0, h1, h2, h3, h4

        # Main loop
        for i in range(80):
            if 0 <= i < 20:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (rotate_left(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
            e = d
            d = c
            c = rotate_left(b, 30)
            b = a
            a = temp

            # Display the current round state
            display_widget.insert(
                tk.END,
                f"Round {i + 1}:\n"
                f"A = {a:08x}, B = {b:08x}, C = {c:08x}, "
                f"D = {d:08x}, E = {e:08x}\n\n"
            )
            display_widget.see(tk.END)  # Scroll to the latest output
            display_widget.update()  # Refresh the GUI

        # Add this chunk's hash to the result so far
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    # Final hash value (hexadecimal format)
    final_hash = f"{h0:08x}{h1:08x}{h2:08x}{h3:08x}{h4:08x}"
    
    # Display the final hash at the end of the rounds
    display_widget.insert(tk.END, f"Final SHA-1 Hash: {final_hash}\n")
    display_widget.see(tk.END)  # Scroll to the latest output

# GUI setup
def create_gui():
    # Main window
    window = tk.Tk()
    window.title("SHA-1 Hash Generator")
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
        window, text="Generate SHA-1", 
        command=lambda: sha1_showcase(input_entry.get(), display)
    )
    generate_button.pack(pady=5)

    # Start the GUI loop
    window.mainloop()

# Run the GUI
if __name__ == "__main__":
    create_gui()
