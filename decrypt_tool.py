import base64
import json
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class CardDecryptor:
    def __init__(self, key):
        self.key = key

    def _unpad(self, data):
        padding_length = data[-1]
        return data[:-padding_length]

    def decrypt_text(self, encrypted_data):
        try:
            # Decode base64
            combined_data = base64.b64decode(encrypted_data)

            # Split IV and ciphertext
            iv = combined_data[:16]
            ciphertext = combined_data[16:]

            # Create cipher
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
            decryptor = cipher.decryptor()

            # Decrypt
            padded_text = decryptor.update(ciphertext) + decryptor.finalize()
            plain_text = self._unpad(padded_text).decode('utf-8')

            # Parse JSON
            return json.loads(plain_text)
        except Exception as e:
            print(f"Error during decryption: {str(e)}")
            return None

def main():
    print("Decryption Tool")
    print("=" * 50)

    # Input key (in real-world use, this should be securely stored)
    key_input = input("Enter encryption key (hex format): ")
    try:
        key = bytes.fromhex(key_input)
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes long")
    except Exception as e:
        print(f"Invalid key! {str(e)}")
        return

    decryptor = CardDecryptor(key)

    while True:
        print("\nChoose data type to decrypt:")
        print("1. Public data (from QR)")
        print("2. Server data")
        print("3. Exit")

        choice = input("Your choice (1-3): ")

        if choice == "3":
            break

        if choice not in ["1", "2"]:
            print("Invalid choice! Please try again.")
            continue

        encrypted_data = input("\nEnter ciphertext (base64): ")

        try:
            decrypted_data = decryptor.decrypt_text(encrypted_data)
            if decrypted_data:
                print("\nDecrypted data:")
                print(json.dumps(decrypted_data, indent=2, ensure_ascii=False))
            else:
                print("Failed to decrypt data!")
        except Exception as e:
            print(f"Error: {str(e)}")

        print("\n" + "=" * 50)

if __name__ == "__main__":
    main()