from module.hash import hash_file, verify_integrity
from module.encryption import aes_ed, rsa_ed
from module.password import check_strength, hash_pw, verify_password
from getpass import getpass


def menu():
    print("\nSelect Operation: ")
    print("1. hash file")
    print("2. Check file integrity")
    print("3. AES Encrypt/Decrypt")
    print("4. RSA Encrypt/Decrypt")
    print("5. Password Manager")
    print("0. Exit")

print("""
Initiating Cryptography Toolkit v1.0...

\nWelcome, Agent! Your mission, should you choose to accept it:
- Analyze and hash files to detect tampering
- Encrypt and decrypt messages with AES and RSA
- Securely manage passwords and assess their strength

All systems online. Data protection protocols active.
Prepare to enter the world of digital secrecy!""")

while True:
    menu()
    choice = input("Enter choice(0-5): ")
    if choice == "0":
        break

    elif choice == "1":
        file_path = input("Enter file path: ")
        print("\nSHA Hash of File is: ", hash_file(file_path))

    elif choice == "2":
        file_path1 = input("Enter file path 1: ")
        file_path2 = input("Enter file path 2: ")
        print(verify_integrity(file_path1, file_path2))
        
    elif choice == "3":
        message = input("Enter message: ")
        key, ciphertext, plaintext = aes_ed(message.encode())
        print("AES Key: ", key)
        print("AES Ciphertext: ", ciphertext)
        print("AES Plaintext: ", plaintext)
    elif choice == "4":
        message = input("Enter message: ")
        ciphertext, plaintext = rsa_ed(message.encode())
        print("RSA message, encrypted with a public key: ", ciphertext)
        print("RSA message, decrypted with a private key: ", plaintext)
        
    elif choice == "5":
        while True:
            password = getpass("Enter a password to check strength: ")
            print(check_strength(password))
            if check_strength(password).startswith("Weak"):
                print("Please choose a stronger password.")
            
            else:
                break
        
        hashed_password = hash_pw(password)
        print("Hashed password: ", hashed_password)
        attempt = getpass("Re-enter the password to verify: ")
        print(verify_password(attempt, hashed_password))

    else:
        print("Invalid Choice")