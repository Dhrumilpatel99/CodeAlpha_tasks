import socket
import os
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

# Generate RSA Keys for secure key exchange
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Serialize public key for exchange
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

def generate_symmetric_key():
    return Fernet.generate_key()

def encrypt_file(file_path, cipher_suite):
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_data = cipher_suite.encrypt(file_data)
    return encrypted_data

def decrypt_file(encrypted_data, cipher_suite):
    return cipher_suite.decrypt(encrypted_data)

def compute_hash(file_path):
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(4096):
            hasher.update(chunk)
    return hasher.hexdigest()

def send_file(file_path):
    if not os.path.isfile(file_path):
        print("Invalid file path. Please try again.")
        return

    symmetric_key = generate_symmetric_key()
    cipher_suite = Fernet(symmetric_key)
    encrypted_data = encrypt_file(file_path, cipher_suite)
    file_hash = compute_hash(file_path)
    
    # Encrypt symmetric key with RSA
    encrypted_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('127.0.0.1', 65432))
        file_info = {
            "key": encrypted_key.hex(),
            "data": encrypted_data.hex(),
            "hash": file_hash
        }
        s.sendall(json.dumps(file_info).encode())
        print("File sent successfully with end-to-end encryption.")

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(('127.0.0.1', 65432))
        server.listen()
        print("Server listening for incoming files...")
        conn, addr = server.accept()
        with conn:
            data = json.loads(conn.recv(4096).decode())
            encrypted_key = bytes.fromhex(data["key"])
            encrypted_data = bytes.fromhex(data["data"])
            received_hash = data["hash"]
            
            # Decrypt symmetric key
            symmetric_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            cipher_suite = Fernet(symmetric_key)
            decrypted_data = decrypt_file(encrypted_data, cipher_suite)
            
            # Save file
            with open("received_file", "wb") as f:
                f.write(decrypted_data)
                
            # Verify integrity
            new_hash = hashlib.sha256(decrypted_data).hexdigest()
            if new_hash == received_hash:
                print("File received successfully with integrity verified.")
            else:
                print("File integrity check failed!")

if __name__ == "__main__":
    print("Secure File Transfer Application")
    print("1. Send a file")
    print("2. Receive a file")
    
    # Use a predefined choice to avoid input() errors in a restricted environment
    choice = "1"  # Change this manually to "2" for receiving mode
    print(f"Selected option: {choice}")
    
    if choice == "1":
        file_path = "example.txt"  # Change this manually to the desired file path
        print(f"Transferring file: {file_path}")
        send_file(file_path)
    elif choice == "2":
        start_server()
    else:
        print("Invalid choice. Exiting.")
