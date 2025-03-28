import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend

# =============== SOCKET CLIENT FOR DRONE COMMUNICATION ===============
HOST = '192.168.175.179'  # Drone's IP
PORT = 5000
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    client_socket.connect((HOST, PORT))
    
    print("Connected to the drone.")
except Exception as e:
    print(f"Failed to connect: {e}")
    exit(1)

# =============== FUNCTION: RECEIVE PUBLIC KEY FROM DRONE ===============
def receive_public_key():
    pem_data = b""
    try:
        while True:
            
            chunk = client_socket.recv(1024)
            if not chunk:
                break
            pem_data += chunk
            if b"-----END PUBLIC KEY-----" in pem_data:
                break

        # Validate PEM structure
        if not pem_data.startswith(b"-----BEGIN PUBLIC KEY-----") or not pem_data.strip().endswith(b"-----END PUBLIC KEY-----"):
            raise ValueError("Malformed PEM received. See https://cryptography.io/en/latest/faq/#why-can-t-i-import-my-pem-file")
        
        public_key = serialization.load_pem_public_key(pem_data, backend=default_backend())
        return public_key
    except Exception as e:
        print(f"Error receiving public key: {e}")
        raise

# =============== MAIN LOGIC ===============
try:
    public_key = receive_public_key()
    print("Public key loaded successfully.")

    while True:
        command = input("Enter command: ")
        encrypted_command = public_key.encrypt(
            command.encode(),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        client_socket.sendall(encrypted_command)
        print("Command sent.")
    

except Exception as e:
    print(f"Error: {e}")

finally:
    client_socket.close()