#!/usr/bin/env python
# coding: utf-8

# ### Symmetric AES - Client server

# In[ ]:


import socket
import subprocess
import threading

# Server IP and Port
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65432

# Function to decrypt the file using OpenSSL and AES-256-CBC with a password
def decrypt_message(encrypted_file, decrypted_file):
    # Command to decrypt with password prompt
    command_decrypt = [
        "openssl", "enc", "-aes-256-cbc", "-d", "-in", encrypted_file, "-out", decrypted_file, "-pbkdf2"
    ]

    # Run the OpenSSL command, prompting for password interactively
    subprocess.run(command_decrypt, check=True)
    print(f"Decrypted file saved as '{decrypted_file}'")

# Start the server
def start_server():
    # Create server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(1)
    print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")

    # Accept connection from the client
    conn, addr = server_socket.accept()
    print(f"Connection from {addr}")

    # Receive the encrypted file
    with open("received_encrypted.enc", "wb") as f:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            f.write(data)

    print("Encrypted file received.")

    # Decrypt the received file using the password
    decrypt_message("received_encrypted.enc", "decrypted_message.txt")

    # Close the connection
    conn.close()

threading.Thread(target=start_server, daemon=True).start()


# In[ ]:


import socket
import subprocess

# Server IP and Port
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65432

# Function to encrypt the file using OpenSSL and AES-256-CBC with a password
def encrypt_message(message_file, encrypted_file):
    # Command to encrypt with password prompt
    command_encrypt = [
        "openssl", "enc", "-aes-256-cbc", "-salt", "-in", message_file, "-out", encrypted_file, "-pbkdf2"
    ]

    # Run the OpenSSL command, prompting for password interactively
    subprocess.run(command_encrypt, check=True)
    print(f"File '{message_file}' encrypted and saved as '{encrypted_file}'")

# Send the encrypted file to the server
def send_file(encrypted_file):
    # Connect to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_HOST, SERVER_PORT))

    # Send the encrypted file
    with open(encrypted_file, "rb") as f:
        while (chunk := f.read(1024)):
            client_socket.sendall(chunk)

    print(f"Encrypted file '{encrypted_file}' sent to the server.")

    # Close the connection
    client_socket.close()

    # Encrypt the file using a password
encrypt_message("message.txt", "encrypted_message.enc")

    # Send the encrypted file to the server
send_file("encrypted_message.enc")


# ### Asymmetric - RSA

# In[ ]:


# Save a string to a temporary file
message = "This is a sample message to hash"
with open("message.txt", "w") as f:
    f.write(message)


# In[3]:


import socket
import subprocess
import threading

# Command to generate the private key
generate_private_key = [
    "openssl", "genrsa", "-out", "myprivate.key", "2048"
]

# Command to generate the public key from the private key
generate_public_key = [
    "openssl", "rsa", "-in", "myprivate.key", "-pubout", "-out", "mypublic.key"
]

try:
    # Run the command to generate the private key
    subprocess.run(generate_private_key, check=True)
    print("Private key saved as 'myprivate.key'.")

    # Run the command to generate the public key
    subprocess.run(generate_public_key, check=True)
    print("Public key saved as 'mypublic.key'.")
except subprocess.CalledProcessError as e:
    print(f"An error occurred during key generation: {e}")


# In[4]:


import socket
import subprocess

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 65431))
    server_socket.listen()

    print("Server is listening on port 65431...")

    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")

    # Open a file to store the received content (received_file.enc)
    with open("received_file.enc", 'wb') as file:
        while True:
            data = conn.recv(1024)
            if data == b'END':  # Check for the end-of-file marker
                break
            if not data:
                break  # No more data, break out of the loop
            file.write(data)  # Write data to file in chunks

    print("File received and saved as 'received_file.enc'")

    # Send a confirmation message to the client
    conn.sendall(b"File received successfully")

    # Decrypt the received file (received_file.enc) into decrypt.txt
    command = [
        "openssl", "pkeyutl", "-decrypt", "-in", "received_file.enc",
        "-inkey", "myprivate.key", "-out", "decrypt.txt"
    ]
    subprocess.run(command, check=True)

    print("File decrypted and saved as 'decrypt.txt'")

    conn.close()

# Create and start server thread
server_thread = threading.Thread(target=start_server)
server_thread.start()


# In[ ]:


import socket
import subprocess

def send_file():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 65431))

    # Run OpenSSL command to encrypt message.txt into encrypt.enc
    command = [
        "openssl", "pkeyutl", "-encrypt", "-in", "message.txt",
        "-pubin", "-inkey", "mypublic.key", "-out", "encrypt.enc"
    ]
    subprocess.run(command, check=True)

    # Send the encrypted file content (encrypt.enc)
    with open("encrypt.enc", 'rb') as file:
        chunk = file.read(1024)
        while chunk:
            client_socket.sendall(chunk)
            chunk = file.read(1024)

    # Send an end-of-file marker to indicate the end of transmission
    client_socket.sendall(b'END')

    # Receive the server's confirmation
    data = client_socket.recv(1024)
    print(f"Received from server: {data.decode('utf-8')}")

    client_socket.close()

send_file()


# ### Digital signature

# In[5]:


import subprocess

# Command to generate the private key
generate_private_key = [
    "openssl", "genrsa", "-out", "myprivate.key", "2048"
]

# Command to generate the public key from the private key
generate_public_key = [
    "openssl", "rsa", "-in", "myprivate.key", "-pubout", "-out", "mypublic.key"
]

try:
    # Run the command to generate the private key
    subprocess.run(generate_private_key, check=True)
    print("Private key saved as 'myprivate.key'.")

    # Run the command to generate the public key
    subprocess.run(generate_public_key, check=True)
    print("Public key saved as 'mypublic.key'.")
except subprocess.CalledProcessError as e:
    print(f"An error occurred during key generation: {e}")


# In[ ]:


import socket
import subprocess

def verify_signature(message, signature):
    # Save the message to a file
    with open("message_server.txt", 'w') as file:
        file.write(message)

    # Save the received signature to a file
    with open("signature_received.bin", "wb") as sig_file:
        sig_file.write(signature)

    # Command to verify the digital signature using the public key
    verify_command = [
        "openssl", "dgst", "-sha256", "-verify", "mypublic.key", "-signature", "signature_received.bin", "message_server.txt"
    ]

    try:
        # Run the OpenSSL command to verify the signature
        subprocess.run(verify_command, check=True)
        print("Signature verification successful.")
    except subprocess.CalledProcessError as e:
        print("Signature verification failed.")

def server_program():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 65432))
    server_socket.listen(1)
    print("Server listening...")

    conn, addr = server_socket.accept()
    print(f"Connection from {addr}")

    # Receive the original message from the client
    message = conn.recv(1024).decode()
    print(f"Message received: {message}")

    # Receive the signature from the client
    signature = conn.recv(1024)

    # Verify the signature using the public key and the received message
    verify_signature(message, signature)

    conn.close()

# Create and start server thread
server_thread = threading.Thread(target=server_program)
server_thread.start()


# In[ ]:


import socket
import subprocess

def create_message_digest_and_sign(message):
    # Save the message to a file
    with open("message_client.txt", 'w') as file:
        file.write(message)

    # Command to create a message digest (hash) and sign it using the private key
    sign_command = [
        "openssl", "dgst", "-sha256", "-sign", "myprivate.key", "-out", "signature.bin", "message_client.txt"
    ]

    try:
        # Run the OpenSSL command to create the message digest and sign it
        subprocess.run(sign_command, check=True)
        print("Digital signature created and saved as 'signature.bin'.")

        # Read the digital signature from the file
        with open("signature.bin", "rb") as sig_file:
            signature = sig_file.read()

        return signature
    except subprocess.CalledProcessError as e:
        print(f"An error occurred during signature generation: {e}")
        return None

def client_program():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 65432))

    # Message to be sent
    message = "This is the original message."

    # Create the message digest and sign it using the private key
    signature = create_message_digest_and_sign(message)

    if signature:
        # Send the original message first
        client_socket.sendall(message.encode())

        # Then send the signature
        client_socket.sendall(signature)

    client_socket.close()

# Run the client program
client_program()


# ### Message digest

# In[ ]:


def calculate_message_digest(message):
    # Save the received message to a file
    with open("message_server.txt", 'w') as file:
        file.write(message)

    # Generate digest from the received message using OpenSSL
    generate_digest = [
        "openssl", "dgst", "-sha256", "-out", "digest_server.txt", "message_server.txt"
    ]

    try:
        subprocess.run(generate_digest, check=True)
        print("Digest calculated and saved as 'digest_server.txt'.")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred during digest calculation: {e}")

    # Read the calculated digest
    with open("digest_server.txt", "r") as digest_file:
        digest = digest_file.read().split("= ")[1].strip()
    return digest

def server_program():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 65432))
    server_socket.listen(1)
    print("Server listening...")

    conn, addr = server_socket.accept()
    print(f"Connection from {addr}")

    # Receive the message
    message = conn.recv(1024).decode()
    print(f"Received message: {message}")

    # Receive the digest
    received_digest = conn.recv(1024).decode()
    print(f"Received digest: {received_digest}")

    # Calculate the digest from the received message
    calculated_digest = calculate_message_digest(message)
    print(f"Calculated digest: {calculated_digest}")

    # Verify the digests
    if received_digest == calculated_digest:
        print("The message integrity is verified!")
    else:
        print("Message integrity verification failed!")

    conn.close()

# Create and start server thread
server_thread = threading.Thread(target=server_program)
server_thread.start()


# In[ ]:


import socket
import subprocess

def create_message_digest(message):
    # Write the message to a file
    with open("message_client.txt", 'w') as file:
        file.write(message)

    # Generate message digest using OpenSSL
    generate_digest = [
        "openssl", "dgst", "-sha256", "-out", "digest_client.txt", "message_client.txt"
    ]

    try:
        subprocess.run(generate_digest, check=True)
        print("Message digest generated and saved as 'digest_client.txt'.")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred during digest generation: {e}")

    # Read the generated digest
    with open("digest_client.txt", "r") as digest_file:
        digest = digest_file.read().split("= ")[1].strip()
    return digest

def client_program():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 65432))

    # Original message to send
    message = "This is a secret message."

    # Create the digest
    digest = create_message_digest(message)

    # Send the message
    client_socket.send(message.encode())
    print(f"Sent message: {message}")

    # Send the digest
    client_socket.send(digest.encode())
    print(f"Sent digest: {digest}")

    client_socket.close()

# Run the client program
client_program()


# In[6]:


#Certificate


# In[ ]:


openssl req -x509 -key myprivate.key -sha256 -days 365 -out test_1.cer

openssl x509 -in test_1.cer -pubkey -noout -out key_x509.key


# In[ ]:


import subprocess

command = [
    'openssl', 'x509', '-in', 'test_1.cer', '-pubkey', '-noout', '-out', 'key.key'
]

subprocess.run(command, check=True)


# In[7]:


import subprocess

# Step 1: Generate Private Key
def generate_private_key():
    try:
        subprocess.run(["openssl", "genrsa", "-out", "myserver.key", "2048"], check=True)
        print("Private key saved as 'myserver.key'.")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred during private key generation: {e}")

# Step 2: Generate Certificate Signing Request (CSR)
def generate_csr():
    try:
        subprocess.run([
            "openssl", "req", "-new", "-key", "myserver.key", 
            "-out", "myserver.csr", 
            "-subj", "/C=US/ST=California/L=SanFrancisco/O=MyOrganization/CN=myserver.com"
        ], check=True)
        print("Certificate Signing Request saved as 'myserver.csr'.")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred during CSR generation: {e}")

# Step 3: Generate Self-Signed Certificate
def generate_self_signed_cert():
    try:
        subprocess.run([
            "openssl", "x509", "-req", "-days", "365", 
            "-in", "myserver.csr", "-signkey", "myserver.key", "-out", "myserver.crt"
        ], check=True)
        print("Self-signed certificate saved as 'myserver.crt'.")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred during certificate generation: {e}")

# Run all the steps
generate_private_key()
generate_csr()
generate_self_signed_cert()


# In[8]:


pip install cryptography


# In[9]:


from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate a private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Save the private key to a file
with open("myserver.key", "wb") as key_file:
    key_file.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

print("Private key saved as 'myserver.key'.")


# In[10]:


from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

# Create CSR
csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyOrganization"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"myserver.com"),
])).sign(private_key, hashes.SHA256())

# Save CSR to a file
with open("myserver.csr", "wb") as csr_file:
    csr_file.write(csr.public_bytes(serialization.Encoding.PEM))

print("CSR saved as 'myserver.csr'.")


# In[11]:


# Generate a self-signed certificate (valid for 1 year)
certificate = (
    x509.CertificateBuilder()
    .subject_name(csr.subject)
    .issuer_name(csr.subject)  # Self-signed, so issuer is the same as subject
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(private_key, hashes.SHA256())
)

# Save the certificate to a file
with open("myserver.crt", "wb") as cert_file:
    cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))

print("Self-signed certificate saved as 'myserver.crt'.")


# In[12]:


# Open and read the private key file
with open("myserver.key", "r") as key_file:
    private_key_content = key_file.read()

print("Private Key:")
print(private_key_content)


# In[13]:


# Open and read the CSR file
with open("myserver.csr", "r") as csr_file:
    csr_content = csr_file.read()

print("\nCertificate Signing Request (CSR):")
print(csr_content)


# In[14]:


# Open and read the certificate file
with open("myserver.crt", "r") as cert_file:
    certificate_content = cert_file.read()

print("\nSelf-Signed Certificate:")
print(certificate_content)


# In[ ]:




