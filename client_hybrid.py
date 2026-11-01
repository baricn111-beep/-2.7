import socket
import os

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from cryptography.fernet import Fernet, InvalidToken

HOST = "127.0.0.1"
PORT = 678


# ========== NETWORK FRAMING ==========
def recv_exact(sock, size):
    """Read exactly size bytes, unless the connection closes."""
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly.")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_frame(sock, payload):
    """Send one length-prefixed payload."""
    sock.sendall(len(payload).to_bytes(8, "big") + payload)


def recv_frame(sock):
    """Receive one length-prefixed payload."""
    size = int.from_bytes(recv_exact(sock, 8), "big")
    if size > 100_000_000:
        raise ValueError("Incoming message is too large.")
    return recv_exact(sock, size)


# ========== HYBRID ENCRYPTION HANDSHAKE ==========
def establish_encryption(sock):
    """
    Receive the server's RSA public key, create a Fernet key,
    and send that symmetric key encrypted with RSA-OAEP.
    """
    public_key_data = recv_frame(sock)
    public_key = RSA.import_key(public_key_data)

    symmetric_key = Fernet.generate_key()
    rsa_cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    encrypted_symmetric_key = rsa_cipher.encrypt(symmetric_key)
    send_frame(sock, encrypted_symmetric_key)

    fernet = Fernet(symmetric_key)
    ready_message = fernet.decrypt(recv_frame(sock)).decode("utf-8")
    print("[CLIENT]", ready_message)
    return fernet


def send_encrypted(sock, fernet, data):
    send_frame(sock, fernet.encrypt(data))


def recv_decrypted(sock, fernet):
    return fernet.decrypt(recv_frame(sock))


def receive_file(sock, fernet):
    """Receive screenshot bytes, which are encrypted in transit."""
    data = recv_decrypted(sock, fernet)

    if data.startswith(b"ERROR"):
        print("Server response:", data.decode("utf-8", errors="replace"))
        return

    filename = "received_screenshot.jpg"
    with open(filename, "wb") as file:
        file.write(data)
    print(f"[CLIENT] Screenshot saved to {os.path.abspath(filename)} ({len(data)} bytes)")


def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_socket.connect((HOST, PORT))
        fernet = establish_encryption(client_socket)

        print(
            "Available commands: "
            "DIR <path> | DELETE <file> | COPY <src> <dst> | "
            "EXECUTE <path> | TAKE_SCREENSHOT | SEND_PHOTO | EXIT"
        )

        while True:
            cmd = input("Enter command: ").strip()
            if not cmd:
                continue

            send_encrypted(client_socket, fernet, cmd.encode("utf-8"))

            if cmd.upper() == "SEND_PHOTO":
                receive_file(client_socket, fernet)
                continue

            response = recv_decrypted(client_socket, fernet)
            print("Server response:", response.decode("utf-8", errors="replace"))

            if cmd.upper() == "EXIT":
                break

    except (ConnectionError, OSError, ValueError, InvalidToken) as error:
        print("Connection or encryption error:", error)
    finally:
        client_socket.close()
        print("Disconnected from server.")


if __name__ == "__main__":
    main()
