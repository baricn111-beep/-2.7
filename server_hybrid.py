import socket
import logging
import subprocess
import threading
import os
import shlex
import shutil

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from cryptography.fernet import Fernet, InvalidToken

# ========== CONFIGURATION ==========
SERVER_NAME = "MyServer"
HOST = "127.0.0.1"
PORT = 678
LOG_FILE = "server_log.txt"
SCREENSHOT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "screenshot.jpg")

# ========== LOGGING SETUP ==========
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='[%(levelname)s] %(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)


# ========== NETWORK FRAMING ==========
# Every message starts with an 8-byte length header, then the exact payload.
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
    # Avoid accidentally accepting an unreasonable frame size.
    if size > 100_000_000:
        raise ValueError("Incoming message is too large.")
    return recv_exact(sock, size)


# ========== HYBRID ENCRYPTION HANDSHAKE ==========
def establish_encryption(client_socket):
    """
    RSA-OAEP (asymmetric) securely transfers a fresh Fernet key.
    Fernet (symmetric) is then used for all application messages.
    """
    rsa_private_key = RSA.generate(2048)
    rsa_public_key = rsa_private_key.publickey()

    # Send the public RSA key to the client.
    send_frame(client_socket, rsa_public_key.export_key(format="PEM"))

    # Receive the Fernet key encrypted with the public RSA key.
    encrypted_symmetric_key = recv_frame(client_socket)
    rsa_cipher = PKCS1_OAEP.new(rsa_private_key, hashAlgo=SHA256)
    symmetric_key = rsa_cipher.decrypt(encrypted_symmetric_key)

    fernet = Fernet(symmetric_key)
    logging.info("Hybrid encryption handshake completed.")
    return fernet


def send_encrypted(sock, fernet, data):
    """Encrypt bytes with Fernet, then send them as a framed message."""
    send_frame(sock, fernet.encrypt(data))


def recv_decrypted(sock, fernet):
    """Receive one framed Fernet token and decrypt it to bytes."""
    token = recv_frame(sock)
    return fernet.decrypt(token)


# ========== COMMAND FUNCTIONS ==========
def cmd_photo_send():
    """Return the saved screenshot as bytes, or an error message."""
    try:
        if not os.path.exists(SCREENSHOT_PATH):
            return b"ERROR: screenshot file not found"

        with open(SCREENSHOT_PATH, "rb") as file:
            return file.read()
    except Exception as error:
        return f"ERROR sending screenshot: {error}".encode("utf-8")


def cmd_screenshot():
    """Take a screenshot of the server's screen and save it beside this script."""
    try:
        import pyautogui
        image = pyautogui.screenshot()
        image.save(SCREENSHOT_PATH)
        return f"Screenshot saved: {SCREENSHOT_PATH}"
    except Exception as error:
        return f"Screenshot failed: {error}"


def cmd_copy(src, dst):
    """Copy a file from source path to destination path."""
    try:
        if not src or not dst:
            return "Error: COPY requires source and destination paths.\nExample: COPY C:\\a.txt C:\\b.txt"

        src = src.strip().strip('"')
        dst = dst.strip().strip('"')

        if not os.path.exists(src):
            return f"Error: Source file not found -> {src}"
        if os.path.isdir(src):
            return f"Error: Source path is a directory -> {src}"

        shutil.copy(src, dst)
        return f"File copied successfully:\nFROM: {src}\nTO:   {dst}"
    except PermissionError:
        return f"Error: Permission denied while copying to -> {dst}"
    except Exception as error:
        return f"Error copying file: {error}"


def cmd_delete(file_path):
    """Delete a file at the specified path."""
    try:
        if not file_path:
            return "Error: You must provide a file path."
        file_path = file_path.strip('"')

        if not os.path.exists(file_path):
            logging.warning("DELETE: file not found: %s", file_path)
            return f"Error: File not found -> {file_path}"
        if os.path.isdir(file_path):
            return f"Error: {file_path} is a directory, not a file."

        os.remove(file_path)
        logging.info("File deleted successfully: %s", file_path)
        return f"File deleted successfully: {file_path}"
    except Exception as error:
        logging.error("DELETE command failed for %s: %s", file_path, error)
        return f"Error deleting file: {error}"


def cmd_execute(program_path):
    """Execute a program on the server machine."""
    try:
        if not program_path:
            return "Error: You must provide a program path."
        program_path = program_path.strip('"')
        if not os.path.exists(program_path):
            return f"Error: Program not found -> {program_path}"

        result = subprocess.call(program_path)
        if result == 0:
            return f"Program executed successfully: {program_path}"
        return f"Error: Program returned exit code {result}"
    except Exception as error:
        return f"Execution failed: {error}"


def cmd_dir(path):
    """List files and folders in a directory."""
    try:
        if not path:
            return "Error: You must provide a directory path."
        if not os.path.exists(path):
            logging.warning("DIR: path not found: %s", path)
            return f"Error: Path not found -> {path}"

        items = os.listdir(path)
        if not items:
            return f"The directory {path} is empty."
        logging.info("DIR command executed successfully for %s", path)
        return f"Contents of {path}:\n" + "\n".join(items)
    except Exception as error:
        logging.error("DIR command failed for %s: %s", path, error)
        return f"Error reading directory: {error}"


def cmd_unknown(command):
    logging.warning("Unknown command received: %s", command)
    return f"Unknown command: {command}"


# ========== CLIENT HANDLER ==========
def handle_client(client_socket, client_address):
    logging.info("Client connected: %s", client_address)
    print(f"[+] Client connected: {client_address}")

    try:
        fernet = establish_encryption(client_socket)
        send_encrypted(client_socket, fernet, b"READY: encrypted connection established")

        while True:
            command_line = recv_decrypted(client_socket, fernet).decode("utf-8").strip()
            if not command_line:
                send_encrypted(client_socket, fernet, b"Error: Empty command.")
                continue

            logging.info("Encrypted command received from %s", client_address)
            print(f"[{client_address}] Encrypted command received.")

            try:
                parts = shlex.split(command_line)
            except ValueError:
                send_encrypted(client_socket, fernet, b"Error: Invalid command format.")
                continue

            command = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""

            if command == "DIR":
                response = cmd_dir(arg).encode("utf-8")
            elif command == "DELETE":
                response = cmd_delete(arg).encode("utf-8")
            elif command == "EXIT":
                response = cmd_exit().encode("utf-8")
            elif command == "EXECUTE":
                response = cmd_execute(arg).encode("utf-8")
            elif command == "SEND_PHOTO":
                response = cmd_photo_send()
            elif command == "TAKE_SCREENSHOT":
                response = cmd_screenshot().encode("utf-8")
            elif command == "COPY":
                if len(parts) < 3:
                    response = b"Error: COPY requires source and destination paths."
                else:
                    response = cmd_copy(parts[1], parts[2]).encode("utf-8")
            else:
                response = cmd_unknown(command).encode("utf-8")

            # Text replies and screenshot bytes are both encrypted with Fernet.
            send_encrypted(client_socket, fernet, response)

            if command == "EXIT":
                break

    except (ConnectionError, OSError) as error:
        logging.info("Client connection ended (%s): %s", client_address, error)
    except InvalidToken:
        logging.warning("Invalid encrypted message from %s", client_address)
    except Exception as error:
        logging.exception("Error handling client %s: %s", client_address, error)
    finally:
        client_socket.close()
        logging.info("Client disconnected: %s", client_address)
        print(f"[-] Client disconnected: {client_address}")


def cmd_exit():
    return "Goodbye!"


# ========== MAIN SERVER LOOP ==========
def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)

    print(f"[+] {SERVER_NAME} listening on {HOST}:{PORT}")
    logging.info("%s started on %s:%s", SERVER_NAME, HOST, PORT)

    try:
        while True:
            client_socket, client_address = server.accept()
            thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address),
                daemon=True
            )
            thread.start()
            logging.info("Thread started for %s", client_address)
    except KeyboardInterrupt:
        print("\n[+] Server shutting down.")
    finally:
        server.close()


if __name__ == "__main__":
    main()
