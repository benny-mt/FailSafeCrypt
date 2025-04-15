#!/usr/bin/env python3
import os
import time
import shutil
import hashlib
import csv
import math
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
import getpass
import logging
import sys

# --- Configuration ---
TARGET_FOLDER = "/home/chicken/Documents/Research/Workspace/mySim_logs/mySim_attack"
FILE_EXTENSIONS_TO_ENCRYPT = ('.txt', '.docx', '.pdf')
ENCRYPTED_EXTENSION = '.encrypted'
METRICS_FILE = "simulation_metrics.csv"
BACKUP_DIR = os.path.join(TARGET_FOLDER, ".backup_encryption")
CHUNK_SIZE = 1 * 1024 * 1024  # 1MB chunks for better handling

# --- Setup Logging ---
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('rSim_debug.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

class SimulationMetrics:
    def __init__(self):
        self.metrics = {
            'operation': [],
            'filename': [],
            'original_size': [],
            'processed_size': [],
            'original_checksum': [],
            'processed_checksum': [],
            'original_entropy': [],
            'processed_entropy': [],
            'processing_time': [],
            'success': [],
            'backup_success': [],
            'error_message': []
        }
        self.start_time = None
        self.operation = None
    
    def start_operation(self, operation: str):
        self.operation = operation
        self.start_time = time.time()
    
    def record_file_metrics(self, original_path: str, processed_path: str = None, 
                          success: bool = True, backup_success: bool = True,
                          error_msg: str = ""):
        try:
            # Get basic file info before any file operations
            filename = os.path.basename(original_path)
            original_size = os.path.getsize(original_path) if os.path.exists(original_path) else 0
            orig_checksum = self.calculate_checksum(original_path) if os.path.exists(original_path) else ""
            orig_entropy = self.calculate_entropy(original_path) if os.path.exists(original_path) else 0.0
            
            # Processed file metrics
            proc_size = os.path.getsize(processed_path) if processed_path and os.path.exists(processed_path) else 0
            proc_checksum = self.calculate_checksum(processed_path) if processed_path and os.path.exists(processed_path) else ""
            proc_entropy = self.calculate_entropy(processed_path) if processed_path and os.path.exists(processed_path) else 0.0
            
            proc_time = time.time() - self.start_time if self.start_time else 0
            
            # Record all metrics
            self.metrics['operation'].append(self.operation)
            self.metrics['filename'].append(filename)
            self.metrics['original_size'].append(original_size)
            self.metrics['processed_size'].append(proc_size)
            self.metrics['original_checksum'].append(orig_checksum)
            self.metrics['processed_checksum'].append(proc_checksum)
            self.metrics['original_entropy'].append(orig_entropy)
            self.metrics['processed_entropy'].append(proc_entropy)
            self.metrics['processing_time'].append(proc_time)
            self.metrics['success'].append(success)
            self.metrics['backup_success'].append(backup_success)
            self.metrics['error_message'].append(error_msg)
            
        except Exception as e:
            logging.error(f"Error recording metrics for {original_path}: {str(e)}")
    
    def calculate_checksum(self, filepath: str) -> str:
        hash_sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            logging.error(f"Error calculating checksum for {filepath}: {str(e)}")
            return ""

    def calculate_entropy(self, filepath: str) -> float:
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            
            if not data:
                return 0.0
            
            entropy = 0.0
            size = len(data)
            freq_dict = {}
            
            for byte in data:
                freq_dict[byte] = freq_dict.get(byte, 0) + 1
            
            for freq in freq_dict.values():
                p = freq / size
                entropy -= p * math.log2(p)
            
            return entropy
        
        except Exception as e:
            logging.error(f"Error calculating entropy for {filepath}: {str(e)}")
            return 0.0
    
    def save_to_csv(self, filename: str = METRICS_FILE):
        try:
            with open(filename, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(self.metrics.keys())
                for i in range(len(self.metrics['filename'])):
                    row = [self.metrics[key][i] for key in self.metrics.keys()]
                    writer.writerow(row)
            logging.info(f"Metrics saved to {filename}")
        except Exception as e:
            logging.error(f"Error saving metrics to CSV: {str(e)}")
    
    def print_summary(self):
        if not self.metrics['filename']:
            logging.warning("No metrics collected yet.")
            return
        
        total_files = len(self.metrics['filename'])
        success_count = sum(self.metrics['success'])
        fail_count = total_files - success_count
        backup_success = sum(self.metrics['backup_success'])
        avg_time = sum(self.metrics['processing_time']) / total_files if total_files > 0 else 0
        
        logging.info("\n=== Simulation Metrics Summary ===")
        logging.info(f"Operation: {self.operation}")
        logging.info(f"Total files processed: {total_files}")
        logging.info(f"Success rate: {success_count}/{total_files} ({success_count/total_files*100:.2f}%)")
        logging.info(f"Backup success rate: {backup_success}/{total_files} ({backup_success/total_files*100:.2f}%)")
        logging.info(f"Average processing time per file: {avg_time:.4f} seconds")
        
        # Show checksum changes for failed operations
        logging.info("\nFiles with checksum verification issues:")
        for i in range(total_files):
            if not self.metrics['success'][i] or (
                self.metrics['processed_checksum'][i] and 
                self.metrics['original_checksum'][i] == self.metrics['processed_checksum'][i]
            ):
                logging.info(f"- {self.metrics['filename'][i]}: {self.metrics['error_message'][i] or 'Checksum unchanged after operation'}")
        
        # Show entropy changes
        logging.info("\nEntropy changes (higher = more random):")
        for i in range(min(5, total_files)):  # Show first 5 files as sample
            if self.metrics['processed_entropy'][i]:
                change = self.metrics['processed_entropy'][i] - self.metrics['original_entropy'][i]
                logging.info(f"- {self.metrics['filename'][i]}: {change:+.4f}")

# --- Core Simulator Functions ---
def generate_key(password: str, salt: bytes = None) -> bytes:
    if not salt:
        salt = get_random_bytes(16)
    key = scrypt(password.encode(), salt, key_len=32, N=2**20, r=8, p=1)
    return key, salt

def pad(data: bytes) -> bytes:
    block_size = AES.block_size
    padding_length = block_size - len(data) % block_size
    return data + bytes([padding_length] * padding_length)

def unpad(data: bytes) -> bytes:
    padding_length = data[-1]
    return data[:-padding_length]

def check_resources(target_files):
    total_size = sum(os.path.getsize(f) for f in target_files)
    free_space = shutil.disk_usage(os.path.dirname(target_files[0])).free
    if free_space < total_size * 2:
        raise RuntimeError("Insufficient disk space for backup operation")

def create_backups(target_files):
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    for file_path in target_files:
        backup_path = os.path.join(BACKUP_DIR, os.path.basename(file_path))
        shutil.copy2(file_path, backup_path)
        logging.debug(f"Created backup: {backup_path}")

def restore_files(target_files):
    for file_path in target_files:
        backup_path = os.path.join(BACKUP_DIR, os.path.basename(file_path))
        if os.path.exists(backup_path):
            shutil.copy2(backup_path, file_path)
            logging.debug(f"Restored from backup: {file_path}")
    shutil.rmtree(BACKUP_DIR)
    logging.info("Backup directory cleaned")

def clean_up_backups():
    if os.path.exists(BACKUP_DIR):
        shutil.rmtree(BACKUP_DIR)
        logging.info("Cleaned up backup directory")

def get_target_files():
    target_files = []
    for root, _, files in os.walk(TARGET_FOLDER):
        for file in files:
            if file.endswith(FILE_EXTENSIONS_TO_ENCRYPT) and not file.startswith('.'):
                file_path = os.path.join(root, file)
                target_files.append(file_path)
                logging.debug(f"Found target file: {file_path}")
    return target_files

# --- Enhanced Crypto Operations with Metrics ---
def encrypt_file(file_path: str, key: bytes, metrics: SimulationMetrics) -> bool:
    encrypted_path = file_path + ENCRYPTED_EXTENSION
    success = False
    
    try:
        # Get file info before encryption
        original_size = os.path.getsize(file_path)
        logging.info(f"Encrypting {file_path} ({original_size/1024:.2f} KB)")
        
        # Perform encryption
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        with open(file_path, 'rb') as f_in, open(encrypted_path, 'wb') as f_out:
            f_out.write(iv)
            while True:
                chunk = f_in.read(CHUNK_SIZE)
                if not chunk:
                    break
                if len(chunk) % AES.block_size != 0:
                    chunk = pad(chunk)
                f_out.write(cipher.encrypt(chunk))

        # Verify encryption
        if os.path.exists(encrypted_path) and os.path.getsize(encrypted_path) > 0:
            success = True
            # Record metrics BEFORE deleting original
            metrics.record_file_metrics(
                original_path=file_path,
                processed_path=encrypted_path,
                success=True,
                backup_success=True
            )
            # Only delete original after successful encryption and metrics recording
            os.remove(file_path)
            logging.info(f"Successfully encrypted: {file_path}")
        else:
            raise RuntimeError("Encrypted file not created or is empty")

    except Exception as e:
        logging.error(f"Failed to encrypt {file_path}: {str(e)}")
        # Record failed metrics
        metrics.record_file_metrics(
            original_path=file_path,
            processed_path=encrypted_path if os.path.exists(encrypted_path) else None,
            success=False,
            backup_success=True,
            error_msg=str(e)
        )
        # Clean up failed encryption
        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)
    
    return success

def decrypt_file(encrypted_path: str, key: bytes, metrics: SimulationMetrics) -> bool:
    original_path = encrypted_path[:-len(ENCRYPTED_EXTENSION)]
    success = False
    
    try:
        # Get file info before decryption
        encrypted_size = os.path.getsize(encrypted_path)
        logging.info(f"Decrypting {encrypted_path} ({encrypted_size/1024:.2f} KB)")
        
        # Perform decryption
        with open(encrypted_path, 'rb') as f_in:
            iv = f_in.read(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            
            with open(original_path, 'wb') as f_out:
                while True:
                    chunk = f_in.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    decrypted = cipher.decrypt(chunk)
                    # Only unpad the last chunk
                    if f_in.tell() == encrypted_size:
                        decrypted = unpad(decrypted)
                    f_out.write(decrypted)

        # Verify decryption
        if os.path.exists(original_path) and os.path.getsize(original_path) > 0:
            success = True
            # Record metrics BEFORE deleting encrypted file
            metrics.record_file_metrics(
                original_path=encrypted_path,
                processed_path=original_path,
                success=True,
                backup_success=True
            )
            os.remove(encrypted_path)
            logging.info(f"Successfully decrypted: {encrypted_path}")
        else:
            raise RuntimeError("Decrypted file not created or is empty")

    except Exception as e:
        logging.error(f"Failed to decrypt {encrypted_path}: {str(e)}")
        # Record failed metrics
        metrics.record_file_metrics(
            original_path=encrypted_path,
            processed_path=original_path if os.path.exists(original_path) else None,
            success=False,
            backup_success=True,
            error_msg=str(e)
        )
        # Clean up failed decryption
        if os.path.exists(original_path):
            os.remove(original_path)
    
    return success

# --- Main Operations ---
def simulate_attack():
    metrics = SimulationMetrics()
    metrics.start_operation("encryption")
    
    password = getpass.getpass("Enter encryption password: ")
    key, salt = generate_key(password)
    logging.info(f"Encryption Key Generated (Salt: {salt.hex()})")
    
    target_files = get_target_files()
    if not target_files:
        logging.warning("No target files found for encryption")
        return
    
    try:
        check_resources(target_files)
        create_backups(target_files)
        
        all_success = True
        for file_path in target_files:
            if not encrypt_file(file_path, key, metrics):
                all_success = False
                logging.warning(f"Failed to encrypt {file_path}, stopping...")
                break
        
        if all_success:
            logging.info("All files encrypted successfully")
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
    finally:
        metrics.save_to_csv()
        metrics.print_summary()
        clean_up_backups()

def simulate_recovery():
    metrics = SimulationMetrics()
    metrics.start_operation("decryption")
    
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
                if decrypt_file(file_path, key, metrics):
                    success_count += 1
                else:
                    failure_count += 1
    
    logging.info(f"Decryption complete. Success: {success_count}, Failures: {failure_count}")
    metrics.save_to_csv()
    metrics.print_summary()
    clean_up_backups()

# --- Main ---
if __name__ == "__main__":
    print("=== Enhanced Ransomware Simulator with Metrics ===")
    print("1. Simulate Attack (Encrypt Files with Metrics)")
    print("2. Simulate Recovery (Decrypt Files with Metrics)")
    choice = input("Select mode (1/2): ").strip()
    
    try:
        if choice == "1":
            simulate_attack()
        elif choice == "2":
            simulate_recovery()
        else:
            print("Invalid choice. Exiting.")
    except KeyboardInterrupt:
        logging.warning("Operation cancelled by user")
        clean_up_backups()
        sys.exit(1)
    finally:
        clean_up_backups()