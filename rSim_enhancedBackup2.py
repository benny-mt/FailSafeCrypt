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
PASSWORD = "l"  # Set your password here
SALT_FILE = os.path.join(TARGET_FOLDER, ".encryption_salt")  # File to store salt

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
            'filename': [],
            'operation': [],
            'checksum_match': [],
            'entropy_change': [],
            'processing_time': [],
            'success': [],
            'backup_success': [],
            'error_message': []
        }
        self.start_time = None
        self.operation = None
        self.original_checksums = {}  # Store original checksums for comparison
    
    def start_operation(self, operation: str):
        self.operation = operation
        self.start_time = time.time()
    
    def store_original_checksum(self, file_path: str):
        """Store original checksum before encryption"""
        self.original_checksums[os.path.basename(file_path)] = self.calculate_checksum(file_path)
    
    def record_file_metrics(self, original_path: str, processed_path: str = None, 
                          success: bool = True, backup_success: bool = True,
                          error_msg: str = ""):
        try:
            filename = os.path.basename(original_path)
            
            # For decryption, get the original filename (without .encrypted)
            if self.operation == "decryption":
                original_filename = filename[:-len(ENCRYPTED_EXTENSION)] if filename.endswith(ENCRYPTED_EXTENSION) else filename
                orig_checksum = self.original_checksums.get(original_filename, "")
            else:
                orig_checksum = self.original_checksums.get(filename, "")
            
            # Calculate current checksum and entropy
            proc_checksum = self.calculate_checksum(processed_path) if processed_path and os.path.exists(processed_path) else ""
            orig_entropy = self.calculate_entropy(original_path) if os.path.exists(original_path) else 0.0
            proc_entropy = self.calculate_entropy(processed_path) if processed_path and os.path.exists(processed_path) else 0.0
            
            # Determine checksum match status
            checksum_match = "N/A"
            if self.operation == "decryption" and success and orig_checksum and proc_checksum:
                checksum_match = "Match" if proc_checksum == orig_checksum else "Mismatch"
            
            # Determine entropy change
            entropy_change = "N/A"
            if orig_entropy and proc_entropy:
                if self.operation == "encryption":
                    entropy_change = "Increased" if proc_entropy > orig_entropy else "No change"
                else:
                    entropy_change = "Restored" if abs(proc_entropy - orig_entropy) < 0.1 else "High"
            
            proc_time = time.time() - self.start_time if self.start_time else 0
            
            # Record simplified metrics
            self.metrics['filename'].append(filename)
            self.metrics['operation'].append(self.operation)
            self.metrics['checksum_match'].append(checksum_match)
            self.metrics['entropy_change'].append(entropy_change)
            self.metrics['processing_time'].append(f"{proc_time:.4f}")
            self.metrics['success'].append(success)
            self.metrics['backup_success'].append(backup_success)
            self.metrics['error_message'].append(error_msg)
            
        except Exception as e:
            logging.error(f"Error recording metrics for {original_path}: {str(e)}")
    
    def calculate_checksum(self, filepath: str) -> str:
        if not filepath or not os.path.exists(filepath):
            return ""
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
        if not filepath or not os.path.exists(filepath):
            return 0.0
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
                if p > 0:  # Avoid log(0)
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
        avg_time = sum(float(t) for t in self.metrics['processing_time']) / total_files if total_files > 0 else 0
        
        logging.info("\n=== Simulation Metrics Summary ===")
        logging.info(f"Operation: {self.operation}")
        logging.info(f"Total files processed: {total_files}")
        logging.info(f"Success rate: {success_count}/{total_files} ({success_count/total_files*100:.2f}%)")
        logging.info(f"Average processing time per file: {avg_time:.4f} seconds")
        
        if self.operation == "decryption":
            matches = sum(1 for m in self.metrics['checksum_match'] if m == "Match")
            mismatches = sum(1 for m in self.metrics['checksum_match'] if m == "Mismatch")
            logging.info(f"Checksum matches: {matches}/{total_files}")
            logging.info(f"Checksum mismatches: {mismatches}/{total_files}")
        
        entropy_changes = {
            "Increased": sum(1 for m in self.metrics['entropy_change'] if m == "Increased"),
            "Restored": sum(1 for m in self.metrics['entropy_change'] if m == "Restored"),
            "High": sum(1 for m in self.metrics['entropy_change'] if m == "High")
        }
        logging.info("\nEntropy changes:")
        for change, count in entropy_changes.items():
            if count > 0:
                logging.info(f"- {change}: {count} files")

# --- Core Simulator Functions ---
def generate_key(password: str, salt: bytes = None) -> bytes:
    if not salt:
        salt = get_random_bytes(16)
        # Save salt for decryption
        with open(SALT_FILE, 'wb') as f:
            f.write(salt)
    key = scrypt(password.encode(), salt, key_len=32, N=2**20, r=8, p=1)
    return key, salt

def load_salt():
    try:
        with open(SALT_FILE, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        logging.error("No salt file found. Encryption must be performed first.")
        sys.exit(1)

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

def get_encrypted_files():
    encrypted_files = []
    for root, _, files in os.walk(TARGET_FOLDER):
        for file in files:
            if file.endswith(ENCRYPTED_EXTENSION):
                file_path = os.path.join(root, file)
                encrypted_files.append(file_path)
                logging.debug(f"Found encrypted file: {file_path}")
    return encrypted_files

def encrypt_file(file_path: str, key: bytes, metrics: SimulationMetrics) -> bool:
    encrypted_path = file_path + ENCRYPTED_EXTENSION
    success = False
    
    try:
        logging.info(f"Encrypting {file_path}")
        
        # Store original checksum before encryption
        metrics.store_original_checksum(file_path)
        
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

        if os.path.exists(encrypted_path) and os.path.getsize(encrypted_path) > 0:
            success = True
            metrics.record_file_metrics(
                original_path=file_path,
                processed_path=encrypted_path,
                success=True,
                backup_success=True
            )
            os.remove(file_path)
            logging.info(f"Successfully encrypted: {file_path}")
        else:
            raise RuntimeError("Encrypted file not created or is empty")

    except Exception as e:
        logging.error(f"Failed to encrypt {file_path}: {str(e)}")
        metrics.record_file_metrics(
            original_path=file_path,
            processed_path=encrypted_path if os.path.exists(encrypted_path) else None,
            success=False,
            backup_success=True,
            error_msg=str(e)
        )
        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)
    
    return success

def decrypt_file(encrypted_path: str, key: bytes, metrics: SimulationMetrics) -> bool:
    original_path = encrypted_path[:-len(ENCRYPTED_EXTENSION)]
    success = False
    
    try:
        logging.info(f"Decrypting {encrypted_path}")
        
        with open(encrypted_path, 'rb') as f_in:
            iv = f_in.read(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            
            with open(original_path, 'wb') as f_out:
                while True:
                    chunk = f_in.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    decrypted = cipher.decrypt(chunk)
                    if f_in.tell() == os.path.getsize(encrypted_path):
                        decrypted = unpad(decrypted)
                    f_out.write(decrypted)

        if os.path.exists(original_path) and os.path.getsize(original_path) > 0:
            success = True
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
        metrics.record_file_metrics(
            original_path=encrypted_path,
            processed_path=original_path if os.path.exists(original_path) else None,
            success=False,
            backup_success=True,
            error_msg=str(e)
        )
        if os.path.exists(original_path):
            os.remove(original_path)
    
    return success

def full_cycle_operation():
    """Perform both encryption and decryption in sequence"""
    encryption_metrics = SimulationMetrics()
    
    # Generate or load encryption key
    if os.path.exists(SALT_FILE):
        salt = load_salt()
        key, _ = generate_key(PASSWORD, salt)
    else:
        key, _ = generate_key(PASSWORD)
    
    # Get target files
    target_files = get_target_files()
    if not target_files:
        logging.warning("No target files found for encryption")
        return
    
    try:
        # --- Encryption Phase ---
        logging.info("\n=== Starting Encryption Phase ===")
        encryption_metrics.start_operation("encryption")
        check_resources(target_files)
        create_backups(target_files)
        
        encryption_success = True
        for file_path in target_files:
            if not encrypt_file(file_path, key, encryption_metrics):
                encryption_success = False
                logging.warning(f"Failed to encrypt {file_path}, stopping...")
                break
        
        if not encryption_success:
            logging.error("Encryption failed - restoring original files")
            restore_files(target_files)
            return
        
        # --- Decryption Phase ---
        logging.info("\n=== Starting Decryption Phase ===")
        encrypted_files = get_encrypted_files()
        if not encrypted_files:
            logging.warning("No encrypted files found for decryption")
            return
        
        # Create new metrics object but preserve the original checksums
        decryption_metrics = SimulationMetrics()
        decryption_metrics.original_checksums = encryption_metrics.original_checksums
        decryption_metrics.start_operation("decryption")
        
        decryption_success = True
        for file_path in encrypted_files:
            if not decrypt_file(file_path, key, decryption_metrics):
                decryption_success = False
                logging.warning(f"Failed to decrypt {file_path}, stopping...")
                break
        
        if not decryption_success:
            logging.error("Decryption failed - some files may remain encrypted")
        
        # Combine metrics from both phases
        combined_metrics = SimulationMetrics()
        combined_metrics.metrics = {key: encryption_metrics.metrics[key] + decryption_metrics.metrics[key] 
                                  for key in encryption_metrics.metrics.keys()}
        
    except Exception as e:
        logging.error(f"Critical error during operation: {e}")
        if os.path.exists(BACKUP_DIR):
            logging.info("Attempting to restore files from backup")
            restore_files(target_files)
        else:
            logging.error("No backups available for restoration")
        return
    finally:
        clean_up_backups()
    
    # Save and print combined metrics
    combined_metrics.save_to_csv()
    combined_metrics.print_summary()

# --- Main ---
if __name__ == "__main__":
    print("=== Automated Encryption/Decryption Tool ===")
    print("Performing full encryption/decryption cycle...")
    full_cycle_operation()