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
CHUNK_SIZE = 64 * 1024 * 1024  # 64MB chunks for better handling of large files
PASSWORD = "l"  # Set your password here
SALT_FILE = os.path.join(TARGET_FOLDER, ".encryption_salt")  # File to store salt
TEST_RUNS = 10  # Number of test runs to perform
PROGRESS_UPDATE_INTERVAL = 5  # Seconds between progress updates

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
            'error_message': [],
            'run_number': []  # Added to track which run each metric belongs to
        }
        self.start_time = None
        self.operation = None
        self.original_checksums = {}  # Store original checksums for comparison
        self.current_run = 0  # Track current run number
    
    def set_run_number(self, run_number: int):
        self.current_run = run_number
    
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
            self.metrics['run_number'].append(self.current_run)
            
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
                data = f.read(CHUNK_SIZE)  # Only read first chunk for entropy calculation
            
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
            # Check if file exists to determine if we need to write headers
            file_exists = os.path.isfile(filename)
            
            with open(filename, 'a', newline='') as csvfile:
                writer = csv.writer(csvfile)
                if not file_exists:
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
    # Need space for: original + backup + encrypted files
    if free_space < total_size * 3:
        raise RuntimeError(f"Insufficient disk space. Need {total_size*3/1024/1024:.2f} MB, have {free_space/1024/1024:.2f} MB")

def create_backups(target_files):
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    for file_path in target_files:
        try:
            file_size = os.path.getsize(file_path) / 1024 / 1024
            logging.info(f"Creating backup for {os.path.basename(file_path)} ({file_size:.2f} MB)")
            backup_path = os.path.join(BACKUP_DIR, os.path.basename(file_path))
            shutil.copy2(file_path, backup_path)
            logging.debug(f"Created backup: {backup_path}")
        except Exception as e:
            logging.error(f"Failed to create backup for {file_path}: {str(e)}")
            raise

def restore_files(target_files):
    for file_path in target_files:
        backup_path = os.path.join(BACKUP_DIR, os.path.basename(file_path))
        if os.path.exists(backup_path):
            try:
                shutil.copy2(backup_path, file_path)
                logging.debug(f"Restored from backup: {file_path}")
            except Exception as e:
                logging.error(f"Failed to restore {file_path} from backup: {str(e)}")
    try:
        shutil.rmtree(BACKUP_DIR)
        logging.info("Backup directory cleaned")
    except Exception as e:
        logging.error(f"Failed to clean up backup directory: {str(e)}")

def clean_up_backups():
    if os.path.exists(BACKUP_DIR):
        try:
            shutil.rmtree(BACKUP_DIR)
            logging.info("Cleaned up backup directory")
        except Exception as e:
            logging.error(f"Failed to clean up backup directory: {str(e)}")

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
        file_size = os.path.getsize(file_path)
        logging.info(f"Encrypting {os.path.basename(file_path)} (Size: {file_size/1024/1024:.2f} MB)")
        
        # Store original checksum before encryption
        metrics.store_original_checksum(file_path)
        
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        with open(file_path, 'rb') as f_in, open(encrypted_path, 'wb') as f_out:
            f_out.write(iv)
            bytes_processed = 0
            last_update = time.time()
            
            while True:
                chunk = f_in.read(CHUNK_SIZE)
                if not chunk:
                    break
                
                if len(chunk) % AES.block_size != 0:
                    chunk = pad(chunk)
                
                encrypted_chunk = cipher.encrypt(chunk)
                f_out.write(encrypted_chunk)
                
                # Progress tracking for large files
                bytes_processed += len(chunk)
                if time.time() - last_update > PROGRESS_UPDATE_INTERVAL:
                    progress = bytes_processed / file_size * 100
                    speed = (bytes_processed / (time.time() - last_update)) / 1024 / 1024
                    logging.info(f"Encryption progress: {progress:.1f}% - Speed: {speed:.2f} MB/s")
                    last_update = time.time()

        # Verify the encrypted file
        if os.path.exists(encrypted_path) and os.path.getsize(encrypted_path) > 0:
            success = True
            metrics.record_file_metrics(
                original_path=file_path,
                processed_path=encrypted_path,
                success=True,
                backup_success=True
            )
            try:
                os.remove(file_path)
                logging.info(f"Successfully encrypted: {file_path}")
            except Exception as e:
                logging.error(f"Failed to remove original file {file_path}: {str(e)}")
                success = False
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
            try:
                os.remove(encrypted_path)
            except Exception as e:
                logging.error(f"Failed to cleanup failed encryption output {encrypted_path}: {str(e)}")
    
    return success

def decrypt_file(encrypted_path: str, key: bytes, metrics: SimulationMetrics) -> bool:
    original_path = encrypted_path[:-len(ENCRYPTED_EXTENSION)]
    success = False
    
    try:
        file_size = os.path.getsize(encrypted_path)
        logging.info(f"Decrypting {os.path.basename(encrypted_path)} (Size: {file_size/1024/1024:.2f} MB)")
        
        with open(encrypted_path, 'rb') as f_in:
            iv = f_in.read(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            
            with open(original_path, 'wb') as f_out:
                bytes_processed = 0
                last_update = time.time()
                
                while True:
                    chunk = f_in.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    decrypted = cipher.decrypt(chunk)
                    if f_in.tell() == os.path.getsize(encrypted_path):
                        decrypted = unpad(decrypted)
                    f_out.write(decrypted)
                    
                    # Progress tracking for large files
                    bytes_processed += len(chunk)
                    if time.time() - last_update > PROGRESS_UPDATE_INTERVAL:
                        progress = bytes_processed / file_size * 100
                        speed = (bytes_processed / (time.time() - last_update)) / 1024 / 1024
                        logging.info(f"Decryption progress: {progress:.1f}% - Speed: {speed:.2f} MB/s")
                        last_update = time.time()

        # Verify the decrypted file
        if os.path.exists(original_path) and os.path.getsize(original_path) > 0:
            success = True
            metrics.record_file_metrics(
                original_path=encrypted_path,
                processed_path=original_path,
                success=True,
                backup_success=True
            )
            try:
                os.remove(encrypted_path)
                logging.info(f"Successfully decrypted: {encrypted_path}")
            except Exception as e:
                logging.error(f"Failed to remove encrypted file {encrypted_path}: {str(e)}")
                success = False
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
            try:
                os.remove(original_path)
            except Exception as e:
                logging.error(f"Failed to cleanup failed decryption output {original_path}: {str(e)}")
    
    return success

def full_cycle_operation(run_number: int):
    """Perform both encryption and decryption in sequence"""
    encryption_metrics = SimulationMetrics()
    encryption_metrics.set_run_number(run_number)
    
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
        return None
    
    try:
        # --- Encryption Phase ---
        logging.info(f"\n=== Starting Encryption Phase (Run {run_number}) ===")
        encryption_metrics.start_operation("encryption")
        
        # Check disk space (need 3x space: original + backup + encrypted)
        check_resources(target_files)
        
        # Create backups with progress tracking
        logging.info("Creating backups...")
        create_backups(target_files)
        
        # Encrypt files
        encryption_success = True
        for file_path in target_files:
            try:
                if not encrypt_file(file_path, key, encryption_metrics):
                    encryption_success = False
                    logging.warning(f"Failed to encrypt {file_path}, stopping...")
                    break
            except Exception as e:
                logging.error(f"Critical error encrypting {file_path}: {str(e)}")
                encryption_success = False
                break
        
        if not encryption_success:
            logging.error("Encryption failed - restoring original files")
            restore_files(target_files)
            return None
        
        # --- Decryption Phase ---
        logging.info(f"\n=== Starting Decryption Phase (Run {run_number}) ===")
        encrypted_files = get_encrypted_files()
        if not encrypted_files:
            logging.warning("No encrypted files found for decryption")
            return None
        
        # Create new metrics object but preserve the original checksums
        decryption_metrics = SimulationMetrics()
        decryption_metrics.set_run_number(run_number)
        decryption_metrics.original_checksums = encryption_metrics.original_checksums
        decryption_metrics.start_operation("decryption")
        
        # Decrypt files
        decryption_success = True
        for file_path in encrypted_files:
            try:
                if not decrypt_file(file_path, key, decryption_metrics):
                    decryption_success = False
                    logging.warning(f"Failed to decrypt {file_path}, stopping...")
                    break
            except Exception as e:
                logging.error(f"Critical error decrypting {file_path}: {str(e)}")
                decryption_success = False
                break
        
        if not decryption_success:
            logging.error("Decryption failed - some files may remain encrypted")
        
        # Combine metrics from both phases
        combined_metrics = SimulationMetrics()
        combined_metrics.set_run_number(run_number)
        combined_metrics.metrics = {key: encryption_metrics.metrics[key] + decryption_metrics.metrics[key] 
                                  for key in encryption_metrics.metrics.keys()}
        
        return combined_metrics
        
    except Exception as e:
        logging.error(f"Critical error during operation: {e}")
        if os.path.exists(BACKUP_DIR):
            logging.info("Attempting to restore files from backup")
            restore_files(target_files)
        else:
            logging.error("No backups available for restoration")
        return None
    finally:
        clean_up_backups()

def analyze_test_results(all_metrics):
    """Analyze and print summary statistics across all test runs"""
    if not all_metrics:
        logging.warning("No metrics to analyze")
        return
    
    # Initialize counters
    total_encryptions = 0
    encryption_successes = 0
    backup_successes = 0
    total_decryptions = 0
    checksum_matches = 0
    total_entropy_changes = []
    total_processing_times = []
    encryption_errors = 0
    
    for metrics in all_metrics:
        # Process encryption metrics
        enc_ops = [i for i, op in enumerate(metrics.metrics['operation']) if op == "encryption"]
        total_encryptions += len(enc_ops)
        encryption_successes += sum(metrics.metrics['success'][i] for i in enc_ops)
        backup_successes += sum(metrics.metrics['backup_success'][i] for i in enc_ops)
        encryption_errors += sum(1 for i in enc_ops if not metrics.metrics['success'][i])
        
        # Process decryption metrics
        dec_ops = [i for i, op in enumerate(metrics.metrics['operation']) if op == "decryption"]
        total_decryptions += len(dec_ops)
        checksum_matches += sum(1 for i in dec_ops if metrics.metrics['checksum_match'][i] == "Match")
        
        # Collect entropy changes and processing times
        for i, entropy_change in enumerate(metrics.metrics['entropy_change']):
            if entropy_change in ["Increased", "Restored", "High"]:
                total_entropy_changes.append(entropy_change)
        
        for time_str in metrics.metrics['processing_time']:
            try:
                total_processing_times.append(float(time_str))
            except ValueError:
                pass
    
    # Calculate averages
    avg_entropy_change = "N/A"
    if total_entropy_changes:
        increased = total_entropy_changes.count("Increased")
        restored = total_entropy_changes.count("Restored")
        high = total_entropy_changes.count("High")
        avg_entropy_change = f"Increased: {increased}, Restored: {restored}, High: {high}"
    
    avg_processing_time = sum(total_processing_times) / len(total_processing_times) if total_processing_times else 0
    
    # Print comprehensive summary
    logging.info("\n=== Comprehensive Test Results ===")
    logging.info(f"Total test runs: {len(all_metrics)}")
    logging.info(f"\nEncryption Statistics:")
    logging.info(f"Total encryption attempts: {total_encryptions}")
    logging.info(f"Successful encryptions: {encryption_successes} ({encryption_successes/max(1,total_encryptions)*100:.2f}%)")
    logging.info(f"Backup successes: {backup_successes} ({backup_successes/max(1,total_encryptions)*100:.2f}%)")
    logging.info(f"Encryption errors: {encryption_errors}")
    
    logging.info(f"\nDecryption Statistics:")
    logging.info(f"Total decryption attempts: {total_decryptions}")
    logging.info(f"Checksum matches: {checksum_matches} ({checksum_matches/max(1,total_decryptions)*100:.2f}%)")
    
    logging.info(f"\nPerformance Metrics:")
    logging.info(f"Average processing time: {avg_processing_time:.4f} seconds")
    logging.info(f"Entropy changes: {avg_entropy_change}")

# --- Main ---
if __name__ == "__main__":
    print("=== Automated Encryption/Decryption Tool ===")
    print(f"Performing {TEST_RUNS} full encryption/decryption cycles...")
    
    # Clear existing metrics file
    if os.path.exists(METRICS_FILE):
        os.remove(METRICS_FILE)
    
    all_test_metrics = []
    for run in range(1, TEST_RUNS + 1):
        print(f"\n=== Starting Test Run {run} of {TEST_RUNS} ===")
        metrics = full_cycle_operation(run)
        if metrics:
            all_test_metrics.append(metrics)
        else:
            logging.error(f"Test run {run} failed to complete")
    
    # Analyze and print comprehensive results
    analyze_test_results(all_test_metrics)
    print("\n=== All test runs completed ===")
