import os

# Function to create files in a specified directory
def create_files_in_directory(directory):
    # If the directory doesn't exist, create it
    if not os.path.exists(directory):
        os.makedirs(directory)
    
    # Create 100 txt files with content
    for i in range(1, 101):
        with open(os.path.join(directory, f"file_{i}.txt"), "w") as file:
            file.write(f"This is the content of file number {i}.")

# Hardcoded directory path (example for Linux)
directory = "/home/chicken/Documents/Research/Workspace/txtFileBackup"  # Change this to your desired path

# Call the function with the hardcoded directory
create_files_in_directory(directory)
