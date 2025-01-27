import os
import sys
import requests
from tqdm import tqdm  # Import tqdm for a graphical progress bar
import shutil
import subprocess
import hashlib
import pefile
from colorama import init, Fore

# Define Quarantine directory
Quarantine = os.path.join("Quarantine")
os.makedirs(Quarantine, exist_ok=True)

# Initialize colorama for terminal color support
init()

# ClamAV scan path (make sure this matches the actual path of clamscan on your system)
CLAMSCAN_PATH = r'C:\Program Files\ClamAV\clamscan.exe'  # Adjust as needed


# Function to download file with a progress bar
def download_file(url, filename):
    try:
        # Send a GET request to fetch the file
        response = requests.get(url, stream=True)  # Use stream=True for large files
        total_size = int(response.headers.get('content-length', 0))  # Get the total file size

        if response.status_code == 200:
            # Initialize a progress bar with tqdm
            with tqdm(total=total_size, unit='B', unit_scale=True) as bar:
                with open(filename, 'wb') as file:
                    for data in response.iter_content(chunk_size=1024):
                        file.write(data)  # Write chunk to file
                        bar.update(len(data))  # Update the progress bar with the chunk size
            print(f"{filename} download successful.")
        else:
            print(f"Failed to download {filename}. HTTP status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred during download: {e}")

# Function to check file signature and quarantine if invalid
def check_file_signature(file_path, expected_signature):
    try:
        with open(file_path, 'rb') as file:
            header = file.read(32)
            main_header = str(header.hex())
            if main_header[:4] == expected_signature:
                print(f"File Signature checked {Fore.GREEN}[ OK ]{Fore.RESET}")
            else:
                shutil.move(file_path, Quarantine)
                print(f"File Security Error. File Quarantined {Fore.RED}[ WARNING ]{Fore.RESET}")
    except Exception as e:
        print(f"Error checking file signature: {e}")

# Function to scan the downloaded file with ClamAV
def scan_with_clamav(file_path):
    try:
        print(f"Scanning {file_path} with ClamAV...")
        # Run clamscan using subprocess
        result = subprocess.run([CLAMSCAN_PATH, '--remove', '--infected', '--recursive', '--verbose', file_path], capture_output=True, text=True)
        
        # Check if ClamAV found any infections
        if result.returncode == 0:
            print(f"Scan completed for {file_path}. No threats detected.")
        else:
            print(f"ClamAV found an issue with {file_path}. Moving to quarantine.")
            shutil.move(file_path, Quarantine)
    except Exception as e:
        print(f"Error during ClamAV scan: {e}")

# Get the hash of the file
def get_file_hash(file_path, hash_algorithm='sha256'):
    """Get the hash of the file."""
    hash_func = hashlib.new(hash_algorithm)
    with open(file_path, 'rb') as file:
        while chunk := file.read(4096):
            hash_func.update(chunk)
    return hash_func.hexdigest()

# Extract PE file metadata
def extract_pe_metadata(file_path):
    """Extract PE file metadata."""
    try:
        pe = pefile.PE(file_path)
        print("File Metadata:")
        print(f"  File Version: {pe.FILE_HEADER.Machine}")
        print(f"  File Description: {pe.get_string_from_data(pe.DIRECTORY_ENTRY_RESOURCE.entries[0].data)}")
        # Add more metadata checks as required
    except Exception as e:
        print(f"Error extracting metadata: {e}")

# Extract strings from the EXE file
def extract_strings(file_path):
    """Extract strings from the EXE file."""
    try:
        result = subprocess.run(['strings', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        strings = result.stdout
        suspicious_keywords = ['password', 'execute', 'cmd', 'powershell', 'shell', 'netcat']  # Example suspicious keywords
        for keyword in suspicious_keywords:
            if keyword in strings.lower():
                print(f"[WARNING] Suspicious keyword '{keyword}' found in the file strings.")
    except Exception as e:
        print(f"Error extracting strings: {e}")

# Display help message
def show_help():
    return("""
Usage: winpack.py <option> [<sub-option>]

Options:
  --install          Install the software
    --normal         Install the normal version of the software
      <appname>      Install App (normal version)

    --portable       Install the portable version of the software
      <appname>      Install App (portable version)

  --help             Display this help message

Examples:
  script.py --install --normal --notepad
  script.py --download --data --winrar
    """)

# Main logic based on user input
if len(sys.argv) < 2:
    print("Usage: script.py <option> [<sub-option>]")
    sys.exit(1)

if sys.argv[1] == "--install":
    if len(sys.argv) < 3:
        print("Missing sub-option for --install. Expected --normal or --portable.")
        sys.exit(1)
    
    if sys.argv[2] == "--normal":
        if len(sys.argv) >= 4 and sys.argv[3] == "notepad":
            print("Starting to download Notepad (normal version). Please wait...")
            url = 'https://dl2.soft98.ir/soft/n/Notepad.8.7.5.x64.rar?1735198965'
            download_file(url, 'Notepad_8.7.5.x64.rar')
            # Scan downloaded file with ClamAV
            scan_with_clamav('Notepad_8.7.5.x64.rar')
            # Check file hash and metadata
            print(f"File Hash: {get_file_hash('Notepad_8.7.5.x64.rar')}")
            extract_pe_metadata('Notepad_8.7.5.x64.rar')
            extract_strings('Notepad_8.7.5.x64.rar')

        elif len(sys.argv) >= 4 and sys.argv[3] == "winrar":
            print("Starting to download WinRAR (normal version). Please wait...")
            url = 'https://dl2.soft98.ir/soft/w/WinRAR.7.01.exe?1735201498'
            download_file(url, 'WinRAR.7.01.exe')
            # Check File Signature and Scan with ClamAV
            check_file_signature('WinRAR.7.01.exe', '4d5a')
            scan_with_clamav('WinRAR.7.01.exe')
            # Check file hash and metadata
            print(f"File Hash: {get_file_hash('WinRAR.7.01.exe')}")
            extract_pe_metadata('WinRAR.7.01.exe')
            extract_strings('WinRAR.7.01.exe')
        
        else:
            print("The software you requested (normal version) was not found.")

    elif sys.argv[2] == "--portable":
        if len(sys.argv) >= 4 and sys.argv[3] == "notepad":
            print("Starting to download Notepad (portable version). Please wait...")
            url = 'https://dl2.soft98.ir/soft/n/Notepad.8.6.7.Portable.rar?1735198990'
            download_file(url, 'Notepad.8.6.7.Portable.rar')
            # Scan downloaded file with ClamAV
            scan_with_clamav('Notepad.8.6.7.Portable.rar')
            # Check file hash and metadata
            print(f"File Hash: {get_file_hash('Notepad.8.6.7.Portable.rar')}")
            extract_pe_metadata('Notepad.8.6.7.Portable.rar')
            extract_strings('Notepad.8.6.7.Portable.rar')

        elif len(sys.argv) >= 4 and sys.argv[3] == "winrar":
            print("Starting to download WinRAR (portable version). Please wait...")
            url = 'https://dl2.soft98.ir/soft/w/WinRAR.7.0.Portable.zip?1735201526'
            download_file(url, 'WinRAR.7.0.Portable.zip')
            # Scan downloaded file with ClamAV
            scan_with_clamav('WinRAR.7.0.Portable.zip')
            # Check file hash and metadata
            print(f"File Hash: {get_file_hash('WinRAR.7.0.Portable.zip')}")
            extract_pe_metadata('WinRAR.7.0.Portable.zip')
            extract_strings('WinRAR.7.0.Portable.zip')

        else:
            print("The software you requested (portable version) was not found.")
    
    else:
        print("Invalid option for --install. Expected --normal or --portable.")
        sys.exit(1)

    sys.exit(0)  # Exit after installation logic


elif sys.argv[1] == "--help":
    print(show_help())

else:
    print("Invalid option. Use --help to display usage.")
