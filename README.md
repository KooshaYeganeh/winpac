# WinPack - Windows Software Downloader and Security Scanner

WinPack is a Python script designed to download Windows software packages, scan them for security issues, and analyze file metadata and hash signatures. It supports both normal and portable versions of software, provides security checks (like ClamAV scanning), and analyzes files for potential threats.

## Features
- **Install Windows Software**: Automatically download and install normal or portable versions of software such as Notepad or WinRAR.
- **Security Analysis**: Check the file signature and scan downloaded files using ClamAV.
- **IOC (Indicators of Compromise) Analysis**: Extract file hashes, PE file metadata, and strings from the executable for further investigation of suspicious files.
- **Quarantine**: Files identified as suspicious or infected are moved to a quarantine directory for safety.

## Installation

### Prerequisites

1. **Python 3.x**: Ensure you have Python 3.x installed on your system.
2. **ClamAV**: Install ClamAV on your Windows system. Make sure to adjust the path to `clamscan.exe` in the script as needed.
3. **Required Python Libraries**:
   You need to install the following Python libraries before running the script:
   
   ```bash
   pip install -r requrements.txt
   ```

4. **ClamAV Installation**:  
   You need to install ClamAV to scan the downloaded files for any potential threats. You can download it from [ClamAV's official website](https://www.clamav.net/downloads).

   Once installed, update the `CLAMSCAN_PATH` variable in the script to point to your `clamscan.exe` location:
   
   ```python
   CLAMSCAN_PATH = r'C:\Program Files\ClamAV\clamscan.exe'  # Adjust as needed
   ```

## Usage

### Basic Commands

To run the script, use the following command structure:

```bash
python script.py <option> [<sub-option>]
```

### Options

- `--install`: Download and install the specified software. Use the `--normal` or `--portable` sub-option for normal or portable versions.
    - `--normal <appname>`: Download the normal version of the specified app (e.g., Notepad or WinRAR).
    - `--portable <appname>`: Download the portable version of the specified app.

- `--help`: Display usage instructions.

### Example Commands

1. **Install the normal version of Notepad:**
    ```bash
    python script.py --install --normal notepad
    ```

2. **Install the portable version of WinRAR:**
    ```bash
    python script.py --install --portable winrar
    ```

3. **Show help instructions:**
    ```bash
    python script.py --help
    ```

### What Happens During Execution

- **Download**: The script will download the specified software from a trusted source.
- **Security Check**: The downloaded file will be scanned with ClamAV. If it’s found to be infected, it will be moved to a quarantine directory.
- **File Analysis**: The script will extract metadata from the file, including version information and suspicious strings. It will also compute and display the file’s hash for further analysis.
- **Signature Validation**: The script checks the file’s signature (e.g., for PE files) to ensure its authenticity.

### Quarantine

Files that fail security checks are automatically moved to a `Quarantine` directory to prevent any accidental execution. This directory is created in the same location where the script is run.

## Code Explanation

- **File Downloading**: The `download_file` function downloads software using a stream to handle large files efficiently, displaying a progress bar using the `tqdm` library.
- **Signature Check**: The `check_file_signature` function checks the file’s signature to ensure it matches expected patterns (e.g., PE files).
- **ClamAV Scan**: The `scan_with_clamav` function runs a ClamAV scan on the downloaded file to detect malware.
- **Hashing**: The `get_file_hash` function computes the hash of a file (SHA-256 by default) to verify file integrity.
- **PE Metadata**: The `extract_pe_metadata` function extracts metadata from executable files (like PE files).
- **String Extraction**: The `extract_strings` function uses the `strings` command to extract readable strings from the file and flag suspicious keywords.

## Contributing

If you'd like to contribute to this project, feel free to open an issue or submit a pull request. Improvements, bug fixes, and feature suggestions are always welcome!

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
