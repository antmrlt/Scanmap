# ScanMap

This is the README file for the ScanMap Python script. ScanMap is a script for scanning and mapping network devices and services using the Nmap tool. It generates HTML reports for each subnet and can also create CSV files for storing scan results.

## Prerequisites

Before using the ScanMap script, ensure you have the following prerequisites installed on your system:

- Python 3
- Nmap
- Xalan (for XML to HTML conversion)
- Python `progress` library (install it using `pip install progress`)

## Usage

1. Clone this repository or download the ScanMap script to your local machine.

2. Make the script executable:
   ```
   chmod +x scanmap.py
   ```

3. Run the script with the following command:
   ```
   ./scanmap.py
   ```

4. Follow the on-screen instructions to provide input.

   - You will be prompted to enter the name of a text file containing the subnets you want to scan. Each subnet should be on a separate line in CIDR notation (e.g., `192.168.1.0/24`).

   - You can choose between two display modes:
     - "d" for detailed mode: This mode provides detailed information about the scan progress.
     - "p" for progress bar mode: This mode shows a progress bar for the scan.

   - You can choose to generate a CSV file for the scan results by entering "o" for yes or "n" for no.

5. The script will then start scanning the specified subnets and generate HTML reports for each subnet. If you chose to create a CSV file, it will also generate a CSV file with the scan results.

6. Once the scan is complete, you will see a message indicating that the scan is finished.

## Output

The ScanMap script will create the following output:

- HTML reports for each subnet in a folder named with the date and the two most significant octets of the subnet (e.g., "20230921/192.168.X.X").
- If you chose to generate a CSV file, a CSV file named "bilan_YYYYMMDD_HHMM.csv" will be created in the same directory as the script. This file will contain scan results in CSV format.

## Note

- This script uses Nmap for scanning, so ensure that Nmap is properly installed on your system.

- The script may require administrative privileges to run certain Nmap scans. You may need to run the script with `sudo` or as an administrator.

- Make sure to review and comply with all applicable laws and regulations before scanning any network or system that you do not own or have explicit permission to scan.

- This README provides basic usage instructions. For more advanced usage and customization, please review the script code.

- Use this script responsibly and only on networks and systems that you are authorized to scan.

- The script is provided as-is, and the author assumes no responsibility for its use or any consequences thereof.

## Author

This script was created by the author for educational and testing purposes.

Feel free to reach out to the author for any questions or feedback.

**Happy scanning!**
