# DSC-Nmap-GUI Tool

DSC-Nmap-GUI is a graphical user interface tool built on `tkinter` and `ttkbootstrap` for interacting with the Nmap scanning tool. It simplifies network scanning, risk assessment, and provides an intuitive display of results.

---

## Features

- Supports various Nmap scan types such as SYN, TCP Connect, Ping, and UDP scans.
- Displays scan results in real-time in a user-friendly interface.
- Risk assessment feature to analyze vulnerabilities.
- Options for OS detection, service scan, aggressive mode, and more.
- Export scan results to text or JSON files.
- Customizable themes for light and dark modes.

---

## Prerequisites

- **Python 3.8 or higher** is required.
- Ensure Nmap is installed on your system. Download from [Nmap Official Website](https://nmap.org/download.html).
- An active internet connection for installing Python dependencies.

---

## Installation

Follow these steps to install and run the DSC-Nmap-GUI Tool:

1. Clone or download this repository to your local machine.
2. Navigate to the project directory using the terminal.
3. Install the required Python libraries by running:

    ```bash
    pip install -r requirements.txt
    ```

4. Verify that Nmap is installed and available in your system's PATH by running:

    ```bash
    nmap --version
    ```

5. Run the application using:

    ```bash
    python Nmap_Main.py
    ```

---

## Usage

1. Launch the application by running `python Nmap_Main.py`.
2. Input the target IP address or domain in the **Target** field.
3. Specify a port range (optional).
4. Choose a scan type and additional options as needed.
5. Click **Start Scan** to begin the Nmap scan.
6. View scan results in the **Scan Results** panel and risk assessments in the **Risk Assessment** panel.
7. Export results to a file using the `File > Export Results` menu option.

---

## License and Intellectual Property

- This tool is developed by **Mustafa Banikhalaf** and **Mohammad Majdalawy**.
- All rights reserved. You are permitted to use, modify, and distribute this tool under the terms of its license.
- Any usage of this tool for malicious purposes is strictly prohibited.

---

## Support

For support or inquiries, please contact:

- **Mustafa Banikhalaf**
- **Mohammad Majdalawy**

---

## Contribution

We welcome contributions to improve this tool. To contribute:

1. Fork the repository.
2. Create a new branch for your feature or fix.
3. Submit a pull request with detailed descriptions of the changes made.

---

### Screenshots (Optional)

Include screenshots of the tool's interface if possible.

---

Enjoy using the DSC-Nmap-GUI Tool!
