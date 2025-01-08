# **DSC-Nmap-GUI Tool**

The **DSC-Nmap-GUI Tool** is an advanced yet user-friendly graphical user interface built with Python using `tkinter` and `ttkbootstrap`. Designed for network professionals, ethical hackers, and IT enthusiasts, this tool provides seamless interaction with the powerful Nmap scanning utility. It simplifies complex network scanning and risk assessment processes, offering real-time results and actionable insights.

---

## **Features**

### **1. Comprehensive Nmap Scanning**
- **Supports Various Scan Types:**
  - SYN Scan (`-sS`)
  - TCP Connect Scan (`-sT`)
  - Ping Scan (`-sn`)
  - UDP Scan (`-sU`)
  - Null Scan (`-sN`)
  - FIN Scan (`-sF`)
  - Xmas Scan (`-sX`)
  - ACK Scan (`-sA`)
  - Window Scan (`-sW`)
  - IP Protocol Scan (`-sO`)
- **Advanced Options:**
  - OS detection (`-O`)
  - Service detection (`-sV`)
  - Aggressive scan mode (`-A`)
  - Disable ping (`-Pn`)
  - Verbose output (`-v`)

---

### **2. Real-Time Results Display**
- **Side-by-Side Panels:**
  - **Left Panel:** Displays live scan results in real-time.
  - **Right Panel:** Provides a detailed risk assessment based on vulnerabilities found during the scan.
- Progress bar for tracking scan completion.

---

### **3. Risk Assessment**
- Analyzes scan results to identify and highlight potential vulnerabilities.
- Helps prioritize mitigation actions with actionable insights.

---

### **4. Export Options**
- Save scan results and risk assessments to `.txt` or `.json` files for record-keeping or further analysis.

---

### **5. Customizable Themes**
- Switch between **light mode** (`united`) and **dark mode** (`cyborg`) for personalized usability.

---

## **Prerequisites**

Ensure the following are installed and set up on your system:

### **1. Python**
- **Python 3.8 or higher** is required. Download it from [Python Official Website](https://www.python.org/downloads/).

### **2. Nmap**
- Ensure Nmap is installed on your system. Download it from [Nmap Official Website](https://nmap.org/download.html).
- Verify installation by running:
    ```bash
    nmap --version
    ```

### **3. Required Python Libraries**
- The required Python libraries are listed in the `requirements.txt` file. They include:
  - `ttkbootstrap` for modern GUI components.
  - `tkinter` for core GUI functionalities.

---

## **Installation**

Follow these steps to set up and run the DSC-Nmap-GUI Tool:

### **1. Clone the Repository**
```bash
git clone https://github.com/yourusername/DSC-Nmap-GUI.git
cd DSC-Nmap-GUI
