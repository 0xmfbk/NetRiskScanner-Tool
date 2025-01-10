import re
import os
from ipaddress import ip_address, ip_network
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox
from utils.validator import is_valid_target, is_valid_port_range
from utils.Runner_Tool import Runner_Tool
import google.generativeai as genai
import subprocess
import threading
from queue import Queue
import tkinter as tk
import webbrowser

class NetRiskScanner:
    def __init__(self):
        self.root = ttk.Window(themename="cyborg")
        self.root.title("NetRiskScanner Tool")
        self.root.geometry("1200x700")
        self.style = ttk.Style()

        # Initialize variables
        self.stop_event = threading.Event()
        self.progress_value = ttk.IntVar(value=0)
        self.status_message = ttk.StringVar(value="Ready")
        self.result_queue = Queue()
        self.risk_queue = Queue()
        self.process = None
        self.total_lines = 100

        # Define enqueue_result before initializing Runner_Tool
        self.enqueue_result = self.define_enqueue_result()

        # Initialize Runner_Tool
        self.runner_tool = Runner_Tool(self.enqueue_result)

        # Create UI
        self.create_menu()
        self.create_widgets()

        # Start result updater
        self.update_result_threadsafe()

        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def define_enqueue_result(self):
        """Define the enqueue_result function."""
        def enqueue_result(result_line, for_risk=False):
            if for_risk:
                self.risk_queue.put(result_line)
            else:
                self.result_queue.put(result_line)
        return enqueue_result

    def create_menu(self):
        """Create the optimized menu bar with improved features."""
        menu_bar = ttk.Menu(self.root)

        # File Menu
        file_menu = ttk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Export Results (Ctrl+E)", command=self.export_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit (Ctrl+Q)", command=self.on_closing)
        menu_bar.add_cascade(label="File", menu=file_menu)

        # Theme Menu
        theme_menu = ttk.Menu(menu_bar, tearoff=0)
        theme_menu.add_command(label="Dark Mode", command=lambda: self.switch_theme("cyborg"))
        theme_menu.add_command(label="Light Mode", command=lambda: self.switch_theme("united"))
        menu_bar.add_cascade(label="Theme", menu=theme_menu)

        # Help Menu
        help_menu = ttk.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        help_menu.add_separator()
        help_menu.add_command(label="About", command=self.show_about)
        menu_bar.add_cascade(label="Help", menu=help_menu)

        self.root.config(menu=menu_bar)
        self.root.bind("<Control-e>", lambda event: self.export_results())
        self.root.bind("<Control-q>", lambda event: self.on_closing())

    def show_documentation(self):
        """Open the documentation link in the user's web browser."""
        documentation_url = "https://github.com/MustafaFBK/DSC-Nmap-Copy/blob/main/NetRiskScanner%20Document.pdf"
        try:
            webbrowser.open(documentation_url)
        except Exception as e:
            messagebox.showerror("Error", f"Unable to open documentation: {e}")

    def switch_theme(self, theme_name):
        """Switch between light and dark themes."""
        self.root.style.theme_use(theme_name)

    def create_widgets(self):
        """Create all widgets and input fields."""
        self.create_main_layout()

    def create_main_layout(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=BOTH, expand=True)

        self.create_target_input(main_frame)
        self.create_scan_options(main_frame)
        self.create_scan_buttons(main_frame)
        self.create_split_display(main_frame)
        self.create_progress_bar(main_frame)
        self.create_status_bar(main_frame)

    def create_target_input(self, parent):
        """Create the target input fields for IP/domain and port range."""
        target_frame = ttk.Labelframe(parent, text="Target Information", padding=10, bootstyle=PRIMARY)
        target_frame.pack(pady=10, fill=X, padx=10)

        self.add_labeled_entry(target_frame, "Target:", 50, self.validate_target, "target_entry")
        self.target_feedback = ttk.Label(target_frame, text="", bootstyle="danger")
        self.target_feedback.pack(side=LEFT, padx=5)

        self.add_labeled_entry(target_frame, "Port, Ports or Range:", 15, None, "port_range_entry")

        # Add Timing Template Dropdown
        ttk.Label(target_frame, text="Timing Template:").pack(side=LEFT, padx=5)
        self.timing_template = ttk.StringVar()
        timing_template_combobox = ttk.Combobox(
            target_frame,
            textvariable=self.timing_template,
            values=["-T0 (Paranoid)", "-T1 (Sneaky)", "-T2 (Polite)", "-T3 (Normal)", "-T4 (Aggressive)", "-T5 (Insane)"],
            width=25
        )
        timing_template_combobox.pack(side=LEFT, padx=5)
        timing_template_combobox.set("-T3 (Normal)")

    def add_labeled_entry(self, parent, label_text, width, validation, attr_name):
        """Helper method to create labeled entry widgets."""
        ttk.Label(parent, text=label_text).pack(side=LEFT, padx=5)
        entry = ttk.Entry(parent, width=width)
        entry.pack(side=LEFT, padx=5)
        if validation:
            entry.bind("<FocusOut>", validation)
        setattr(self, attr_name, entry)

    def validate_target(self, event=None):
        """Validate the target input."""
        target = self.target_entry.get()
        if not is_valid_target(target):
            self.target_feedback.config(text="Invalid target! Use format 192.168.1.1, 192.168.1.1-20, 192.168.1.0/24 or example.com")
        else:
            self.target_feedback.config(text="")

    def create_scan_options(self, parent):
        """Create scan type and advanced options in a single frame."""
        options_frame = ttk.Labelframe(parent, text="Options", padding=10, bootstyle=PRIMARY)
        options_frame.pack(pady=10, fill=X, padx=10)

        self.scan_type = ttk.StringVar()
        scan_type_combobox = ttk.Combobox(
            options_frame,
            textvariable=self.scan_type,
            values=[
                "Ping Scan : -sn",
                "SYN Scan : -sS",
                "TCP Connect Scan : -sT",
                "UDP Scan : -sU",
                "Null Scan : -sN",
                "FIN Scan : -sF",
                "Xmas Scan : -sX",
                "ACK Scan : -sA",
                "Window Scan : -sW",
                "IP Protocol Scan : -sO"
            ],
            width=40,
        )
        scan_type_combobox.pack(side=LEFT, padx=5)

        self.os_detection = ttk.BooleanVar()
        self.service_scan = ttk.BooleanVar()
        self.verbose = ttk.BooleanVar()
        self.aggressive_scan = ttk.BooleanVar()
        self.no_ping_option = ttk.BooleanVar()
        self.reason_option = ttk.BooleanVar()

        self.add_checkbox(options_frame, "OS Detection", self.os_detection)
        self.add_checkbox(options_frame, "Service Scan", self.service_scan)
        self.add_checkbox(options_frame, "Verbose", self.verbose)
        self.add_checkbox(options_frame, "Aggressive Scan", self.aggressive_scan)
        self.add_checkbox(options_frame, "No Ping", self.no_ping_option)

    def add_checkbox(self, parent, label_text, variable):
        """Helper method to create checkbox widgets."""
        ttk.Checkbutton(parent, text=label_text, variable=variable, bootstyle=SUCCESS).pack(side=LEFT, padx=5)

    def create_scan_buttons(self, parent):
        """Create the buttons for starting, stopping, and clearing scans."""
        button_frame = ttk.Frame(parent, padding=10)
        button_frame.pack(fill=X, padx=10)

        # Buttons
        self.scan_button = ttk.Button(button_frame, text="Start Scan", command=self.start_scan, bootstyle=SUCCESS)
        self.scan_button.pack(side=LEFT, padx=5)

        self.stop_button = ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan, state=DISABLED, bootstyle=WARNING)
        self.stop_button.pack(side=LEFT, padx=5)

        self.clear_button = ttk.Button(button_frame, text="Clear Results", command=self.clear_results, bootstyle=INFO)
        self.clear_button.pack(side=LEFT, padx=5)

        # Command display with dynamic right padding
        self.command_display = ttk.Entry(button_frame, width=80, state="readonly")
        self.command_display.pack(side=LEFT, padx=5, fill=X, expand=True)

        self.copy_button = ttk.Button(button_frame, text="Copy Command", command=self.copy_command, bootstyle=INFO)
        self.copy_button.pack(side=LEFT, padx=5)

        self.analysis_button = ttk.Button(button_frame, text="Analysis", command=self.perform_risk_analysis, bootstyle=PRIMARY)
        self.analysis_button.pack(side=LEFT, padx=5)

    def copy_command(self):
        """Copy the raw command to the clipboard."""
        self.root.clipboard_clear()
        self.root.clipboard_append(self.command_display.get())
        self.root.update()  # Ensure the clipboard content is updated
        messagebox.showinfo("Copied", "Command copied to clipboard.")

    def create_split_display(self, parent):
        """
        Create split display: left for scan results, right for risk assessment.
        Includes horizontal and vertical scrollbars for both text areas.
        """
        display_frame = ttk.Frame(parent)
        display_frame.pack(fill=BOTH, expand=True, padx=10, pady=10)

        # Left: Scan Results
        results_frame = ttk.Labelframe(display_frame, text="Scan Results", padding=10, bootstyle=PRIMARY)
        results_frame.pack(side=LEFT, fill=BOTH, expand=True, padx=(0, 5))

        result_text_frame = ttk.Frame(results_frame)
        result_text_frame.pack(fill=BOTH, expand=True)

        self.result_text = ttk.Text(result_text_frame, wrap="none", state="disabled", height=20, width=50)
        self.result_text.pack(side=LEFT, fill=BOTH, expand=True)

        # Vertical scrollbar for Scan Results
        result_scrollbar_vertical = ttk.Scrollbar(result_text_frame, orient=tk.VERTICAL, command=self.result_text.yview)
        self.result_text.config(yscrollcommand=result_scrollbar_vertical.set)
        result_scrollbar_vertical.pack(side=tk.RIGHT, fill=tk.Y)

        # Horizontal scrollbar for Scan Results
        result_scrollbar_horizontal = ttk.Scrollbar(results_frame, orient=tk.HORIZONTAL, command=self.result_text.xview)
        self.result_text.config(xscrollcommand=result_scrollbar_horizontal.set)
        result_scrollbar_horizontal.pack(side=tk.BOTTOM, fill=tk.X)

        # Right: Risk Assessment
        risk_frame = ttk.Labelframe(display_frame, text="Risk Assessment", padding=10, bootstyle=WARNING)
        risk_frame.pack(side=LEFT, fill=BOTH, expand=True, padx=(5, 0))

        risk_text_frame = ttk.Frame(risk_frame)
        risk_text_frame.pack(fill=BOTH, expand=True)

        self.risk_text = ttk.Text(risk_text_frame, wrap="none", state="disabled", height=20, width=50)
        self.risk_text.pack(side=LEFT, fill=BOTH, expand=True)

        # Vertical scrollbar for Risk Assessment
        risk_scrollbar_vertical = ttk.Scrollbar(risk_text_frame, orient=tk.VERTICAL, command=self.risk_text.yview)
        self.risk_text.config(yscrollcommand=risk_scrollbar_vertical.set)
        risk_scrollbar_vertical.pack(side=tk.RIGHT, fill=tk.Y)

        # Horizontal scrollbar for Risk Assessment
        risk_scrollbar_horizontal = ttk.Scrollbar(risk_frame, orient=tk.HORIZONTAL, command=self.risk_text.xview)
        self.risk_text.config(xscrollcommand=risk_scrollbar_horizontal.set)
        risk_scrollbar_horizontal.pack(side=tk.BOTTOM, fill=tk.X)

    def create_progress_bar(self, parent):
        """Create the progress bar with animation."""
        progress_frame = ttk.Labelframe(parent, text="Scan Progress", padding=10, bootstyle=PRIMARY)
        progress_frame.pack(fill=X, padx=10, pady=5)

        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_value, maximum=100, bootstyle=INFO, mode="determinate")
        self.progress_bar.pack(fill=X, expand=True)

    def create_status_bar(self, parent):
        """Create the status bar at the bottom of the window."""
        status_frame = ttk.Frame(parent, padding=5)
        status_frame.pack(fill=X, side=BOTTOM)

        self.status_label = ttk.Label(status_frame, textvariable=self.status_message, anchor=W, bootstyle=SECONDARY)
        self.status_label.pack(fill=X)

    def update_progress(self, current_line):
        """Update the progress bar value dynamically."""
        if current_line > self.total_lines:
            self.total_lines = current_line

        if self.total_lines > 0:
            progress = min(int((current_line / self.total_lines) * 100), 100)
            self.progress_value.set(progress)

    def start_scan(self):
        """Start the NetRiskScanner scan."""
        target = self.target_entry.get()
        port_range = self.port_range_entry.get()
        timing_template = self.timing_template.get().split()[0] if self.timing_template.get() else "-T3"

        options = {
            "os_detection": self.os_detection.get(),
            "service_scan": self.service_scan.get(),
            "verbose": self.verbose.get(),
            "scan_type": self.scan_type.get(),
            "aggressive_scan": self.aggressive_scan.get(),
            "no_ping": self.no_ping_option.get(),
            "timing_template": timing_template,
        }

        if not self.validate_inputs(target, port_range):
            return

        command = " ".join(self.runner_tool.build_command(target, port_range, options))
        self.command_display.config(state="normal")
        self.command_display.delete(0, tk.END)
        self.command_display.insert(0, command)
        self.command_display.config(state="readonly")

        self.clear_results()
        self.update_status("Scanning...")
        self.scan_button.config(state=DISABLED)
        self.stop_button.config(state=NORMAL)
        self.progress_value.set(0)

        self.stop_event.clear()
        threading.Thread(target=self.run_NetRiskScanner_scan, args=(target, port_range, options), daemon=True).start()

    def validate_inputs(self, target, port_range):
        """Validate inputs and show error messages if invalid."""
        if not is_valid_target(target):
            messagebox.showerror("Error", "Invalid target. Please enter a valid IP or domain.")
            return False
        if port_range and not is_valid_port_range(port_range):
            messagebox.showerror("Error", "Invalid port range. Enter a valid range (e.g., 20-80).")
            return False
        return True

    def run_NetRiskScanner_scan(self, target, port_range, options):
        try:
            # Build the command for Nmap
            command = self.runner_tool.build_command(target, port_range, options)
            self.update_status("Executing Nmap scan...")
            self.enqueue_result(f"Executing: {' '.join(command)}")

            # Start the Nmap scan subprocess
            self.process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

            # Capture and process the Nmap output
            nmap_output = ""
            for line in self.process.stdout:
                if self.stop_event.is_set():
                    self.process.terminate()
                    self.update_status("Scan stopped by user.")
                    return

                nmap_output += line  # Append the output to a single string
                self.enqueue_result(line.strip())  # Update results in the GUI

            # Capture and process any errors from stderr
            for error_line in self.process.stderr:
                self.enqueue_result(f"Error: {error_line.strip()}")

            # Wait for the scan process to complete
            self.process.wait()

            # If the scan completed successfully, enable the "Do Analysis" button
            if not self.stop_event.is_set():
                self.update_status("Scan completed. You can now perform risk analysis.")
                self.progress_value.set(100)
                self.analysis_button.config(state=NORMAL)  # Enable the "Do Analysis" button

                # Store the Nmap output for analysis
                self.nmap_output_for_analysis = nmap_output

        except Exception as e:
            self.update_status(f"Error during scan: {str(e)}")
            self.enqueue_result(f"Runtime Error: {str(e)}")
        finally:
            # Cleanup and reset buttons
            self.scan_button.config(state=NORMAL)
            self.stop_button.config(state=DISABLED)
            self.update_status("Ready")

    def perform_risk_analysis(self):
        try:
            if not hasattr(self, "nmap_output_for_analysis") or not self.nmap_output_for_analysis.strip():
                messagebox.showerror("Error", "No Nmap output available for analysis.")
                return

            self.update_status("Performing risk analysis using AI...")
            self.enqueue_result("Starting AI Risk Assessment...")

            # Configure Google Generative AI
            api_key = "AIzaSyBgf4etgJtM3y40kiRDUxbYQmtozzXa2T0"
            if not api_key:
                messagebox.showerror("Error", "AI API key is missing. Please set the GEMINI_API_KEY environment variable.")
                return

            genai.configure(api_key=api_key)

            model = genai.GenerativeModel(
                model_name="gemini-1.5-pro",
                generation_config={
                    "temperature": 2,
                    "top_p": 0.95,
                    "top_k": 40,
                    "max_output_tokens": 8192,
                    "response_mime_type": "text/plain",
                }
            )
            chat_session = model.start_chat(history=[])

            # Prompt AI for risk assessment
            ai_prompt = (
                f"Analyze the provided Nmap scan output and create a professional, structured risk assessment report with the following format:\n\n"
                f"\n1. **Executive Summary:**\n"
                f"\t   - Provide a concise overview of the scan findings, highlighting key risks and security concerns.\n\n"
                f"\n2. **Identified Vulnerabilities:**\n"
                f"\t   - List vulnerabilities categorized by severity (High, Medium, Low).\n"
                f"\t   - Include a brief description of each vulnerability and its potential impact.\n"
                f"\t   - Specify associated services and ports for each identified vulnerability.\n\n"
                f"\n3. **Risk Levels:**\n"
                f"   - Present a structured table with the following columns:\n"
                f"     - **Port**: The scanned port number.\n"
                f"     - **Service**: The service associated with the port.\n"
                f"     - **Risk Level**: The severity of the risk (e.g., Low, Medium, High).\n"
                f"     - **Description**: A clear explanation of the risk.\n"
                f"   - Ensure the table is properly formatted and readable.\n\n"
                f"\n4. **Recommendations:**\n"
                f"   - Provide actionable recommendations categorized into three sections:\n"
                f"     - **Immediate Actions:**\n"
                f"\t       1. List specific steps to address critical vulnerabilities immediately. Include firewall configurations, service disabling, or patches.\n"
                f"\t       2. Ensure each action is clearly numbered and described in detail.\n\n"
                f"     - **Short-Term Strategies:**\n"
                f"\t       1. List actions that should be implemented within the next few weeks to mitigate medium-severity risks.\n"
                f"\t       2. Focus on configuration changes, software updates, or additional security measures.\n\n"
                f"     - **Long-Term Strategies:**\n"
                f"\t       1. Outline best practices for ongoing security and risk mitigation, such as regular vulnerability scanning, penetration testing, and user education.\n"
                f"\t       2. Number each step and provide specific, actionable advice.\n\n"
                f"\n5. **Disclaimer:**\n"
                f"   - Add a formal disclaimer emphasizing that this assessment is based on the provided scan data and that a comprehensive penetration test is recommended for a complete evaluation.\n\n"
                f"Scan Output:\n{self.nmap_output_for_analysis.strip()}"
            )


            response = chat_session.send_message(ai_prompt)

            # Process and clean the AI's response
            risk_assessment_text = self.clean_response_text(response.text)

            # Extract Risk Levels table dynamically from the AI response
            extracted_risk_levels = self.extract_risk_levels(risk_assessment_text)
            risk_levels_table = self.generate_risk_levels_table(extracted_risk_levels)

            # Display the AI's risk assessment in the risk text area
            self.risk_text.config(state="normal")
            self.risk_text.delete("1.0", tk.END)

            self.risk_text.insert(tk.END, "Nmap Scan Risk Assessment\n\n", "bold")
            self.risk_text.insert(tk.END, "=" * 100 + "\n\n", "normal")
            self.risk_text.insert(tk.END, risk_assessment_text + "\n\n", "normal")
            self.risk_text.insert(tk.END, "Risk Levels:\n", "bold")
            self.risk_text.insert(tk.END, risk_levels_table + "\n\n", "normal")
            self.risk_text.insert(tk.END, "Recommendations:\n", "bold")
            self.risk_text.insert(tk.END, "- Follow best practices to secure services.\n", "normal")
            self.risk_text.insert(tk.END, "- Close unused ports.\n", "normal")
            self.risk_text.insert(tk.END, "- Regularly update software and services.\n", "normal")

            self.risk_text.config(state="disabled")
            self.update_status("Risk analysis completed.")

        except Exception as e:
            self.enqueue_result(f"AI Risk Assessment Error: {str(e)}", for_risk=True)
            self.update_status(f"Error during risk analysis: {str(e)}")

    def extract_risk_levels(self, risk_assessment_text):
        """
        Extract risk levels from the AI response dynamically.
        """
        # Example pattern to match risk levels (adjust based on AI response format)
        risk_level_pattern = re.compile(r"Port:\s*(\d+).*?Service:\s*(.*?)\s*Risk Level:\s*(.*?)\s*Description:\s*(.*?)\n", re.DOTALL)
        matches = risk_level_pattern.findall(risk_assessment_text)

        risk_levels = []
        for match in matches:
            risk_levels.append({
                "Port": match[0],
                "Service": match[1].strip(),
                "Risk Level": match[2].strip(),
                "Description": match[3].strip(),
            })
        return risk_levels

    def generate_risk_levels_table(self, risk_levels):
        """
        Generate a properly formatted and dynamically adjusted table for Risk Levels.
        """
        if not risk_levels:
            return "No risk levels identified in the assessment."

        # Define headers and calculate column widths dynamically
        headers = ["Port", "Service", "Risk Level", "Description"]
        column_widths = {
            "Port": max(len("Port"), max(len(str(item["Port"])) for item in risk_levels)),
            "Service": max(len("Service"), max(len(item["Service"]) for item in risk_levels)),
            "Risk Level": max(len("Risk Level"), max(len(item["Risk Level"]) for item in risk_levels)),
            "Description": max(len("Description"), max(len(item["Description"]) for item in risk_levels)),
        }

        # Add spacing to column widths for better readability
        column_widths = {key: width + 2 for key, width in column_widths.items()}

        # Build header row
        header_row = "|".join(header.center(column_widths[header]) for header in headers)
        separator_row = "+".join("-" * column_widths[header] for header in headers)

        # Build rows dynamically
        rows = []
        for level in risk_levels:
            row = "|".join(
                str(level[key]).ljust(column_widths[key])[:column_widths[key]]
                for key in headers
            )
            rows.append(row)

        # Combine all rows into the final table
        return f"{separator_row}\n{header_row}\n{separator_row}\n" + "\n".join(rows) + f"\n{separator_row}"

    def clean_response_text(self, text):
        """
        Clean the response text to remove stars and unnecessary symbols.
        """
        # Remove stars and unnecessary symbols
        cleaned_text = re.sub(r"\*\*?", "", text)  # Removes single or double asterisks
        cleaned_text = re.sub(r"#{1,6}\s*", "", cleaned_text)  # Removes markdown headings (#, ##, etc.)
        cleaned_text = re.sub(r"={3,}", "", cleaned_text)  # Removes separators (e.g., "===")

        # Normalize spaces and lines
        cleaned_text = re.sub(r"\n{2,}", "\n\n", cleaned_text)  # Replace multiple newlines with a single newline
        return cleaned_text.strip()

    def clear_results(self):
        """Clear all displayed results."""
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.result_text.config(state="disabled")

        self.risk_text.config(state="normal")
        self.risk_text.delete("1.0", tk.END)
        self.risk_text.config(state="disabled")

    def export_results(self):
        """Export scan results and risk assessments to a file."""
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            try:
                with open(file_path, 'w') as file:
                    # Save results
                    results = self.result_text.get("1.0", tk.END).strip()
                    file.write(results)
                messagebox.showinfo("Success", "Results exported successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save the file: {str(e)}")

    def update_result_threadsafe(self):
        """Fetch and display results from the queue."""
        try:
            while not self.result_queue.empty():
                line = self.result_queue.get_nowait()
                self.result_text.config(state="normal")
                self.result_text.insert(tk.END, line + "\n")
                self.result_text.config(state="disabled")

            while not self.risk_queue.empty():
                risk = self.risk_queue.get_nowait()
                self.risk_text.config(state="normal")
                self.risk_text.insert(tk.END, risk + "\n")
                self.risk_text.config(state="disabled")
        except Exception as e:
            print(f"Error updating result: {e}")
        finally:
            self.root.after(100, self.update_result_threadsafe)

    def update_status(self, message):
        """Update the status bar message."""
        self.status_message.set(message)
        self.root.update_idletasks()

    def stop_scan(self):
        """Stop the current scan."""
        self.stop_event.set()
        if self.process:
            self.process.terminate()
        self.progress_value.set(0)  # Reset the progress bar to zero
        self.update_status("Scan stopped.")
        self.scan_button.config(state=NORMAL)
        self.stop_button.config(state=DISABLED)

    def show_about(self):
        """Show information about the application."""
        messagebox.showinfo("About", "NetRiskScanner Tool\nCreated by:\n\n- Mustafa Banikhalaf\n- Mohammad Majdalawy")

    def on_closing(self):
        """Handle the window closing event."""
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.root.destroy()


if __name__ == "__main__":
    app = NetRiskScanner()
    app.root.mainloop()
