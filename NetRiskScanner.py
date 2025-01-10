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
import sys

class NetRiskScanner:
    def __init__(self):
        self.root = ttk.Window(themename="cyborg")
        self.root.title("NetRiskScanner Tool")
        self.style = ttk.Style()

        # Get the screen width and height
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        # Set the window geometry to the maximum screen size
        self.root.geometry(f"{screen_width}x{screen_height}+0+0")

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
        documentation_url = "https://github.com/MustafaFBK/NetRiskScanner-Tool/blob/56afaa4ba4b58967b3bdd1ab1dfe075226537da5/NetRiskScanner%20Document.pdf"
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
        # Default dimensions
        default_width = 1200
        default_height = 700

        # Check for dimensions passed from the frontend
        if len(sys.argv) == 3:
            try:
                width = int(sys.argv[1])
                height = int(sys.argv[2])
                self.root.geometry(f"{width}x{height}")
            except ValueError:
                self.root.geometry(f"{default_width}x{default_height}")
        else:
            self.root.geometry(f"{default_width}x{default_height}")

        self.add_checkbox(options_frame, "OS Detection", self.os_detection)
        self.add_checkbox(options_frame, "Service Scan", self.service_scan)
        self.add_checkbox(options_frame, "Verbose", self.verbose)
        self.add_checkbox(options_frame, "Aggressive Scan", self.aggressive_scan)
        self.add_checkbox(options_frame, "No Ping", self.no_ping_option)

    def add_checkbox(self, parent, label_text, variable):
        """Helper method to create checkbox widgets."""
        ttk.Checkbutton(parent, text=label_text, variable=variable, bootstyle=SUCCESS).pack(side=LEFT, padx=5)

    def create_scan_buttons(self, parent):
        """Create the buttons for starting, stopping, clearing scans, and saving results."""
        button_frame = ttk.Frame(parent, padding=10)
        button_frame.pack(fill=X, padx=10)

        # Buttons
        self.scan_button = ttk.Button(button_frame, text="Start Scan", command=self.start_scan, bootstyle=SUCCESS)
        self.scan_button.pack(side=LEFT, padx=5)

        self.stop_button = ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan, state=DISABLED, bootstyle=WARNING)
        self.stop_button.pack(side=LEFT, padx=5)

        self.clear_button = ttk.Button(button_frame, text="Clear Everything", command=self.clear_results, state=DISABLED, bootstyle=INFO)
        self.clear_button.pack(side=LEFT, padx=5)

        self.command_display = ttk.Entry(button_frame, width=80, state="readonly")
        self.command_display.pack(side=LEFT, padx=5, fill=X, expand=True)

        self.copy_button = ttk.Button(button_frame, text="Copy Command", command=self.copy_command, state=DISABLED, bootstyle=INFO)
        self.copy_button.pack(side=LEFT, padx=5)

        self.analysis_button = ttk.Button(button_frame, text="Result Analysis", command=self.perform_risk_analysis, state=DISABLED, bootstyle=PRIMARY)
        self.analysis_button.pack(side=LEFT, padx=5)

        self.save_button = ttk.Button(button_frame, text="Save the result", command=self.export_results, state=DISABLED, bootstyle=SUCCESS)
        self.save_button.pack(side=LEFT, padx=5)

    def save_risk_assessment(self):
        """Save the Risk Assessment results to a text file."""
        try:
            # Open file dialog to select save location
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt")],
                title="Save Risk Assessment"
            )
            if not file_path:
                return  # User canceled the save dialog

            # Fetch the Risk Assessment content
            self.risk_text.config(state="normal")  # Temporarily unlock the text widget
            risk_assessment_content = self.risk_text.get("1.0", tk.END).strip()
            self.risk_text.config(state="disabled")  # Lock the text widget back

            # Save the content to the chosen file
            with open(file_path, "w", encoding="utf-8") as file:
                file.write(risk_assessment_content)

            messagebox.showinfo("Success", "Risk Assessment saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save Risk Assessment: {str(e)}")


    def copy_command(self):
        """Copy the raw command to the clipboard."""
        self.root.clipboard_clear()
        self.root.clipboard_append(self.command_display.get())
        self.root.update()  # Ensure the clipboard content is updated
        messagebox.showinfo("Copied", "Command copied to clipboard.")

    def create_split_display(self, parent):
        """
        Create split display: left for scan results, right for risk assessment.
        Includes a correctly placed horizontal scrollbar for the Risk Assessment text area.
        """
        display_frame = ttk.Frame(parent)
        display_frame.pack(fill=BOTH, expand=True, padx=10, pady=10)

        # Left: Scan Results
        results_frame = ttk.Labelframe(display_frame, text="Scan Results", padding=10, bootstyle=PRIMARY)
        results_frame.pack(side=LEFT, fill=BOTH, expand=True, padx=(0, 5))

        self.result_text = ttk.Text(results_frame, wrap="word", state="disabled", height=20, width=50)
        self.result_text.pack(side=LEFT, fill=BOTH, expand=True, padx=5)

        results_scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.result_text.yview)
        self.result_text.config(yscrollcommand=results_scrollbar.set)
        results_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

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
        """Create an optimized progress bar."""
        progress_frame = ttk.Labelframe(
            parent, text="Scan Progress", padding=10, bootstyle=PRIMARY
        )
        progress_frame.pack(fill=X, padx=10, pady=5)

        # Progress bar with clean style
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            variable=self.progress_value,
            maximum=100,
            bootstyle="success",  # Changed to "success" for a clean look
            mode="determinate",
        )
        self.progress_bar.pack(fill=X, expand=True)

    def create_status_bar(self, parent):
        """Create an optimized status bar with colored text."""
        status_frame = ttk.Frame(parent, padding=5)
        status_frame.pack(fill=X, side=BOTTOM)

        self.status_label = ttk.Label(
            status_frame,
            textvariable=self.status_message,
            anchor=W,
            font=("Helvetica", 10, "bold"),
            bootstyle=WARNING,  # Changed for better visibility
        )
        self.status_label.pack(fill=X)

    def update_progress(self, phase, current, total=None):
        """
        Update the progress bar dynamically and synchronize with the current phase.

        Args:
            phase (str): The current phase ("Scanning" or "Analysis").
            current (int): The current progress count.
            total (int, optional): Total progress count. If None, it defaults to the stored total_lines.
        """
        if total is not None:
            self.total_lines = total  # Dynamically update the total lines if provided

        if self.total_lines > 0:
            # Calculate progress as a percentage
            progress = min(int((current / self.total_lines) * 100), 100)
            self.progress_value.set(progress)  # Update the progress bar value
            # Provide synchronized feedback in the status bar
            self.update_status(f"{phase}: {progress}% completed")
            # Update the UI in real-time
            self.root.update_idletasks()
            
    def reset_progress(self):
        """
        Reset progress bar, stop any ongoing process, and clear progress-related variables.
        """
        # Stop any ongoing process
        self.stop_event.set()
        if self.process:
            self.process.terminate()
            self.process = None

        # Reset the progress bar
        self.progress_value.set(0)

        # Update status
        self.update_status("Progress reset. Ready for a new scan.")

                    
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

        # Validate inputs
        if not self.validate_inputs(target, port_range):
            return

        # Reset progress and results
        self.reset_progress()
        self.clear_results()

        # Build the scan command
        command = " ".join(self.runner_tool.build_command(target, port_range, options))

        # Display the raw command
        self.command_display.config(state="normal")
        self.command_display.delete(0, tk.END)
        self.command_display.insert(0, command)
        self.command_display.config(state="readonly")

        # Enable or disable the Copy Command button based on the command presence
        self.copy_button.config(state=NORMAL if command.strip() else DISABLED)

        # Update UI for scan initiation
        self.update_status("Scanning...")
        self.scan_button.config(state=DISABLED)
        self.stop_button.config(state=NORMAL)
        self.clear_button.config(state=NORMAL)  # Enable the Clear Results button
        self.progress_value.set(0)

        # Start the scan in a separate thread
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
        """
        Execute the Nmap scan with real-time progress updates and error handling.

        Args:
            target (str): The target IP or domain.
            port_range (str): The port range to scan.
            options (dict): Additional options for the scan.
        """
        try:
            # Build the command for Nmap
            command = self.runner_tool.build_command(target, port_range, options)
            self.update_status("Executing Nmap scan...")
            self.enqueue_result(f"Executing: {' '.join(command)}")

            # Start the Nmap scan subprocess
            self.process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

            # Initialize progress tracking
            total_lines_estimate = 100  # Estimated total output lines for progress
            current_line = 0
            nmap_output = ""

            # Capture and process the Nmap output in real-time
            for line in self.process.stdout:
                if self.stop_event.is_set():
                    self.process.terminate()
                    self.update_status("Scan stopped by user.")
                    return

                nmap_output += line  # Append the output to the full result
                self.enqueue_result(line.strip())  # Display results in the GUI
                current_line += 1

                # Update progress dynamically
                self.update_progress("Scanning", current_line, total_lines_estimate)

            # Capture and process any errors from stderr
            for error_line in self.process.stderr:
                self.enqueue_result(f"Error: {error_line.strip()}")

            # Wait for the scan process to complete
            self.process.wait()

            # Check if the scan was stopped by the user
            if self.stop_event.is_set():
                self.update_status("Scan stopped.")
                return

            # Finalize the scan results
            self.nmap_output_for_analysis = nmap_output
            self.progress_value.set(100)  # Set progress bar to 100%
            self.update_status("Scan completed successfully. You can now perform risk analysis.")
            self.analysis_button.config(state=NORMAL)  # Enable the "Do Analysis" button

        except Exception as e:
            self.update_status(f"Error during scan: {str(e)}")
            self.enqueue_result(f"Runtime Error: {str(e)}")

        finally:
            # Cleanup and reset UI elements
            self.scan_button.config(state=NORMAL)
            self.stop_button.config(state=DISABLED)
            self.update_status("Ready")
            
            
            
    def perform_risk_analysis(self):
        """
        Perform risk analysis using AI with a slow progress bar for better user experience.
        """
        try:
            # Ensure scan results are available for analysis
            if not hasattr(self, "nmap_output_for_analysis") or not self.nmap_output_for_analysis.strip():
                messagebox.showerror("Error", "No Nmap output available for analysis.")
                return

            # Reset the progress bar and initialize status
            self.progress_value.set(0)
            self.update_status("Performing risk analysis using AI...")
            self.enqueue_result("Starting AI Risk Assessment...")
            self.stop_event.clear()  # Ensure stop event is clear before starting

            # Configure Google Generative AI
            api_key = "AIzaSyBgf4etgJtM3y40kiRDUxbYQmtozzXa2T0"  # Replace with your actual API key
            if not api_key:
                messagebox.showerror("Error", "AI API key is missing. Please set the GEMINI_API_KEY environment variable.")
                return

            genai.configure(api_key=api_key)

            model = genai.GenerativeModel(
                model_name="gemini-1.5-flash-8b",
                generation_config = {
                "temperature": 2,
                "top_p": 0.95,
                "top_k": 40,
                "max_output_tokens": 8192,
                "response_mime_type": "text/plain",
                }
            )
            chat_session = model.start_chat(history=[])

            # Read the AI prompt template from an external file
            try:
                with open("ai_prompt.txt", "r", encoding="utf-8") as file:
                    ai_prompt_template = file.read()
            except FileNotFoundError:
                messagebox.showerror("Error", "AI prompt file 'ai_prompt.txt' not found.")
                return

            # Prepare the AI prompt with scan results
            ai_prompt = f"{ai_prompt_template}\n{self.nmap_output_for_analysis.strip()}"

            def analysis_task():
                try:
                    # Perform the analysis process
                    response = chat_session.send_message(ai_prompt)

                    # Process and clean the AI's response
                    risk_assessment_text = self.clean_response_text(response.text)

                    # Extract Risk Levels table and recommendations dynamically
                    extracted_risk_levels = self.extract_risk_levels(risk_assessment_text)
                    risk_levels_table = self.generate_risk_levels_table(extracted_risk_levels)

                    # Display the risk assessment in the GUI
                    self.risk_text.config(state="normal")
                    self.risk_text.delete("1.0", tk.END)

                    self.risk_text.insert(tk.END, "Nmap Scan Risk Assessment\n\n", "bold")
                    self.risk_text.insert(tk.END, "=" * 20 + "\n\n", "normal")
                    self.risk_text.insert(tk.END, risk_assessment_text + "\n\n", "normal")
                    self.risk_text.insert(tk.END, "Risk Levels:\n", "bold")
                    self.risk_text.insert(tk.END, risk_levels_table + "\n\n", "normal")
                    self.risk_text.insert(tk.END, "Recommendations:\n", "bold")
                    self.risk_text.insert(tk.END, "- Follow best practices to secure services.\n", "normal")
                    self.risk_text.insert(tk.END, "- Close unused ports.\n", "normal")
                    self.risk_text.insert(tk.END, "- Regularly update software and services.\n", "normal")

                    self.risk_text.config(state="disabled")
                    self.update_status("Risk analysis completed.")
                    self.save_button.config(state=NORMAL)  # Enable save button

                    # Mark analysis as done for progress synchronization
                    self.analysis_completed = True

                except Exception as e:
                    self.enqueue_result(f"AI Risk Assessment Error: {str(e)}", for_risk=True)
                    self.update_status(f"Error during risk analysis: {str(e)}")

            def progress_task():
                """
                Slow progress bar simulation, independent of the actual analysis speed.
                """
                self.analysis_completed = False  # Flag to monitor analysis completion
                progress = 0
                while progress < 100:
                    if self.stop_event.is_set() or self.analysis_completed:
                        break

                    # Increment progress bar slowly
                    progress = min(progress + 1, 100)
                    self.progress_value.set(progress)
                    self.update_status(f"Analysis in progress... {progress}% completed")
                    self.root.update_idletasks()
                    threading.Event().wait(0.1)  # Adjust this delay to control speed (slower with higher delay)

                # Ensure progress bar is at 100% when analysis completes
                if self.analysis_completed:
                    self.progress_value.set(100)
                    self.update_status("Risk analysis completed.")

            # Run the analysis and progress tasks in separate threads
            analysis_thread = threading.Thread(target=analysis_task, daemon=True)
            progress_thread = threading.Thread(target=progress_task, daemon=True)

            analysis_thread.start()
            progress_thread.start()

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

        # Define headers
        headers = ["Port", "Service", "Risk Level", "Description"]

        # Calculate column widths dynamically based on the content
        column_widths = {
            "Port": max(len("Port"), *(len(str(item["Port"])) for item in risk_levels)),
            "Service": max(len("Service"), *(len(item["Service"]) for item in risk_levels)),
            "Risk Level": max(len("Risk Level"), *(len(item["Risk Level"]) for item in risk_levels)),
            "Description": max(len("Description"), *(len(item["Description"]) for item in risk_levels)),
        }

        # Add padding to column widths for better readability
        column_widths = {key: width + 2 for key, width in column_widths.items()}

        # Build header row
        header_row = "|".join(header.ljust(column_widths[header]) for header in headers)
        separator_row = "+".join("-" * column_widths[header] for header in headers)

        # Build table rows dynamically
        rows = []
        for level in risk_levels:
            row = "|".join(
                str(level[header]).ljust(column_widths[header])[:column_widths[header]]
                for header in headers
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
        """
        Clear all displayed results, reset progress bar, disable the "Clear Results" button,
        and disable action buttons.
        """
        # Stop all active tasks
        self.stop_event.set()

        # Clear Scan Results
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.result_text.config(state="disabled")

        # Clear Risk Assessment Results
        self.risk_text.config(state="normal")
        self.risk_text.delete("1.0", tk.END)
        self.risk_text.config(state="disabled")

        # Reset Progress Bar
        self.progress_value.set(0)

        # Clear the command display field
        self.command_display.config(state="normal")
        self.command_display.delete(0, tk.END)
        self.command_display.config(state="readonly")

        # Disable Buttons
        self.analysis_button.config(state=DISABLED)
        self.save_button.config(state=DISABLED)
        self.copy_button.config(state=DISABLED)
        self.clear_button.config(state=DISABLED)  # Disable the "Clear Results" button

        # Update Status
        self.update_status("Results cleared. Ready for a new scan.")

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
            
            # Enable the "Save" button if the Risk Assessment is not empty
            if self.risk_text.get("1.0", tk.END).strip():
                self.save_button.config(state=NORMAL)
            else:
                self.save_button.config(state=DISABLED)
        except Exception as e:
            print(f"Error updating result: {e}")
        finally:
            self.root.after(100, self.update_result_threadsafe)

    def update_status(self, message):
        """Update the status bar message."""
        self.status_message.set(message)
        self.root.update_idletasks()

    def stop_scan(self):
        """
        Stop the current scan and reset progress.
        """
        self.reset_progress()
        self.scan_button.config(state=NORMAL)
        self.stop_button.config(state=DISABLED)
        self.clear_button.config(state=NORMAL)  # Allow clearing results after stopping

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
