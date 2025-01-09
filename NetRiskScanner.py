import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox
from utils.validator import is_valid_target, is_valid_port_range, is_valid_mac_spoof
from utils.Runner_Tool import Runner_Tool
import subprocess
import threading
from queue import Queue
import tkinter as tk
import json
import re
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
        documentation_url = "https://github.com/MustafaFBK/DSC-Nmap-Copy/blob/c822c607fa04429b52b5fd6ef0b7ab9bb716b3a5/NetRiskScanner%20Document.pdf"
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

        self.add_labeled_entry(target_frame, "Port Range:", 15, None, "port_range_entry")
        self.add_labeled_entry(target_frame, "Spoof MAC:", 15, None, "spoof_mac")

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
            self.target_feedback.config(text="Invalid target! Use format 192.168.1.1, CIDR, or example.com.")
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

        self.scan_button = ttk.Button(button_frame, text="Start Scan", command=self.start_scan, bootstyle=SUCCESS)
        self.scan_button.pack(side=LEFT, padx=5)

        self.stop_button = ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan, state=DISABLED, bootstyle=WARNING)
        self.stop_button.pack(side=LEFT, padx=5)

        self.clear_button = ttk.Button(button_frame, text="Clear Results", command=self.clear_results, bootstyle=INFO)
        self.clear_button.pack(side=LEFT, padx=5)

    def create_split_display(self, parent):
        """Create split display: left for scan results, right for risk assessment."""
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

        self.risk_text = ttk.Text(risk_frame, wrap="word", state="disabled", height=20, width=50)
        self.risk_text.pack(side=LEFT, fill=BOTH, expand=True, padx=5)

        risk_scrollbar = ttk.Scrollbar(risk_frame, orient=tk.VERTICAL, command=self.risk_text.yview)
        self.risk_text.config(yscrollcommand=results_scrollbar.set)
        risk_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

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
        # Dynamically set total_lines based on actual scan output if possible
        if current_line > self.total_lines:
            self.total_lines = current_line  # Adjust total lines dynamically

        if self.total_lines > 0:
            progress = min(int((current_line / self.total_lines) * 100), 100)
            self.progress_value.set(progress)


    def start_scan(self):
        """Start the NetRiskScanner scan."""
        target = self.target_entry.get()
        port_range = self.port_range_entry.get()
        spoof_mac = self.spoof_mac.get()

        options = {
            "spoof_mac": spoof_mac,
            "os_detection": self.os_detection.get(),
            "service_scan": self.service_scan.get(),
            "verbose": self.verbose.get(),
            "scan_type": self.scan_type.get(),
            "aggressive_scan": self.aggressive_scan.get(),
            "no_ping": self.no_ping_option.get(),
        }

        if not self.validate_inputs(target, port_range, spoof_mac):
            return

        self.clear_results()
        self.update_status("Scanning...")
        self.scan_button.config(state=DISABLED)
        self.stop_button.config(state=NORMAL)
        self.progress_value.set(0)

        self.stop_event.clear()
        threading.Thread(target=self.run_NetRiskScanner_scan, args=(target, port_range, options), daemon=True).start()

    def validate_inputs(self, target, port_range, spoof_mac):
        """Validate inputs and show error messages if invalid."""
        if not is_valid_target(target):
            messagebox.showerror("Error", "Invalid target. Please enter a valid IP or domain.")
            return False
        if port_range and not is_valid_port_range(port_range):
            messagebox.showerror("Error", "Invalid port range. Enter a valid range (SYN Scan : -sSe.g., 20-80).")
            return False
        if spoof_mac and not is_valid_mac_spoof(spoof_mac):
            messagebox.showerror("Error", "Invalid MAC address format.")
            return False
        return True

    def run_NetRiskScanner_scan(self, target, port_range, options):
        """Run the NetRiskScanner scan command and update progress."""
        try:
            command = self.runner_tool.build_command(target, port_range, options)
            self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            current_line = 0
            for line in self.process.stdout:
                if self.stop_event.is_set():
                    self.process.terminate()
                    self.update_status("Scan stopped.")
                    break

                current_line += 1
                self.enqueue_result(line.strip())
                self.update_progress(current_line)

            for error_line in self.process.stderr:
                self.enqueue_result(f"Error: {error_line.strip()}")

            self.process.wait()

            # Ensure progress bar is complete on successful scan
            if not self.stop_event.is_set():
                self.progress_value.set(100)
                self.update_status("Scan Completed.")
        except Exception as e:
            self.update_status(f"Error: {str(e)}")
            messagebox.showerror("Error", f"Scan failed: {str(e)}")
        finally:
            self.scan_button.config(state=NORMAL)
            self.stop_button.config(state=DISABLED)

            
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
        messagebox.showinfo("About", "NetRiskScanner Tool\nCreated by:\n- Mustafa Banikhalaf\n- Mohammad Majdalawy")

    def on_closing(self):
        """Handle the window closing event."""
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.root.destroy()


if __name__ == "__main__":
    app = NetRiskScanner()
    app.root.mainloop()
