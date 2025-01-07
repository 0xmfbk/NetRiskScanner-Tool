import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox
from utils.validator import is_valid_target, is_valid_port_range, is_valid_mac_spoof
from utils.nmap_runner import NmapRunner
import subprocess
import threading
from queue import Queue
import tkinter as tk  # Explicit import for tkinter widgets like Text


class NmapGUI:
    def __init__(self):
        self.root = ttk.Window(themename="cyborg")  # Use ttkbootstrap's theme
        self.root.title("DSC-Nmap-GUI")
        self.root.geometry("900x700")

        # Initialize variables
        self.nmap_runner = None  # Placeholder for NmapRunner instance
        self.stop_event = threading.Event()

        self.progress_value = ttk.IntVar()
        self.status_message = ttk.StringVar(value="Ready")

        self.result_queue = Queue()

        # Create the UI
        self.create_menu()
        self.create_widgets()

        # Initialize NmapRunner (after defining enqueue_result)
        self.nmap_runner = NmapRunner(self.enqueue_result)

        # Start result updater
        self.update_result_threadsafe()

        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_menu(self):
        """Create the menu bar with file and help options."""
        menu_bar = ttk.Menu(self.root)

        # File Menu
        file_menu = ttk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Export Results", command=self.export_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)
        menu_bar.add_cascade(label="File", menu=file_menu)

        # Help Menu
        help_menu = ttk.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menu_bar.add_cascade(label="Help", menu=help_menu)

        self.root.config(menu=menu_bar)

    def create_widgets(self):
        """Create all widgets and input fields."""
        self.create_target_input()
        self.create_scan_options()
        self.create_scan_buttons()
        self.create_result_display()
        self.create_progress_bar()
        self.create_status_bar()

    def create_target_input(self):
        """Create the target input fields for IP/domain and port range."""
        target_frame = ttk.Labelframe(self.root, text="Target Information", padding=10, bootstyle=PRIMARY)
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

    def create_scan_options(self):
        """Create the scan type and advanced options input fields."""
        options_frame = ttk.Labelframe(self.root, text="Scan Options", padding=10, bootstyle=PRIMARY)
        options_frame.pack(pady=10, fill=X, padx=10)

        self.create_scan_type_options(options_frame)
        self.create_service_detection_options(options_frame)
        self.create_advanced_options(options_frame)

    def create_scan_type_options(self, parent):
        """Create dropdowns for selecting scan types."""
        scan_type_frame = ttk.Labelframe(parent, text="Scan Type", padding=10)
        scan_type_frame.pack(fill=X, padx=5, pady=5)

        self.scan_type = ttk.StringVar()
        basic_scan_types = ["-sn", "-sS", "-sT", "-sU", "-sN", "-sF", "-sX"]
        advanced_scan_types = ["-sA", "-sW", "-sM", "-sC", "-sI", "-sR", "-sP"]

        self.add_labeled_combobox(scan_type_frame, "Basic Scan Type:", basic_scan_types, "scan_type")
        self.add_labeled_combobox(scan_type_frame, "Advanced Scan Type:", advanced_scan_types, "advanced_scan_type")

    def create_service_detection_options(self, parent):
        """Create checkboxes for service detection options."""
        service_frame = ttk.Labelframe(parent, text="Service Detection", padding=10)
        service_frame.pack(fill=X, padx=5, pady=5)

        self.os_detection = ttk.BooleanVar()
        self.service_scan = ttk.BooleanVar()

        self.add_checkbox(service_frame, "OS Detection", self.os_detection)
        self.add_checkbox(service_frame, "Service Scan", self.service_scan)

    def create_advanced_options(self, parent):
        """Create advanced options like verbose, aggressive scan, etc."""
        advanced_options_frame = ttk.Labelframe(parent, text="Advanced Options", padding=10)
        advanced_options_frame.pack(fill=X, padx=5, pady=5)

        self.verbose = ttk.BooleanVar()
        self.aggressive_scan = ttk.BooleanVar()
        self.no_ping_option = ttk.BooleanVar()
        self.reason_option = ttk.BooleanVar()

        self.add_checkbox(advanced_options_frame, "Verbose Output", self.verbose)
        self.add_checkbox(advanced_options_frame, "Aggressive Scan", self.aggressive_scan)
        self.add_checkbox(advanced_options_frame, "No Ping", self.no_ping_option)
        self.add_checkbox(advanced_options_frame, "Include Reason", self.reason_option)

    def add_labeled_combobox(self, parent, label_text, values, attr_name):
        """Helper method to create labeled combobox widgets."""
        ttk.Label(parent, text=label_text).pack(side=LEFT, padx=5)
        combobox = ttk.Combobox(parent, values=values, width=10, bootstyle=INFO)
        combobox.pack(side=LEFT, padx=5)
        setattr(self, attr_name, combobox)

    def add_checkbox(self, parent, label_text, variable):
        """Helper method to create checkbox widgets."""
        ttk.Checkbutton(parent, text=label_text, variable=variable, bootstyle=SUCCESS).pack(side=LEFT, padx=5)

    def create_scan_buttons(self):
        """Create the buttons for starting, stopping, and clearing scans."""
        button_frame = ttk.Frame(self.root, padding=10)
        button_frame.pack(fill=X, padx=10)

        self.scan_button = ttk.Button(button_frame, text="Start Scan", command=self.start_scan, bootstyle=SUCCESS)
        self.scan_button.pack(side=LEFT, padx=5)

        self.stop_button = ttk.Button(button_frame, text="Stop Scan", command=self.start_scan, state=DISABLED, bootstyle=DANGER)
        self.stop_button.pack(side=LEFT, padx=5)

        self.clear_button = ttk.Button(button_frame, text="Clear Results", command=self.clear_results, bootstyle=INFO)
        self.clear_button.pack(side=LEFT, padx=5)

    def create_result_display(self):
        """Create the text boxes for displaying results and errors."""
        result_frame = ttk.Labelframe(self.root, text="Scan Results", padding=10, bootstyle=PRIMARY)
        result_frame.pack(padx=10, pady=10, fill=BOTH, expand=True)

        self.result_text = tk.Text(result_frame, wrap="word", state="disabled", height=20, width=40, bg="#f9f9f9", fg="#333333")
        self.result_text.pack(side=LEFT, padx=5, pady=5, fill=BOTH, expand=True)

        self.error_text = tk.Text(result_frame, wrap="word", state="disabled", height=20, width=40, bg="#f9f9f9", fg="red")
        self.error_text.pack(side=LEFT, padx=5, pady=5, fill=BOTH, expand=True)

    def create_progress_bar(self):
        """Create the progress bar to show scan progress."""
        progress_frame = ttk.Labelframe(self.root, text="Scan Progress", padding=10, bootstyle=PRIMARY)
        progress_frame.pack(fill=X, padx=10, pady=5)

        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_value, maximum=100, bootstyle=INFO)
        self.progress_bar.pack(fill=X, expand=True)

    def create_status_bar(self):
        """Create the status bar at the bottom of the window."""
        status_frame = ttk.Frame(self.root, padding=5)
        status_frame.pack(fill=X, side=BOTTOM)

        self.status_label = ttk.Label(status_frame, textvariable=self.status_message, anchor=W, bootstyle=SECONDARY)
        self.status_label.pack(fill=X)

    def update_status(self, message):
        """Update the status bar message."""
        self.status_message.set(message)

    def enqueue_result(self, result_line):
        """Add result lines to the queue for thread-safe updates."""
        self.result_queue.put(result_line)

    def update_result_threadsafe(self):
        """Fetch and display results from the queue."""
        try:
            while not self.result_queue.empty():
                line = self.result_queue.get_nowait()
                self.result_text.config(state="normal")
                self.result_text.insert(tk.END, line + "\n")
                self.result_text.config(state="disabled")
        except Exception as e:
            print(f"Error updating result: {e}")
        finally:
            self.root.after(100, self.update_result_threadsafe)

    def start_scan(self):
        """Start the Nmap scan with the provided options."""
        target = self.target_entry.get()
        port_range = self.port_range_entry.get()
        spoof_mac = self.spoof_mac.get()

        options = {
            "spoof_mac": spoof_mac,
            "os_detection": self.os_detection.get(),
            "service_scan": self.service_scan.get(),
            "verbose": self.verbose.get(),
            "scan_type": self.scan_type.get() or self.advanced_scan_type.get(),
            "aggressive_scan": self.aggressive_scan.get(),
            "no_ping": self.no_ping_option.get(),
            "reason": self.reason_option.get(),  # Include reason checkbox
        }

        if not self.validate_inputs(target, port_range, spoof_mac):
            return

        self.clear_results()
        self.update_status("Scanning...")
        self.scan_button.config(state=DISABLED)
        self.stop_button.config(state=NORMAL)

        self.stop_event.clear()
        threading.Thread(target=self.run_nmap_scan, args=(target, port_range, options), daemon=True).start()

    def validate_inputs(self, target, port_range, spoof_mac):
        """Validate inputs and show error messages if invalid."""
        if not is_valid_target(target):
            messagebox.showerror("Error", "Invalid target. Please enter a valid IP or domain.")
            return False
        if port_range and not is_valid_port_range(port_range):
            messagebox.showerror("Error", "Invalid port range. Enter a valid range (e.g., 20-80).")
            return False
        if spoof_mac and not is_valid_mac_spoof(spoof_mac):
            messagebox.showerror("Error", "Invalid MAC address format.")
            return False
        return True

    def run_nmap_scan(self, target, port_range, options):
        """Run the Nmap scan command."""
        try:
            nmap_command = self.nmap_runner.build_nmap_command(target, port_range, options)
            process = subprocess.Popen(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for line in process.stdout:
                if self.stop_event.is_set():
                    process.terminate()
                    self.update_status("Scan stopped.")
                    break
                self.enqueue_result(line.strip())
            process.wait()
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

        self.error_text.config(state="normal")
        self.error_text.delete("1.0", tk.END)
        self.error_text.config(state="disabled")

    def export_results(self):
        """Export scan results to a file."""
        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text files", "*.txt"), ("JSON files", "*.json")])
        if file_path:
            try:
                with open(file_path, 'w') as file:
                    if file_path.endswith('.json'):
                        import json
                        file.write(json.dumps({"results": self.result_text.get("1.0", tk.END).strip()}, indent=4))
                    else:
                        file.write(self.result_text.get("1.0", tk.END).strip())
                messagebox.showinfo("Success", "Results exported successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save the file: {str(e)}")

    def show_about(self):
        """Show information about the application."""
        messagebox.showinfo("About", "DSC-Nmap-GUI\nCreated by:\n- Mustafa Banikhalaf\n- Mohammad Majdalawy")

    def on_closing(self):
        """Handle the window closing event."""
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.root.destroy()


if __name__ == "__main__":
    app = NmapGUI()
    app.root.mainloop()
