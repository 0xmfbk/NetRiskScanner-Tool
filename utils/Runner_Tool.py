import subprocess
import threading

class Runner_Tool:
    def __init__(self, update_result_callback, update_risk_callback=None):
        """
        Initializes the Runner_Tool class.
        Args:
            update_result_callback (function): Callback function to handle scan results in real-time.
            update_risk_callback (function): Optional callback to handle risk assessment based on scan results.
        """
        self.update_result_callback = update_result_callback
        self.update_risk_callback = update_risk_callback
        self.scan_thread = None
        self.scan_process = None
        self.stop_event = threading.Event()

    def build_command(self, target, port_range, options):
        """
        Constructs the Nmap command based on the provided parameters.
        Args:
            target (str): Target IP or domain.
            port_range (str): Port range as a string (e.g., "20-80").
            options (dict): Dictionary of scan options.
        Returns:
            list: List of command arguments for subprocess.
        """
        command = ["nmap"]

        # Map option keys to their corresponding command flags
        option_mapping = {
            "scan_type": lambda value: value.split(": ")[1],
            "service_scan": lambda _: "-sV",
            "os_detection": lambda _: "-O",
            "aggressive_scan": lambda _: "-A",
            "verbose": lambda _: "-v",
            "no_ping": lambda _: "-Pn",
           # "spoof_mac": lambda value: f"--spoof-mac {value}",
            "timing_template": lambda value: value
        }

        # Append options based on the mapping
        for key, handler in option_mapping.items():
            if key in options and options[key]:
                command.append(handler(options[key]))

        # Append port range and target
        if port_range:
            command.append(f"-p{port_range}")
        if target:
            command.append(target)
        else:
            raise ValueError("Target cannot be empty.")

        return command

    def run_scan(self, target, port_range, options):
        """
        Executes the scan command and updates the progress.
        """
        try:
            command = self.build_command(target, port_range, options)
            self.update_result_callback(f"Executing: {' '.join(command)}")

            self.scan_process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

            for line in self.scan_process.stdout:
                if self.stop_event.is_set():
                    self.scan_process.terminate()
                    self.update_result_callback("Scan stopped by user.")
                    return
                self.update_result_callback(line.strip())

            for error_line in self.scan_process.stderr:
                self.update_result_callback(f"Error: {error_line.strip()}")

            self.scan_process.wait()

            if not self.stop_event.is_set():
                self.update_result_callback("Scan Completed Successfully.")
                if self.update_risk_callback:
                    self.update_risk_callback("Risk assessment initiated.")

        except ValueError as ve:
            self.update_result_callback(f"Input Error: {str(ve)}")
        except Exception as e:
            self.update_result_callback(f"Runtime Error: {str(e)}")
        finally:
            self.cleanup_process()

    def terminate_scan_process(self):
        """
        Terminates the scan subprocess gracefully, or forcefully if necessary.
        """
        if self.scan_process:
            try:
                self.scan_process.terminate()
                self.scan_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.scan_process.kill()
                self.update_result_callback("Scan process forcefully terminated.")
            finally:
                self.cleanup_process()

    def cleanup_process(self):
        """
        Resets the scan process and stop event.
        """
        self.scan_process = None
        self.stop_event.clear()
        self.update_result_callback("Scan process cleaned up.")

    def start_scan(self, target, port_range, options):
        """
        Starts a new scan in a separate thread.
        Args:
            target (str): Target IP or domain.
            port_range (str): Port range as a string (e.g., "20-80").
            options (dict): Dictionary of scan options.
        """
        if self.scan_thread and self.scan_thread.is_alive():
            self.update_result_callback("A scan is already in progress. Please wait.")
            return

        self.stop_event.clear()
        self.scan_thread = threading.Thread(
            target=self.run_scan, args=(target, port_range, options), daemon=True
        )
        self.scan_thread.start()
        self.update_result_callback("Scan started in a separate thread.")

    def stop_scan(self):
        """
        Stops the currently running scan.
        """
        if self.scan_process and self.scan_process.poll() is None:
            self.stop_event.set()
            self.terminate_scan_process()
        else:
            self.update_result_callback("No active scan to stop.")
