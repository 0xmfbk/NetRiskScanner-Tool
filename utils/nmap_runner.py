import subprocess
import threading


class NmapRunner:
    def __init__(self, update_result_callback):
        """
        Initializes the NmapRunner class.
        Args:
            update_result_callback (function): Callback function to handle scan results in real time.
        """
        self.update_result_callback = update_result_callback
        self.scan_thread = None
        self.scan_process = None
        self.stop_event = threading.Event()  # Event to signal scan termination

    def build_nmap_command(self, target, port_range, options):
        """
        Constructs the Nmap command based on the provided parameters.
        Args:
            target (str): Target IP or domain.
            port_range (str): Port range as a string (e.g., "20-80").
            options (dict): Dictionary of scan options.
        Returns:
            list: List of command arguments for subprocess.
        """
        base_command = ["nmap"]

        # Adding scan type
        scan_type = options.get("scan_type")
        if scan_type:
            base_command.append(scan_type)

        # Adding port range
        if port_range:
            base_command.append(f"-p{port_range}")

        # Adding service detection
        if options.get("service_scan"):
            base_command.append("-sV")

        # Adding OS detection
        if options.get("os_detection"):
            base_command.append("-O")

        # Adding aggressive scan
        if options.get("aggressive_scan"):
            base_command.append("-A")

        # Adding verbose output
        if options.get("verbose"):
            base_command.append("-v")

        # Adding custom script
        script = options.get("script")
        if script:
            base_command.append(f"--script={script}")

        # Adding no ping option
        if options.get("no_ping"):
            base_command.append("-Pn")

        # Adding reason option
        if options.get("reason"):
            base_command.append("--reason")

        # Append target
        base_command.append(target)

        return base_command

    def run_scan(self, command):
        """
        Executes the Nmap scan and streams the output in real time.
        Args:
            command (list): List of command arguments to execute.
        """
        try:
            self.update_result_callback(f"Starting scan: {' '.join(command)}")
            self.scan_process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Stream output line by line
            for line in self.scan_process.stdout:
                if self.stop_event.is_set():
                    self.scan_process.terminate()
                    self.update_result_callback("Scan stopped by user.")
                    break
                self.update_result_callback(line.strip())

            # Check for errors from stderr
            for error_line in self.scan_process.stderr:
                self.update_result_callback(f"Error: {error_line.strip()}")

            self.scan_process.wait()
            if not self.stop_event.is_set():
                self.update_result_callback("Scan completed successfully.")
        except FileNotFoundError:
            self.update_result_callback("Error: Nmap is not installed or not available in the PATH.")
        except Exception as e:
            self.update_result_callback(f"Error during scan: {str(e)}")
        finally:
            self.scan_process = None
            self.stop_event.clear()  # Reset stop event for the next scan

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

        try:
            # Build the Nmap command
            command = self.build_nmap_command(target, port_range, options)

            # Reset stop event
            self.stop_event.clear()

            # Start the scan in a separate thread
            self.scan_thread = threading.Thread(target=self.run_scan, args=(command,), daemon=True)
            self.scan_thread.start()
        except Exception as e:
            self.update_result_callback(f"Error starting scan: {str(e)}")

    def stop_scan(self):
        """
        Stops the currently running scan.
        """
        if self.scan_process and self.scan_process.poll() is None:
            self.stop_event.set()
            try:
                self.scan_process.terminate()
                self.update_result_callback("Scan stopped immediately.")
            except Exception as e:
                self.update_result_callback(f"Error stopping scan: {str(e)}")
        else:
            self.update_result_callback("No active scan to stop.")
