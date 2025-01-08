import subprocess
import threading
import json


class NmapRunner:
    def __init__(self, update_result_callback, update_risk_callback=None):
        """
        Initializes the NmapRunner class.
        Args:
            update_result_callback (function): Callback function to handle scan results in real time.
            update_risk_callback (function): Optional callback to handle risk assessment based on scan results.
        """
        self.update_result_callback = update_result_callback
        self.update_risk_callback = update_risk_callback
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
            base_command.append(scan_type.split(": ")[1])  # Extract the actual command part

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

        # Adding fragmented packet scan option
        if options.get("Fragmented Packet Scan"):
            base_command.append("-f")

        # Adding timing template
        timing_template = options.get("timing_template")
        if timing_template:
            base_command.append(timing_template.split(" ")[0])  # Extract T0-T5

        # Validate and append target
        if target:
            base_command.append(target)
        else:
            raise ValueError("Target cannot be empty.")

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

            scan_results = []
            # Stream output line by line
            for line in self.scan_process.stdout:
                if self.stop_event.is_set():
                    self.scan_process.terminate()
                    self.update_result_callback("Scan stopped by user.")
                    return
                scan_results.append(line.strip())
                self.update_result_callback(line.strip())

            # Capture any errors
            for error_line in self.scan_process.stderr:
                self.update_result_callback(f"Error: {error_line.strip()}")

            self.scan_process.wait()

            # Perform risk assessment on scan results
            if not self.stop_event.is_set() and self.update_risk_callback:
                risk_report = self.perform_risk_assessment(scan_results)
                self.update_risk_callback(risk_report)

            if not self.stop_event.is_set():
                self.update_result_callback("Scan completed successfully.")
        except FileNotFoundError:
            self.update_result_callback("Error: Nmap is not installed or not available in the PATH.")
        except ValueError as e:
            self.update_result_callback(f"Invalid scan parameters: {e}")
        except Exception as e:
            self.update_result_callback(f"Unexpected error during scan: {str(e)}")
        finally:
            self.scan_process = None
            self.stop_event.clear()  # Reset stop event for the next scan

    def perform_risk_assessment(self, scan_results):
        """
        Analyzes the scan results and generates a risk assessment report.
        Args:
            scan_results (list): List of scan result lines.
        Returns:
            str: Risk assessment report in string format.
        """
        open_ports = []
        vulnerabilities = []

        # Parse results to identify risks
        for line in scan_results:
            if "open" in line:  # Look for open ports
                open_ports.append(line)
            if "vulnerable" in line or "CVE" in line:  # Look for vulnerability mentions
                vulnerabilities.append(line)

        # Compile risk report
        risk_report = {
            "Open Ports": open_ports,
            "Potential Vulnerabilities": vulnerabilities
        }

        return json.dumps(risk_report, indent=4)

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
        except ValueError as e:
            self.update_result_callback(f"Error starting scan: {e}")
        except Exception as e:
            self.update_result_callback(f"Unexpected error starting scan: {str(e)}")

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
