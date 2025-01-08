import re
from ipaddress import ip_address, ip_network

def expand_ip_range_with_octet(start_ip, end_octet):
    """
    Expands an IP range with a fixed prefix (e.g., '192.168.1.1-10') into a list of IPs.
    The range is applied to the last octet.
    """
    start = ip_address(start_ip)
    start_prefix = '.'.join(str(x) for x in str(start).split('.')[:-1])  # Get the first three octets
    start_last_octet = int(str(start).split('.')[-1])  # Last octet of the start IP
    end_last_octet = int(end_octet)  # The end of the range

    # Generate the list of IPs with the expanded last octet
    return [f"{start_prefix}.{i}" for i in range(start_last_octet, end_last_octet + 1)]

def expand_ipv4_cidr_range(cidr):
    """
    Expands a CIDR range into a list of IP addresses.
    """
    network = ip_network(cidr, strict=False)
    return [str(ip) for ip in network.hosts()]

def is_valid_target(target):
    """
    Validates the target input for:
    - Single IPv4 addresses.
    - IPv4 CIDR notation (e.g., '192.168.1.1/24').
    - Domain names.
    - IPv6 addresses.
    - Ranges with last octet (e.g., '192.168.1.1-10').
    - Space-separated targets (e.g., '192.168.1.1 192.168.1.195').
    """
    # Regular expressions for valid IP addresses, domain names, and ranges
    ipv4_pattern = r"^((25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})(\.(?!$)|$)){4}$"
    domain_pattern = r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    ipv6_pattern = r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
    ipv4_range_pattern = r"^(\d{1,3}(\.\d{1,3}){3})-(\d{1,3}(\.\d{1,3}){3})$"
    ipv4_last_octet_range_pattern = r"^(\d{1,3}(\.\d{1,3}){3})-(\d+)$"  # For range format like '192.168.1.1-10'
    ipv4_cidr_pattern = r"^(\d{1,3}(\.\d{1,3}){3})/(\d{1,2})$"  # CIDR notation (e.g., 192.168.1.1/24)

    if not target or not isinstance(target, str):
        return False

    # Split by spaces for multiple targets
    targets = target.split()

    expanded_targets = []  # To store expanded IPs

    for t in targets:
        t = t.strip()  # Remove any leading or trailing whitespace

        # Check if it's a valid IPv4 address
        if re.match(ipv4_pattern, t):
            expanded_targets.append(t)
            continue

        # Check if it's a valid domain
        if re.match(domain_pattern, t):
            expanded_targets.append(t)
            continue

        # Check if it's a valid IPv6 address
        if re.match(ipv6_pattern, t):
            expanded_targets.append(t)
            continue

        # Check if it's a valid range with the last octet (e.g., '192.168.1.1-10')
        if re.match(ipv4_last_octet_range_pattern, t):
            try:
                start_ip, end_octet = t.split('-')
                if not end_octet.isdigit() or not (0 <= int(end_octet) <= 255):
                    return False  # Ensure the range is valid
                expanded_targets.extend(expand_ip_range_with_octet(start_ip, end_octet))
                continue
            except ValueError:
                return False

        # Skip processing of the range format '192.168.1.1-192.168.1.100'
        if re.match(ipv4_range_pattern, t):
            continue  # Simply skip this case, it won't be processed

        # Check if it's a valid IPv4 CIDR notation (e.g., '192.168.1.1/24')
        if re.match(ipv4_cidr_pattern, t):
            try:
                network = expand_ipv4_cidr_range(t)
                expanded_targets.extend(network)
                continue
            except ValueError:
                return False

        # Check if it's a valid IPv4 network (CIDR)
        try:
            network = ip_network(t, strict=False)  # Validate the network
            expanded_targets.append(str(network))
            continue
        except ValueError:
            pass

        # If none of the above match, return False
        return False

    return expanded_targets

def is_valid_mac_spoof(mac):
    """Validate the spoofed MAC address format."""
    mac_regex = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    return re.match(mac_regex, mac)

def is_valid_port_range(port_range):
    """
    Validates the port range format and limits:
    - Single port (e.g., '22').
    - Comma-separated ports (e.g., '22,80,443').
    - Port ranges (e.g., '22-80').
    """
    if not port_range:
        return True  # Port range is optional

    if not isinstance(port_range, str):
        return False

    # Check for comma-separated ports (e.g., '22,80,443')
    if re.match(r'^\d+(,\d+)*$', port_range):
        try:
            ports = map(int, port_range.split(','))
            return all(0 <= port <= 65535 for port in ports)
        except ValueError:
            return False

    # Check for port range format (e.g., '22-80')
    match = re.match(r"^(\d+)(-(\d+))?$", port_range)
    if match:
        try:
            start = int(match.group(1))
            end = int(match.group(3)) if match.group(3) else start
            return 0 <= start <= 65535 and start <= end
        except ValueError:
            return False

    return False
