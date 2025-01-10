import re
from ipaddress import ip_address, ip_network

def expand_ip_range_with_octet(start_ip, end_octet):
    """
    Expands an IP range with a fixed prefix (e.g., '192.168.1.1-10') into a list of IPs.
    The range is applied to the last octet.
    """
    start = ip_address(start_ip)
    start_prefix = '.'.join(str(start).split('.')[:-1])  # Get the first three octets
    start_last_octet = int(start.exploded.split('.')[-1])  # Last octet of the start IP
    end_last_octet = int(end_octet)

    return [f"{start_prefix}.{i}" for i in range(start_last_octet, end_last_octet + 1)]

def expand_ipv4_cidr_range(cidr):
    """
    Expands a CIDR range into a list of IP addresses.
    """
    return [str(ip) for ip in ip_network(cidr, strict=False).hosts()]

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
    if not target or not isinstance(target, str):
        return False

    # Regular expressions for valid inputs
    patterns = {
        "ipv4": r"^((25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})(\.(?!$)|$)){4}$",
        "domain": r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$",
        "ipv6": r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$",
        "ipv4_range": r"^(\d{1,3}(\.\d{1,3}){3})-(\d{1,3}(\.\d{1,3}){3})$",
        "last_octet_range": r"^(\d{1,3}(\.\d{1,3}){3})-(\d+)$",
        "ipv4_cidr": r"^(\d{1,3}(\.\d{1,3}){3})/(\d{1,2})$",
    }

    expanded_targets = []

    for t in map(str.strip, target.split()):  # Handle space-separated targets
        if re.match(patterns["ipv4"], t):
            expanded_targets.append(t)
        elif re.match(patterns["domain"], t):
            expanded_targets.append(t)
        elif re.match(patterns["ipv6"], t):
            expanded_targets.append(t)
        elif re.match(patterns["last_octet_range"], t):
            try:
                start_ip, end_octet = t.split('-')
                if 0 <= int(end_octet) <= 255:
                    expanded_targets.extend(expand_ip_range_with_octet(start_ip, end_octet))
                else:
                    return False
            except ValueError:
                return False
        elif re.match(patterns["ipv4_cidr"], t):
            try:
                expanded_targets.extend(expand_ipv4_cidr_range(t))
            except ValueError:
                return False
        elif re.match(patterns["ipv4_range"], t):
            # Currently unsupported format
            continue
        else:
            try:
                network = ip_network(t, strict=False)
                expanded_targets.append(str(network))
            except ValueError:
                return False

    return expanded_targets

def is_valid_ip_spoof(ip):
    """Validate the spoofed IP address format."""
    return bool(re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ip))

def is_valid_mac_spoof(mac):
    """Validate the spoofed MAC address format."""
    is_valid = bool(re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac))
    if not is_valid:
        print(f"Invalid MAC address: {mac}")  # Debug statement
    return is_valid

def is_valid_port_range(port_range):
    """
    Validates the port range format and limits:
    - Single port (e.g., '22').
    - Comma-separated ports (e.g., '22,80,443').
    - Port ranges (e.g., '22-80').
    """
    if not port_range:
        return True  # Port range is optional

    if re.match(r'^\d+(,\d+)*$', port_range):  # Comma-separated ports
        try:
            return all(0 <= int(port) <= 65535 for port in port_range.split(','))
        except ValueError:
            return False

    match = re.match(r"^(\d+)(-(\d+))?$", port_range)  # Port range format
    if match:
        try:
            start = int(match.group(1))
            end = int(match.group(3)) if match.group(3) else start
            return 0 <= start <= 65535 and start <= end
        except ValueError:
            return False

    return False
