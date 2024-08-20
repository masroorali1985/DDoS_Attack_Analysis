import os
from scapy.all import rdpcap, IP, ICMP, UDP, TCP, Raw  # Import Scapy components
from collections import defaultdict
from config import local_dir, tcpdump_file
import geoip2.database
from config import geoip2_db_path

reader = geoip2.database.Reader(geoip2_db_path)

def analyze_dump():
    icmp_attackers = {}
    udp_attackers = {}
    tcp_syn_attackers = {}
    tcp_rst_fin_attackers = {}
    packet_sizes = []
    malformed_packets = 0
    fragmented_packets = 0
    payloads = defaultdict(list)  # Store payloads by source IP
    repetitive_payloads = defaultdict(int)  # Count repetitive payloads by source IP
    
    packets = rdpcap(os.path.join(local_dir, os.path.basename(tcpdump_file)))
    
    for packet in packets:
        if IP in packet:
            # Check for fragmented IP packets
            if packet[IP].flags == 1 or packet[IP].frag > 0:
                fragmented_packets += 1

        if ICMP in packet and packet[ICMP].type == 8:  # ICMP Echo Request
            src_ip = packet[IP].src
            
            # Count packet per source IP (ICMP)
            if src_ip not in icmp_attackers:
                icmp_attackers[src_ip] = 1
            else:
                icmp_attackers[src_ip] += 1
            
            # Analyze packet sizes
            packet_sizes.append(len(packet))
        
        elif UDP in packet:  # UDP packet
            src_ip = packet[IP].src
            
            # Count packet per source IP (UDP)
            if src_ip not in udp_attackers:
                udp_attackers[src_ip] = 1
            else:
                udp_attackers[src_ip] += 1
            
            # Analyze packet sizes
            packet_sizes.append(len(packet))
            
            # Check and store payloads for UDP
            if Raw in packet:
                payload = packet[Raw].load
                if payload in payloads[src_ip]:
                    repetitive_payloads[src_ip] += 1
                else:
                    payloads[src_ip].append(payload)
        
        elif TCP in packet:
            src_ip = packet[IP].src
            
            if packet[TCP].flags & 0x02:  # TCP SYN packet
                # Count packet per source IP (TCP SYN)
                if src_ip not in tcp_syn_attackers:
                    tcp_syn_attackers[src_ip] = 1
                else:
                    tcp_syn_attackers[src_ip] += 1
            
            if packet[TCP].flags & 0x04 or packet[TCP].flags & 0x01:  # TCP RST or FIN packet
                # Count packet per source IP (TCP RST/FIN)
                if src_ip not in tcp_rst_fin_attackers:
                    tcp_rst_fin_attackers[src_ip] = 1
                else:
                    tcp_rst_fin_attackers[src_ip] += 1
            
            # Analyze packet sizes
            packet_sizes.append(len(packet))
            
            # Check and store payloads for TCP
            if Raw in packet:
                payload = packet[Raw].load
                if payload in payloads[src_ip]:
                    repetitive_payloads[src_ip] += 1
                else:
                    payloads[src_ip].append(payload)
        
        # Check for malformed packets (simplified check)
        if not (packet.haslayer(ICMP) or packet.haslayer(UDP) or packet.haslayer(TCP)) or not packet.haslayer(IP):
            malformed_packets += 1
    
    return {
        "icmp_attackers": icmp_attackers,
        "udp_attackers": udp_attackers,
        "tcp_syn_attackers": tcp_syn_attackers,
        "tcp_rst_fin_attackers": tcp_rst_fin_attackers,
        "packet_sizes": packet_sizes,
        "malformed_packets": malformed_packets,
        "fragmented_packets": fragmented_packets,  # Include fragmented packets in the result
        "repetitive_payloads": repetitive_payloads,  # Include repetitive payloads in the result
    }

def analyze_attack(analysis_results):
    attack_details = {
        "icmp_attackers": [],
        "udp_attackers": [],
        "tcp_syn_attackers": [],
        "tcp_rst_fin_attackers": [],
        "repetitive_payloads": analysis_results["repetitive_payloads"],
        "fragmented_packets": analysis_results["fragmented_packets"],
    }

    # Analyze ICMP attackers
    for ip, count in analysis_results['icmp_attackers'].items():
        if count >= 1000:  # Only show if the count is 1000 or more
            try:
                response = reader.city(ip)
                country = response.country.name
            except geoip2.errors.AddressNotFoundError:
                country = "Unknown"

            attack_details["icmp_attackers"].append({
                "source_ip": ip,
                "source_country": country,
                "packet_count": count
            })

    # Analyze UDP attackers
    for ip, count in analysis_results['udp_attackers'].items():
        if count >= 1000:  # Only show if the count is 1000 or more
            try:
                response = reader.city(ip)
                country = response.country.name
            except geoip2.errors.AddressNotFoundError:
                country = "Unknown"

            attack_details["udp_attackers"].append({
                "source_ip": ip,
                "source_country": country,
                "packet_count": count
            })

    # Analyze TCP SYN attackers
    for ip, count in analysis_results['tcp_syn_attackers'].items():
        if count >= 1000:  # Only show if the count is 1000 or more
            try:
                response = reader.city(ip)
                country = response.country.name
            except geoip2.errors.AddressNotFoundError:
                country = "Unknown"

            attack_details["tcp_syn_attackers"].append({
                "source_ip": ip,
                "source_country": country,
                "packet_count": count
            })

    # Analyze TCP RST/FIN attackers
    for ip, count in analysis_results['tcp_rst_fin_attackers'].items():
        if count >= 1000:  # Only show if the count is 1000 or more
            try:
                response = reader.city(ip)
                country = response.country.name
            except geoip2.errors.AddressNotFoundError:
                country = "Unknown"

            attack_details["tcp_rst_fin_attackers"].append({
                "source_ip": ip,
                "source_country": country,
                "packet_count": count
            })

    # Check for unusual packet size patterns
    if len(set(analysis_results['packet_sizes'])) < len(analysis_results['packet_sizes']) / 2:
        attack_details["unusual_packet_size"] = "Repetitive Payloads Detected"

    if max(analysis_results['packet_sizes']) > 1500:
        attack_details["unusual_packet_size"] = "Large Packet Sizes Detected"

    if analysis_results['malformed_packets'] > 0:
        attack_details["malformed_packets"] = f"{analysis_results['malformed_packets']} Malformed Packets Detected"

    return attack_details
