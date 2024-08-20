Dependencies:

1. Python Packages:

	•	Paramiko: For SSH operations to connect to the remote server and execute commands.
	•	Scapy: For packet capture and analysis.
	•	GeoIP2: For looking up geographical information about IP addresses.
	•	Jinja2: For generating HTML reports.
	•	Collections: For using specialized data structures like defaultdict.

2. Operating System Tools:

	•	tcpdump: The script uses tcpdump to capture packets on the remote server. This tool should be installed on the remote server.

3. Python Installation:

	•	Python 3.x environment.

4. GeoLite2-City.mmdb Database:

	•	This database file is required for IP geolocation lookups using GeoIP2.

How to Run:

	•	You can now run the analysis by simply executing main.py.


How tcpdump Analysis is performed:

Fragmented packets:
In the script, the check is implemented in the following lines:

if IP in packet:
    # Check for fragmented IP packets
    if packet[IP].flags == 1 or packet[IP].frag > 0:
        fragmented_packets += 1

Explanation:

	1.	IP Layer Check:
	•	The first check if IP in packet: ensures that the packet has an IP layer. This is necessary because fragmentation occurs at the IP layer.
	2.	Flags Field (packet[IP].flags):
	•	The script checks packet[IP].flags == 1 to see if the “More Fragments” (MF) flag is set. In Scapy, the flags field in the IP layer indicates whether more fragments are following. If this is 1, it means the packet is part of a fragmented series.
	3.	Fragment Offset Field (packet[IP].frag):
	•	The script checks packet[IP].frag > 0 to determine if the fragment offset is greater than zero. A non-zero fragment offset indicates that this is not the first fragment but part of a larger fragmented packet.
	4.	Counting Fragmented Packets:
	•	If either of these conditions is true, it indicates that the packet is a fragment, and the script increments the fragmented_packets counter.

 ICMP Flood:
 In the script, the check for an ICMP flood is performed using the following code:

 if ICMP in packet and packet[ICMP].type == 8:  # ICMP Echo Request
    src_ip = packet[IP].src

    # Count packet per source IP (ICMP)
    if src_ip not in icmp_attackers:
        icmp_attackers[src_ip] = 1
    else:
        icmp_attackers[src_ip] += 1

Explanation:

	1.	ICMP Layer Check:
	•	The script first checks if the packet contains an ICMP layer using if ICMP in packet:. This ensures that the packet is an ICMP packet, which is necessary to identify an ICMP flood.
	2.	ICMP Echo Request (Type 8):
	•	The script then checks packet[ICMP].type == 8, which identifies the specific type of ICMP packet. Type 8 corresponds to an ICMP Echo Request, which is the type of packet used in a Ping flood.
	3.	Counting ICMP Packets by Source IP:
	•	The script uses the src_ip = packet[IP].src statement to extract the source IP address of the packet.
	•	It then checks if this source IP address is already in the icmp_attackers dictionary:
	•	If not, it adds the IP address to the dictionary with an initial count of 1.
	•	If the IP address is already in the dictionary, it increments the count for that IP address by 1.
	4.	Flood Detection:
	•	The overall idea is to collect and count ICMP Echo Request packets from each source IP address. If a particular IP sends a large number of ICMP Echo Requests (typically 1000 or more, as set in the analyze_attack function), it might be indicative of an ICMP flood attack.
	5.	Reporting:
	•	After all packets are analyzed, the total count of ICMP Echo Request packets from each source IP is included in the analysis results. This data is then used to generate a report, highlighting potential ICMP flood attacks.

UDP Flood:
In the script, the check for a UDP flood is performed using the following code:

elif UDP in packet:  # UDP packet
    src_ip = packet[IP].src

    # Count packet per source IP (UDP)
    if src_ip not in udp_attackers:
        udp_attackers[src_ip] = 1
    else:
        udp_attackers[src_ip] += 1

Explanation:

	1.	UDP Layer Check:
	•	The script first checks if the packet contains a UDP layer using elif UDP in packet:. This ensures that the packet is a UDP packet, which is necessary to identify a UDP flood.
	2.	Counting UDP Packets by Source IP:
	•	The script extracts the source IP address of the packet using src_ip = packet[IP].src.
	•	It then checks if this source IP address is already in the udp_attackers dictionary:
	•	If not, it adds the IP address to the dictionary with an initial count of 1.
	•	If the IP address is already in the dictionary, it increments the count for that IP address by 1.
	3.	Flood Detection:
	•	The script collects and counts the number of UDP packets sent by each source IP address. If a particular IP sends a large number of UDP packets (typically 1000 or more, as set in the analyze_attack function), it might be indicative of a UDP flood attack.
	4.	Reporting:
	•	After all packets are analyzed, the total count of UDP packets from each source IP is included in the analysis results. This data is then used to generate a report, highlighting potential UDP flood attacks.


Repetitive Payloads:

repetitive Payloads can indicate a brute-force style attack, is implemented in the analyze_dump function within the analysis.py module. 

Here’s how it works:

payloads = defaultdict(list)  # Store payloads by source IP
repetitive_payloads = defaultdict(int)  # Count repetitive payloads by source IP

# Inside the loop where packets are analyzed:
if Raw in packet:
    payload = packet[Raw].load
    if payload in payloads[src_ip]:
        repetitive_payloads[src_ip] += 1
    else:
        payloads[src_ip].append(payload)

Explanation:

	1.	Raw Layer Check:
	•	The script checks if the packet contains a Raw layer using if Raw in packet:. The Raw layer in Scapy represents the payload of the packet, which is the data being transmitted.
	2.	Extracting and Storing Payloads:
	•	If the packet has a Raw layer, the payload is extracted using payload = packet[Raw].load.
	•	The payload is then checked against a list of previously seen payloads from the same source IP address, stored in the payloads dictionary.
	3.	Checking for Repetitive Payloads:
	•	The script checks if the extracted payload has been seen before from the same source IP:
	•	If the payload has been seen before (i.e., it is already in the payloads[src_ip] list), the script increments the count of repetitive payloads for that source IP in the repetitive_payloads dictionary.
	•	If the payload has not been seen before, it is added to the list of known payloads for that source IP.
	4.	Flood Detection:
	•	The repetitive_payloads dictionary keeps track of how many times a source IP has sent the same payload. A high count in this dictionary can indicate that the source IP is engaging in repetitive or brute-force style behavior.
	5.	Reporting:
	•	After all packets are analyzed, the repetitive_payloads dictionary is included in the analysis results. This data is then used to generate a report, highlighting any potential repetitive payload patterns that could indicate an attack.

TCP SYN Flood:

TCP SYN flood attacks is implemented in the analyze_dump function within the analysis.py module. Here’s how it works:

A SYN flood attack is a type of denial-of-service (DoS) attack where the attacker sends a large number of TCP SYN packets to the target system. These SYN packets initiate a TCP handshake but do not complete it, causing the target to use up resources as it waits for the final ACK packet, leading to resource exhaustion and potential service disruption.

elif TCP in packet:
    src_ip = packet[IP].src

    if packet[TCP].flags & 0x02:  # TCP SYN packet
        # Count packet per source IP (TCP SYN)
        if src_ip not in tcp_syn_attackers:
            tcp_syn_attackers[src_ip] = 1
        else:
            tcp_syn_attackers[src_ip] += 1

Explanation:

	1.	TCP Layer Check:
	•	The script first checks if the packet contains a TCP layer using elif TCP in packet:. This ensures that the packet is a TCP packet, which is necessary to identify a SYN flood attack.
	2.	TCP Flags Field Check for SYN:
	•	The script then checks if the TCP packet is a SYN packet by evaluating the TCP flags using packet[TCP].flags & 0x02.
	•	In the TCP header, the SYN flag is represented by the value 0x02. The bitwise operation & 0x02 checks if the SYN flag is set in the TCP packet.
	3.	Counting SYN Packets by Source IP:
	•	The script extracts the source IP address of the packet using src_ip = packet[IP].src.
	•	It then checks if this source IP address is already in the tcp_syn_attackers dictionary:
	•	If not, it adds the IP address to the dictionary with an initial count of 1.
	•	If the IP address is already in the dictionary, it increments the count for that IP address by 1.
	4.	Flood Detection:
	•	The script collects and counts the number of TCP SYN packets sent by each source IP address. If a particular IP sends a large number of SYN packets (typically 1000 or more, as set in the analyze_attack function), it might be indicative of a SYN flood attack.
	5.	Reporting:
	•	After all packets are analyzed, the total count of TCP SYN packets from each source IP is included in the analysis results. This data is then used to generate a report, highlighting potential SYN flood attacks.
