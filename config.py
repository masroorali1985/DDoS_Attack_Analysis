import getpass
from datetime import datetime

# Configuration
remote_ip = input("Enter the remote IP of the BigIP F5 device: ")
username = input("Enter the SSH username: ")
password = getpass.getpass("Enter the SSH password: ")  # Hide password input

dump_dir = "/var/tmp"
local_dir = "./tcpdumps"
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
tcpdump_file = f"{dump_dir}/tcpdump_{remote_ip}_{timestamp}.pcap"
tcpdump_cmd = f"tcpdump -i external '(icmp or udp or tcp[tcpflags] & tcp-syn != 0)' -w {tcpdump_file} -c 3000"

geoip2_db_path = '/Users/masroorali/Documents/python/DDoS_Analysis_v1/GeoLite2-City_20240816/GeoLite2-City.mmdb'  # Replace with the actual path to GeoLite2-City.mmdb