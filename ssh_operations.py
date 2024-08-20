import paramiko
import time
import os
from config import remote_ip, username, password, dump_dir, local_dir, tcpdump_file, tcpdump_cmd

def run_tcpdump():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(remote_ip, username=username, password=password)
    
    # Run tcpdump in background and let it run for 10 seconds or until 3000 packets are captured
    stdin, stdout, stderr = ssh.exec_command(f"({tcpdump_cmd}) & sleep 10; pkill -2 tcpdump")
    time.sleep(12)  # Ensure tcpdump has finished before proceeding
    ssh.close()

def download_tcpdump():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(remote_ip, username=username, password=password)
    
    sftp = ssh.open_sftp()
    if not os.path.exists(local_dir):
        os.makedirs(local_dir)
    
    local_path = os.path.join(local_dir, os.path.basename(tcpdump_file))
    sftp.get(tcpdump_file, local_path)
    
    sftp.close()
    ssh.close()