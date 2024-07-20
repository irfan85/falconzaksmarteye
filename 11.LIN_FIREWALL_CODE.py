import paramiko
import getpass
import subprocess
import ipaddress
from colorama import Fore, Style, init

# Initialize colorama
init()

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def ping_host(ip):
    result = subprocess.run(['ping', '-c', '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            if "ttl=" in line.lower():
                ttl = int(line.split('ttl=')[1].split()[0])
                if ttl <= 64:  # Common TTL range for Linux
                    return True
    return False

def execute_ssh_command(ssh_client, command, password=None):
    stdin, stdout, stderr = ssh_client.exec_command(command)
    if password:
        stdin.write(password + "\n")
        stdin.flush()
    return stdout.read().decode().strip(), stderr.read().decode().strip()

def detect_os(ssh_client):
    stdout, stderr = execute_ssh_command(ssh_client, "cat /etc/os-release")
    if 'ubuntu' in stdout.lower() or 'debian' in stdout.lower():
        return 'debian'
    elif 'rhel' in stdout.lower() or 'centos' in stdout.lower() or 'fedora' in stdout.lower():
        return 'rhel'
    elif 'suse' in stdout.lower():
        return 'suse'
    elif 'ubuntu' in execute_ssh_command(ssh_client, "lsb_release -a")[0].lower():
        return 'debian'
    return None

def check_firewall_status(ssh_client, os_type, password):
    if os_type == 'debian':
        command = "sudo -S ufw status"
    elif os_type == 'rhel':
        command = "sudo -S firewall-cmd --state"
    elif os_type == 'suse':
        command = "sudo -S systemctl is-active firewalld"
    else:
        # Fallback to checking iptables for older systems
        command = "sudo -S iptables -L"

    output, error = execute_ssh_command(ssh_client, command, password)
    if "active" in output or "running" in output or "Chain" in output:
        return "Firewall is enabled.", 5
    elif "inactive" in output or "not loaded" in output or "iptables v" in error:
        return "Firewall is not enabled.", 0
    else:
        return f"Firewall status unknown: {output} Error: {error}", 0

def main():
    remote_ip = input("Enter the IP address of the target machine: ")
    if not validate_ip(remote_ip):
        print("Invalid IP address format. Please enter a valid IPv4 address.")
    elif not ping_host(remote_ip):
        print("The target machine does not appear to be running Linux OS, please check the IP and enter the correct one.")
    else:
        username = input(f"Enter the username for {remote_ip}: ")
        password = getpass.getpass(f"Enter the password for {username}@{remote_ip}: ")

        print(f"\n{Fore.YELLOW}Falconzak Smart Eye is checking Firewall status for Linux Machine ({remote_ip})...{Style.RESET_ALL}\n")

        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(remote_ip, username=username, password=password)
            
            os_type = detect_os(ssh_client)
            firewall_status, score = check_firewall_status(ssh_client, os_type, password)
            print(firewall_status)
            print_score(score)

            ssh_client.close()
            
        except paramiko.AuthenticationException:
            print("Authentication failed. Please check your credentials.")
        except paramiko.SSHException as e:
            print("SSH Error:", str(e))
        except Exception as e:
            print("Error:", str(e))

def print_score(score):
    if score == 0:
        print(f"{Fore.RED}Score: {score}/5{Style.RESET_ALL}\n")
    else:
        print(f"{Fore.GREEN}Score: {score}/5{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()
