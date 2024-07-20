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

def execute_ssh_command(ssh_client, command):
    stdin, stdout, stderr = ssh_client.exec_command(command)
    return stdout.read().decode().strip(), stderr.read().decode().strip()

def check_antivirus_status(ssh_client):
    clamav_active = False
    stdout, stderr = execute_ssh_command(ssh_client, "command -v systemctl")
    use_systemctl = bool(stdout)
    stdout, stderr = execute_ssh_command(ssh_client, "command -v service")
    use_service = bool(stdout)

    antivirus_status_messages = []

    if use_systemctl:
        commands = ["systemctl is-active clamav-daemon", "systemctl is-active clamav-freshclam"]
    elif use_service:
        commands = ["service clamav-daemon status", "service clamav-freshclam status"]
    else:
        clamav_active, _ = execute_ssh_command(ssh_client, "ps -A | grep clam")
        if clamav_active:
            antivirus_status_messages.append("ClamAV process is active and running.")
        else:
            antivirus_status_messages.append("ClamAV process is not active.")

    if use_systemctl or use_service:
        for command in commands:
            output, error_output = execute_ssh_command(ssh_client, command)
            service_name = "ClamAV daemon" if "daemon" in command else "ClamAV freshclam"
            if "active" in output or "running" in output:
                antivirus_status_messages.append(f"{service_name} is active and running.")
                clamav_active = True
            else:
                antivirus_status_messages.append(f"{service_name} is not active.")
                if error_output:
                    antivirus_status_messages.append(f"Error checking {service_name}: {error_output}")

    return clamav_active, "\n".join(antivirus_status_messages)

def main():
    remote_ip = input("Enter the IP address of the target machine: ")
    if not validate_ip(remote_ip):
        print("Invalid IP address format. Please enter a valid IPv4 address.")
    elif not ping_host(remote_ip):
        print("The target machine does not appear to be running Linux OS, please check the IP and enter the correct one.")
    else:
        username = input(f"Enter the username for {remote_ip}: ")
        password = getpass.getpass(f"Enter the password for {username}@{remote_ip}: ")

        print(f"\n{Fore.YELLOW}Falconzak Smart Eye is checking Antivirus status for Linux Machine ({remote_ip})...{Style.RESET_ALL}\n")

        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(remote_ip, username=username, password=password)
            
            clamav_active, antivirus_status = check_antivirus_status(ssh_client)
            print(antivirus_status)

            if clamav_active:
                print("\n\u001b[1mAntivirus is found to be enabled.\u001b[0m")
                print(f"{Fore.GREEN}Score: 5/5{Style.RESET_ALL}\n")
            else:
                print("\n\u001b[1mAntivirus is not found to be enabled.\u001b[0m")
                print(f"{Fore.RED}Score: 0/5{Style.RESET_ALL}\n")

            ssh_client.close()
            
        except paramiko.AuthenticationException:
            print("Authentication failed. Please check your credentials.")
        except paramiko.SSHException as e:
            print("SSH Error:", str(e))
        except Exception as e:
            print("Error:", str(e))

if __name__ == "__main__":
    main()
