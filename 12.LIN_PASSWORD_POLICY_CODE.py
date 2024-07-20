import paramiko
import getpass
import subprocess
import ipaddress
from colorama import Fore, Style, init

# Initialize colorama
init()

# Standard password policy settings
standard_policy = {
    "minlen": 12,
    "dcredit": -1,
    "ucredit": -1,
    "lcredit": -1,
    "ocredit": -1,
    "PASS_MAX_DAYS": 60,
    "PASS_MIN_DAYS": 0,
    "PASS_WARN_AGE": 7
}

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

def check_password_policy(ssh_client):
    command_policy = "cat /etc/login.defs"
    output_policy, _ = execute_ssh_command(ssh_client, command_policy)
    
    current_policy = {}
    for line in output_policy.split('\n'):
        line = line.strip()
        if line and not line.startswith("#"):
            parts = line.split()
            if len(parts) > 1:
                key, value = parts[0], parts[1]
                current_policy[key] = value
    
    print("Parameter".ljust(15), "Current Value".ljust(14), "Standard Value".ljust(14), "Status")
    print("-" * 60)
    
    fail_flag = False
    for key, value in standard_policy.items():
        current_value = current_policy.get(key, "#")
        status = "Pass" if current_value == str(value) else "Fail"
        if status == "Fail":
            fail_flag = True
        print(key.ljust(15), str(current_value).ljust(14), str(value).ljust(14), status)
    
    print("-" * 60)
    
    if fail_flag:
        return "Password policy does not meet the standard requirements.", 0
    else:
        return "Password policy meets the standard requirements.", 5

def main():
    remote_ip = input("Enter the IP address of the target machine: ")
    if not validate_ip(remote_ip):
        print("Invalid IP address format. Please enter a valid IPv4 address.")
    elif not ping_host(remote_ip):
        print("The target machine does not appear to be running Linux OS, please check the IP and enter the correct one.")
    else:
        username = input(f"Enter the username for {remote_ip}: ")
        password = getpass.getpass(f"Enter the password for {username}@{remote_ip}: ")

        print(f"\n{Fore.YELLOW}Falconzak Smart Eye is checking Password Policy for Linux Machine ({remote_ip})...{Style.RESET_ALL}\n")

        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(remote_ip, username=username, password=password)
            
            password_policy_status, score = check_password_policy(ssh_client)
            print(password_policy_status)
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
