import subprocess
import getpass
import winrm
from colorama import Fore, Style, init
import re

# Initialize colorama
init()

def get_valid_ip():
    while True:
        ip = input("Enter the IP address of the target machine: ")
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
            octets = ip.split('.')
            if all(0 <= int(octet) <= 255 for octet in octets):
                return ip
        print("Invalid IP address format. Please enter a valid IP address.")

def ping_host(ip):
    result = subprocess.run(['ping', '-c', '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            if "ttl=" in line.lower():
                ttl = int(line.split('ttl=')[1].split()[0])
                if ttl <= 128 and ttl > 64:  # Common TTL range for Windows
                    return True
    return False

def execute_command(ip, username, password, command):
    session = winrm.Session(target=ip, auth=(username, password), transport='ntlm', server_cert_validation='ignore')
    result = session.run_ps(command)
    if result.status_code == 0:
        return result.std_out.decode()
    else:
        raise Exception(result.std_err.decode())

def is_domain_controller(ip, username, password):
    command = "Import-Module ActiveDirectory; (Get-ADDomainController -Identity $env:COMPUTERNAME) -ne $null"
    try:
        output = execute_command(ip, username, password, command)
        return 'True' in output
    except Exception as e:
        print(f"{Fore.RED}Failed to verify Domain Controller status due to an exception: {str(e)}{Style.RESET_ALL}")
        return False

def check_password_policy(ip, username, password):
    try:
        command = "net accounts /domain"
        output = execute_command(ip, username, password, command)

        best_practices = {
            "Force user logoff how long after time expires?": "Never",
            "Minimum password age (days)": "1",
            "Maximum password age (days)": "42",
            "Minimum password length": "7",
            "Length of password history maintained": "24",
            "Lockout threshold": "Never",
            "Lockout duration (minutes)": "30",
            "Lockout observation window (minutes)": "30"
        }

        results = []
        current_policy_content = "Current Password Policy Settings:\n==================================\n"
        for setting in best_practices:
            value_line = output.split(setting)[1].splitlines()[0]
            current_value = value_line.split(":")[1].strip() if ":" in value_line else "Not found"
            current_policy_content += f"{setting}: {current_value}\n"
            results.append(current_value == best_practices[setting])

        standard_policy_content = "\nStandard Password Policy Settings:\n==================================\n"
        for setting, best_value in best_practices.items():
            standard_policy_content += f"{setting}: {best_value}\n"

        comparison_content = "\nComparison with Best Practice Settings:\n======================================\n"
        for setting, best_value in best_practices.items():
            value_line = output.split(setting)[1].splitlines()[0]
            current_value = value_line.split(":")[1].strip() if ":" in value_line else "Not found"
            status = "PASS" if current_value == best_value else "FAIL"
            comparison_content += f"{setting}: {status}\n"

        if all(results):
            return (current_policy_content + standard_policy_content + comparison_content + 
                    "\nCongratulations, Password Policy meets standard requirement, result is PASS"), 5
        else:
            return (current_policy_content + standard_policy_content + comparison_content + 
                    "\nPassword Policy doesn't meet standard requirement, result is FAIL"), 0
    except Exception as e:
        raise Exception(f"Error checking password policy on {ip}: {str(e)}")

def print_section_header(number, title):
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}{number}. {title}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{Style.BRIGHT}{'-' * (len(str(number)) + len(title) + 2)}{Style.RESET_ALL}\n")

def print_score(score):
    if score == 0:
        print(f"{Fore.RED}Score: {score}/5{Style.RESET_ALL}\n")
    else:
        print(f"{Fore.GREEN}Score: {score}/5{Style.RESET_ALL}\n")

def main():
    print(f"\n{Fore.CYAN}Welcome to Falconzak Smart Eye Console!{Style.RESET_ALL}\n")
    ip = get_valid_ip()

    if ping_host(ip):
        domain = "falconzak"
        username = f"{domain}\\admin"
        password = getpass.getpass(f"Enter the password for {username}@{ip}: ")

        try:
            execute_command(ip, username, password, "hostname")
        except Exception as e:
            print(f"{Fore.RED}Failed to authenticate: {str(e)}{Style.RESET_ALL}")
            return

        if is_domain_controller(ip, username, password):
            print()
            print(f"{Fore.YELLOW}Falconzak Smart Eye is checking the password policy for this Windows AD Server ({ip}).{Style.RESET_ALL}")
            print_section_header(7, "Password Policy Check")
            try:
                password_policy_status, score = check_password_policy(ip, username, password)
            except Exception as e:
                password_policy_status = str(e)
                score = 0
            print(password_policy_status)
            print()
            print_score(score)
        else:
            print(f"{Fore.RED}The entered IP does not belong to a Domain Controller.{Style.RESET_ALL}")

    else:
        print(f"{Fore.RED}The target machine is not running Windows or not reachable.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
