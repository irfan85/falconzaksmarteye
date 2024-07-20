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
    session = winrm.Session(target=ip, auth=(username, password), transport='ntlm')
    result = session.run_ps(command)
    if result.status_code == 0:
        return result.std_out.decode()
    else:
        raise Exception(result.std_err.decode())

def check_windows_update_status(ip, username, password):
    try:
        command = """
        $criteria = "IsInstalled=0"
        $searcher = New-Object -ComObject Microsoft.Update.Searcher
        $result = $searcher.Search($criteria)
        $updates = $result.Updates

        Write-Output "Pending Critical Installation Updates:"
        $criticalUpdates = $updates | Where-Object { $_.MsrcSeverity -eq 'Critical' }
        $criticalUpdates | Select-Object Title, MsrcSeverity, Description | Format-List

        Write-Output "`nPending Important Installation Updates:"
        $importantUpdates = $updates | Where-Object { $_.MsrcSeverity -eq 'Important' }
        $importantUpdates | Select-Object Title, MsrcSeverity, Description | Format-List

        Write-Output "`nPending Other Installation Updates:"
        $otherUpdates = $updates | Where-Object { $_.MsrcSeverity -ne 'Critical' -and $_.MsrcSeverity -ne 'Important' }
        $otherUpdates | Select-Object Title, MsrcSeverity, Description | Format-List
        """
        output = execute_command(ip, username, password, command).strip()
        if "Critical" in output or "Important" in output:
            return f"Pending updates found on this Windows system ({ip}):\n\n{output}", 0
        else:
            return f"No pending critical or important updates on this Windows system ({ip}).", 5
    except Exception as e:
        raise Exception(f"Error checking Windows update status on {ip}: {str(e)}")

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

        print(f"\n{Fore.GREEN}Falconzak Smart Eye is checking pending Windows updates on machine {ip}.{Style.RESET_ALL}\n")

        print_section_header(3, "Windows Update Status")
        try:
            update_status, score = check_windows_update_status(ip, username, password)
        except Exception as e:
            update_status = str(e)
            score = 0
        print(update_status)
        print()
        print_score(score)

    else:
        print(f"{Fore.RED}The target machine is not running Windows or not reachable.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
