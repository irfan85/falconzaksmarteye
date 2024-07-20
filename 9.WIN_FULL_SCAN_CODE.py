import subprocess
import getpass
import winrm
from datetime import datetime, timedelta
from dateutil import parser
import time
import threading
from tabulate import tabulate
from colorama import Fore, Style, init
import os
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

def check_windows_antivirus(ip, username, password):
    try:
        command = "Get-MpComputerStatus"
        output = execute_command(ip, username, password, command)
        if "RealTimeProtectionEnabled" in output:
            return f"Antivirus is enabled.", 5
        else:
            return f"Antivirus is not enabled.", 0
    except Exception as e:
        raise Exception(f"Error checking Windows antivirus on {ip}: {str(e)}")

def check_windows_disk_encryption(ip, username, password):
    try:
        check_command = "Get-Command -Module BitLocker"
        check_output = execute_command(ip, username, password, check_command).strip()
        if not check_output:
            return f"BitLocker module is not available.", 0
        
        command = "Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus | Format-Table -HideTableHeaders"
        output = execute_command(ip, username, password, command).strip()
        results = []
        score = 5
        for line in output.splitlines():
            parts = line.strip().split(None, 1)
            if parts and len(parts) == 2:
                drive, status = parts
                encrypted_status = "Encrypted" if "FullyEncrypted" in status else "Not Encrypted"
                results.append(f"{drive} drive is {encrypted_status}")
                if "Not Encrypted" in encrypted_status:
                    score = 0
        return "\n".join(results), score
    except Exception as e:
        raise Exception(f"Error checking BitLocker status on {ip}: {str(e)}")

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
            return f"Pending updates found:\n\n{output}", 0
        else:
            return f"No pending critical or important updates.", 5
    except Exception as e:
        raise Exception(f"Error checking Windows update status on {ip}: {str(e)}")

def check_antimalware_signature_age(ip, username, password):
    try:
        command = """
        $update = Get-MpComputerStatus
        $lastUpdate = $update.AntivirusSignatureLastUpdated
        return $lastUpdate
        """
        output = execute_command(ip, username, password, command).strip()
        if output:
            last_update_date = parser.parse(output).replace(tzinfo=None)
            days_since_update = (datetime.now().replace(tzinfo=None) - last_update_date).days
            if days_since_update > 30:
                return (f"Antimalware signature update is more than 30 days old. "
                        f"Last updated: {last_update_date.strftime('%Y-%m-%d')} ({days_since_update} days ago)"), 0
            else:
                return (f"Antimalware signature is less than 30 days old. "
                        f"Last updated: {last_update_date.strftime('%Y-%m-%d')} ({days_since_update} days ago)"), 5
        else:
            return f"Unable to determine the last antimalware signature update date.", 0
    except Exception as e:
        raise Exception(f"Error checking antimalware signature update status on {ip}: {str(e)}")

def check_windows_firewall_status(ip, username, password):
    try:
        command = """
        $firewallProfiles = Get-NetFirewallProfile
        $status = $firewallProfiles | Select-Object Name, Enabled | Format-Table -AutoSize
        $status
        """
        output = execute_command(ip, username, password, command)
        if "True" in output:
            return output.strip(), 5
        else:
            return output.strip(), 0
    except Exception as e:
        raise Exception(f"Error checking Windows Firewall status on {ip}: {str(e)}")

def check_windows_defender_status(ip, username, password):
    try:
        command = "Get-Service -Name WinDefend"
        output = execute_command(ip, username, password, command)
        if "Running" in output:
            return f"Windows Defender service is running.", 5
        elif "Stopped" in output:
            return f"Windows Defender service is stopped.", 0
        else:
            return f"Unable to determine Windows Defender status.", 0
    except Exception as e:
        raise Exception(f"Error checking Windows Defender status on {ip}: {str(e)}")

def nmap_scan(target_ip):
    command = f"nmap {target_ip} -Pn"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

def parse_nmap_output(nmap_output):
    lines = nmap_output.splitlines()
    open_ports = []
    for line in lines:
        if "/tcp" in line:
            parts = line.split()
            port = parts[0]
            service = " ".join(parts[1:])
            open_ports.append((port, service))
    return open_ports

def nmap_enhanced_scan(target_ip, ports):
    vulnerability_table = []
    exploit_count = 0
    critical_high_vuln_count = 0
    for port in ports:
        command = f"nmap -A --script vulners -T4 -n {target_ip} -p{port}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        for line in result.stdout.splitlines():
            if "https://vulners.com/" in line:
                parts = line.strip('|').strip().split()
                vulnerability_name = parts[0]
                score = parts[1]
                try:
                    float_score = float(score)
                except ValueError:
                    continue
                url = parts[2]
                exploitable = "*EXPLOIT*" in line
                vulnerability_table.append((vulnerability_name, score, url, "YES" if exploitable else "NO", port))
                if exploitable or float_score >= 7.0:
                    critical_high_vuln_count += 1
                exploit_count += 1 if exploitable else 0
    return critical_high_vuln_count, vulnerability_table

def classify_vulnerabilities(vulnerability_table):
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    for _, score, _, _, _ in vulnerability_table:
        score_float = float(score)
        if score_float >= 7.0:
            if score_float >= 10.0:
                critical_count += 1
            elif score_float >= 8.0:
                high_count += 1
            else:
                medium_count += 1
        else:
            low_count += 1
    return critical_count, high_count, medium_count, low_count

def timer(start_time, stop_event):
    while not stop_event.is_set():
        elapsed_time = time.time() - start_time
        print(f"\r{Fore.YELLOW}Time elapsed: {elapsed_time:.2f} seconds{Style.RESET_ALL}", end='', flush=True)
        time.sleep(1)

def print_section_header(number, title):
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}{number}. {title}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{Style.BRIGHT}{'-' * (len(str(number)) + len(title) + 2)}{Style.RESET_ALL}\n")

def print_score(score):
    if score == 0:
        print(f"{Fore.RED}Score: {score}/5{Style.RESET_ALL}\n")
    else:
        print(f"{Fore.GREEN}Score: {score}/5{Style.RESET_ALL}\n")

def write_to_file(filename, content):
    directory = "/home/kali/Full_Scan_Reports"
    if not os.path.exists(directory):
        os.makedirs(directory)
    filepath = os.path.join(directory, filename)
    with open(filepath, "w") as file:
        file.write(content)
    print(f"{Fore.BLUE}Report written to: {filepath}{Style.RESET_ALL}")

def print_welcome_message():
    print(f"{Fore.CYAN}Welcome to Falconzak Smart Eye Console!{Style.RESET_ALL}")

def run_remote_powershell_command(host, username, password, command):
    session = winrm.Session(target=host, auth=(username, password), transport='ntlm', server_cert_validation='ignore')
    result = session.run_ps(command)
    return result.std_out.decode("utf-8")

def is_domain_controller(host, username, password):
    command = "Import-Module ActiveDirectory; (Get-ADDomainController -Identity $env:COMPUTERNAME) -ne $null"
    try:
        output = run_remote_powershell_command(host, username, password, command)
        return 'True' in output
    except Exception as e:
        raise Exception(f"Failed to verify Domain Controller status due to an exception: {str(e)}")

def check_password_policy(ip, username, password):
    try:
        command = "net accounts /domain"
        output = run_remote_powershell_command(ip, username, password, command)

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

def main():
    print_welcome_message()
    ip = get_valid_ip()

    if ping_host(ip):
        domain = "falconzak"
        username = f"{domain}\\admin"
        password = getpass.getpass(f"Enter the password for {username}@{ip}: ")

        try:
            # Validate credentials by running a simple command
            execute_command(ip, username, password, "hostname")
        except Exception as e:
            print(f"{Fore.RED}Failed to authenticate: {str(e)}{Style.RESET_ALL}")
            return

        print(f"\n{Fore.GREEN}Falconzak Smart Eye is running a full system scan for this Windows Machine ({ip}){Style.RESET_ALL}\n")

        total_score = 0
        max_score = 35  # 5 points each for 7 checks
        report_content = []
        failures = []

        print_section_header(1, "Antivirus Status")
        try:
            antivirus_status, score = check_windows_antivirus(ip, username, password)
        except Exception as e:
            antivirus_status = str(e)
            score = 0
        total_score += score
        print(antivirus_status)
        print_score(score)
        report_content.append(f"1. Antivirus Status\n{antivirus_status}\n\nScore: {score}/5\n\n")
        if score == 0:
            failures.append("Antivirus is not enabled.")

        print_section_header(2, "Disk Encryption Status")
        try:
            bitlocker_status, score = check_windows_disk_encryption(ip, username, password)
        except Exception as e:
            bitlocker_status = str(e)
            score = 0
        total_score += score
        print(bitlocker_status)
        print_score(score)
        report_content.append(f"2. Disk Encryption Status\n{bitlocker_status}\n\nScore: {score}/5\n\n")
        if score == 0:
            failures.append("Disk encryption is not enabled on all drives.")

        print_section_header(3, "Firewall Status")
        try:
            firewall_status, score = check_windows_firewall_status(ip, username, password)
        except Exception as e:
            firewall_status = str(e)
            score = 0
        total_score += score
        print(firewall_status)
        print_score(score)
        report_content.append(f"3. Firewall Status\n{firewall_status}\n\nScore: {score}/5\n\n")
        if score == 0:
            failures.append("Windows Firewall is not enabled.")

        print_section_header(4, "Windows Defender Status")
        try:
            defender_status, score = check_windows_defender_status(ip, username, password)
        except Exception as e:
            defender_status = str(e)
            score = 0
        total_score += score
        print(defender_status)
        print_score(score)
        report_content.append(f"4. Windows Defender Status\n{defender_status}\n\nScore: {score}/5\n\n")
        if score == 0:
            failures.append("Windows Defender service is not running.")

        print_section_header(5, "Windows Update Status")
        try:
            update_status, score = check_windows_update_status(ip, username, password)
        except Exception as e:
            update_status = str(e)
            score = 0
        total_score += score
        print(update_status)
        print_score(score)
        report_content.append(f"5. Windows Update Status\n{update_status}\n\nScore: {score}/5\n\n")
        if score == 0:
            failures.append("There are pending critical or important updates.")

        print_section_header(6, "Antimalware Signature Status")
        try:
            antimalware_status, score = check_antimalware_signature_age(ip, username, password)
        except Exception as e:
            antimalware_status = str(e)
            score = 0
        total_score += score
        print(antimalware_status)
        print_score(score)
        report_content.append(f"6. Antimalware Signature Status\n{antimalware_status}\n\nScore: {score}/5\n\n")
        if score == 0:
            failures.append("Antimalware signature is not updated.")

        # Only run password policy check if the machine is a Domain Controller
        try:
            if is_domain_controller(ip, username, password):
                print(f"{Fore.YELLOW}Falconzak Smart Eye is checking the password policy for this Windows AD Server ({ip}){Style.RESET_ALL}\n")
                print_section_header(7, "Password Policy Check")
                password_policy_status, score = check_password_policy(ip, username, password)
                total_score += score
                print(password_policy_status)
                print_score(score)
                report_content.append(f"7. Password Policy Check\n{password_policy_status}\n\nScore: {score}/5\n\n")
                if score == 0:
                    failures.append("Password policy does not meet the standard requirements.")
                max_score += 5  # Include password policy check score in the max score
        except Exception as e:
            print(f"{Fore.RED}{str(e)}{Style.RESET_ALL}")
            return

        print_section_header(8 if max_score == 40 else 7, "Vulnerability Scan")

        nmap_output = nmap_scan(ip)
        open_ports = parse_nmap_output(nmap_output)
        
        if not open_ports:
            print("No open ports detected. There may be a firewall blocking the scan or the host is down.")
            vulnerability_score = 5
        else:
            print("Open ports detected:")
            print(tabulate(open_ports, headers=["Port", "Service"]) + "\n")
            report_content.append(f"Open Ports\n{tabulate(open_ports, headers=['Port', 'Service'])}\n")

            scan_ports = [port_info[0].split('/')[0] for port_info in open_ports]

            if scan_ports:
                print(f"\n{Fore.YELLOW}Falconzak Smart Eye is scanning all the vulnerabilities on the above open ports, stay calm!{Style.RESET_ALL}")
                start_time = time.time()
                stop_event = threading.Event()
                timer_thread = threading.Thread(target=timer, args=(start_time, stop_event))
                timer_thread.start()

                critical_high_vuln_count, vulnerability_table = nmap_enhanced_scan(ip, scan_ports)
                
                stop_event.set()
                timer_thread.join()

                print()
                print("\nVulnerability Summary".center(60, "-"))
                print(tabulate(vulnerability_table, headers=["Vulnerability Name", "Score", "URL", "Exploitable", "Port"]) + "\n")
                report_content.append(f"Vulnerability Summary\n{tabulate(vulnerability_table, headers=['Vulnerability Name', 'Score', 'URL', 'Exploitable', 'Port'])}\n")

                critical_count, high_count, medium_count, low_count = classify_vulnerabilities(vulnerability_table)
                print("Classification of Vulnerabilities".center(60, "-"))
                print(f"Number of Critical Vulnerabilities: {critical_count}")
                print(f"Number of High Vulnerabilities: {high_count}")
                print(f"Number of Medium Vulnerabilities: {medium_count}")
                print(f"Number of Low Vulnerabilities: {low_count}\n")
                report_content.append(f"Classification of Vulnerabilities\nNumber of Critical Vulnerabilities: {critical_count}\nNumber of High Vulnerabilities: {high_count}\nNumber of Medium Vulnerabilities: {medium_count}\nNumber of Low Vulnerabilities: {low_count}\n")

                print(f"Number of exploitable vulnerabilities: {critical_high_vuln_count}\n")
                report_content.append(f"Number of exploitable vulnerabilities: {critical_high_vuln_count}\n")

                if critical_high_vuln_count > 0:
                    vulnerability_score = 0
                    failures.append("There are exploitable critical or high vulnerabilities.")
                else:
                    vulnerability_score = 5
        total_score += vulnerability_score
        print(f"{8 if max_score == 40 else 7}. Vulnerability Scan")
        print_score(vulnerability_score)
        report_content.append(f"{8 if max_score == 40 else 7}. Vulnerability Scan\nScore: {vulnerability_score}/5\n\n")

        percentage_score = (total_score / max_score) * 100
        print_section_header("", "Final Score")
        print(f"Total Score: {total_score} / {max_score}")
        print(f"Percentage Score: {percentage_score:.2f}%\n")
        report_content.append(f"Final Score\nTotal Score: {total_score} / {max_score}\nPercentage Score: {percentage_score:.2f}%\n")

        if percentage_score == 100:
            assessment = f"Congratulations! This system ({ip}) has passed the security assessment done by Falconzak Smart Eye!"
        else:
            assessment = f"This system ({ip}) has failed the security assessment done by Falconzak Smart Eye."
        print(f"{Fore.CYAN}Assessment: {assessment}{Style.RESET_ALL}\n")
        report_content.append(f"Assessment: {assessment}\n")

        if failures:
            print_section_header("", "Summary of Failures")
            for failure in failures:
                print(f"{Fore.RED}- {failure}{Style.RESET_ALL}")
            report_content.append("Summary of Failures\n" + "\n".join(f"- {failure}" for failure in failures))

        save_to_file = input("Do you want to save the report to a file? (Y/N): ").strip().upper()
        if save_to_file == 'Y':
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"Full_System_Scan_{ip}_{timestamp}.txt"
            write_to_file(filename, "\n".join(report_content))

    else:
        print(f"{Fore.RED}The target machine is not running Windows or not reachable.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
