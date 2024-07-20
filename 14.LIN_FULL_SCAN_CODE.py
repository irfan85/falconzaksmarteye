import subprocess
import getpass
import paramiko
from datetime import datetime
import time
import threading
from tabulate import tabulate
from colorama import Fore, Style, init
import os
import re
import ipaddress

# Initialize colorama
init()

def get_valid_ip():
    while True:
        ip = input("Enter the IP address of the target machine: ")
        try:
            ipaddress.IPv4Address(ip)
            return ip
        except ipaddress.AddressValueError:
            print("Invalid IP address format. Please enter a valid IPv4 address.")

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
        return "Firewall is enabled."
    elif "inactive" in output or "not loaded" in output or "iptables v" in error:
        return "Firewall is not enabled."
    else:
        return f"Firewall status unknown: {output} Error: {error}"

def check_password_policy(ssh_client):
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
        print("Your password policy is not set as per the standard. Result: Fail")
        return False
    else:
        print("Your password policy is set as per the standard.")
        return True

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
    welcome_message = f"""
    {Fore.CYAN}{"="*60}
    {"Welcome to Falconzak Smart Eye Console!".center(60)}
    {"="*60}{Style.RESET_ALL}
    """
    print(welcome_message)

def main():
    print_welcome_message()
    ip = get_valid_ip()

    if ping_host(ip):
        username = input(f"Enter the username for {ip}: ")
        password = getpass.getpass(f"Enter the password for {username}@{ip}: ")

        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(ip, username=username, password=password)
        except paramiko.AuthenticationException:
            print(f"{Fore.RED}Failed to authenticate: the specified credentials were rejected by the server.{Style.RESET_ALL}")
            return

        print(f"\n{Fore.GREEN}Falconzak Smart Eye is running a full system scan for this Linux machine ({ip})...{Style.RESET_ALL}\n")

        total_score = 0
        max_score = 20  # 5 points each for 4 checks
        report_content = []
        failures = []

        print_section_header(1, "Antivirus Status")
        try:
            clamav_active, antivirus_status = check_antivirus_status(ssh_client)
            score = 5 if clamav_active else 0
        except Exception as e:
            antivirus_status = str(e)
            score = 0
        total_score += score
        print(antivirus_status)
        print_score(score)
        report_content.append(f"1. Antivirus Status\n{antivirus_status}\n\nScore: {score}/5\n\n")
        if score == 0:
            failures.append("Antivirus is not enabled.")

        os_type = detect_os(ssh_client)
        print_section_header(2, "Firewall Status")
        try:
            firewall_status = check_firewall_status(ssh_client, os_type, password)
            score = 5 if firewall_status == "Firewall is enabled." else 0
        except Exception as e:
            firewall_status = str(e)
            score = 0
        total_score += score
        print(firewall_status)
        print_score(score)
        report_content.append(f"2. Firewall Status\n{firewall_status}\n\nScore: {score}/5\n\n")
        if score == 0:
            failures.append("Firewall is not enabled.")

        print_section_header(3, "Password Policy")
        try:
            password_policy_status = check_password_policy(ssh_client)
            score = 5 if password_policy_status else 0
        except Exception as e:
            password_policy_status = str(e)
            score = 0
        total_score += score
        print(password_policy_status)
        print_score(score)
        report_content.append(f"3. Password Policy\n{password_policy_status}\n\nScore: {score}/5\n\n")
        if score == 0:
            failures.append("Password policy does not meet the standard requirements.")

        print_section_header(4, "Vulnerability Scan")

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
        print(f"4. Vulnerability Scan")
        print_score(vulnerability_score)
        report_content.append(f"4. Vulnerability Scan\nScore: {vulnerability_score}/5\n\n")

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
        print(f"{Fore.RED}The target machine is not running Linux or not reachable.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
