import subprocess
import time
import threading
from tabulate import tabulate
import ipaddress
from colorama import Fore, Style, init

# Initialize colorama
init()

def get_target_ip():
    while True:
        target_ip = input("Enter target IP address: ")
        try:
            ipaddress.IPv4Address(target_ip)
            return target_ip
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

def print_score(score):
    if score == 0:
        print(f"{Fore.RED}Score: {score}/5{Style.RESET_ALL}\n")
    else:
        print(f"{Fore.GREEN}Score: {score}/5{Style.RESET_ALL}\n")

def main():
    target_ip = get_target_ip()
    if not ping_host(target_ip):
        print("The target machine does not appear to be running Linux OS, please check the IP and enter the correct one.")
        return

    print(f"\n{Fore.YELLOW}Falconzak Smart Eye is checking Vulnerability status for Linux Machine ({target_ip})...{Style.RESET_ALL}\n")

    nmap_output = nmap_scan(target_ip)
    open_ports = parse_nmap_output(nmap_output)
    
    if not open_ports:
        print("No open ports detected. There may be a firewall blocking the scan or the host is down.")
        print_score(5)
    else:
        print("Open ports detected:")
        print(tabulate(open_ports, headers=["Port", "Service"]))

        scan_ports = [port_info[0].split('/')[0] for port_info in open_ports]

        if scan_ports:
            print(f"\n{Fore.YELLOW}Falconzak Smart Eye is scanning all the vulnerabilities on the above open ports, stay calm!{Style.RESET_ALL}")
            start_time = time.time()
            stop_event = threading.Event()
            timer_thread = threading.Thread(target=timer, args=(start_time, stop_event))
            timer_thread.start()

            critical_high_vuln_count, vulnerability_table = nmap_enhanced_scan(target_ip, scan_ports)
            
            stop_event.set()
            timer_thread.join()

            print("\nVulnerability Summary:")
            print(tabulate(vulnerability_table, headers=["Vulnerability Name", "Score", "URL", "Exploitable", "Port"]))

            critical_count, high_count, medium_count, low_count = classify_vulnerabilities(vulnerability_table)
            print("\nClassification of Vulnerabilities:")
            print(f"Number of Critical Vulnerabilities: {critical_count}")
            print(f"Number of High Vulnerabilities: {high_count}")
            print(f"Number of Medium Vulnerabilities: {medium_count}")
            print(f"Number of Low Vulnerabilities: {low_count}")

            print(f"\nNumber of exploitable vulnerabilities: {critical_high_vuln_count}")

            if critical_high_vuln_count > 0:
                print_score(0)
            else:
                print_score(5)

if __name__ == "__main__":
    main()
