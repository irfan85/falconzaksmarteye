import os
import subprocess
import time
import sys
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init()

def run_testssl_script(url):
    try:
        # Construct the command to run testssl with the URL
        command = ["testssl", url]
        
        # Print the message
        print(f"\n{Fore.YELLOW}Falconzak Smart Eye is scanning SSL Vulnerabilities for {url}. This may take a few minutes, stay calm!{Style.RESET_ALL}\n")
        
        # Start the timer
        start_time = time.time()
        
        # Run the command and capture the output
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Sequentially output the scan results and elapsed time
        full_output = ""
        while True:
            elapsed_time = time.time() - start_time
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                full_output += output
                print(output.strip())
        
        # Ensure all remaining output is printed
        remaining_output, _ = process.communicate()
        full_output += remaining_output
        print(remaining_output)
        
        vulnerabilities_found = False
        
        # Extracting and printing vulnerability information
        if "Testing vulnerabilities" in full_output:
            print("\n\u001b[4m\u001b[1mFollowing Vulnerabilities have been found by Falconzak Smart Eye:\u001b[0m\n")
            vuln_lines = [line.strip() for line in full_output.split('\n') if "VULNERABLE" in line]
            if vuln_lines:
                vulnerabilities_found = True
                for vuln_line in vuln_lines:
                    print(vuln_line)
            else:
                print("No Vulnerabilities found")
        
        # Extracting and printing grade information
        if "Rating (experimental)" in full_output:
            print("\nGrade information:")
            grade_lines = [line.strip() for line in full_output.split('\n') if "Overall Grade" in line]
            for grade_line in grade_lines:
                grade = grade_line.split(":")[-1].strip()
                print("Overall Grade:", grade)
            
            # Print Grade cap reasons
            grade_cap_reasons = [line.strip() for line in full_output.split('\n') if "Grade cap reasons" in line]
            if grade_cap_reasons:
                print("\nGrade cap reasons:")
                for reason in grade_cap_reasons:
                    print(reason)

        # Print the explanation of grades
        print_grades_explanation()

        # Determine and print the score based on the presence of vulnerabilities
        score = 0 if vulnerabilities_found else 5
        print_score(score)

        # Print the elapsed time
        elapsed_time = time.time() - start_time
        print(f"\nTime taken: {round(elapsed_time, 2)} seconds")

        # Ask the user if they want to save the report
        save_report = input("\nDo you want to save the report? (Y/N): ").strip().upper()
        if save_report == 'Y':
            save_report_to_file(url, full_output)

    except subprocess.CalledProcessError as e:
        # If there's an error running the command, print the error message
        print("Error:", e)

def print_grades_explanation():
    print("\n\u001b[4m\u001b[1mOverall grade stats:\u001b[0m")
    grades_info = """
A+: Excellent security, top-grade.
A: Very good security.
B: Acceptable security, with room for improvement.
C: Average security.
D: Below average security.
E: Indicates errors or critical issues.
F: Failing grade, significant security issues.
T: Trusted, indicating trustworthiness.
Secure/Insecure: Binary security indication.
Not Rated: No specific grade assigned.
    """
    print(grades_info)

def print_score(score):
    if score == 0:
        print(f"{Fore.RED}Score: {score}/5{Style.RESET_ALL}\n")
    else:
        print(f"{Fore.GREEN}Score: {score}/5{Style.RESET_ALL}\n")

def save_report_to_file(url, report_content):
    directory = "/home/kali/SSL_Scan_Reports/"
    if not os.path.exists(directory):
        os.makedirs(directory)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_url = url.replace("://", "_").replace("/", "_")
    filename = f"SSL_Scan_{safe_url}_{timestamp}.txt"
    filepath = os.path.join(directory, filename)

    try:
        with open(filepath, 'w') as file:
            file.write(report_content)
        print(f"{Fore.BLUE}Report saved to: {filepath}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error saving report: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    url = input("Enter the URL: ")
    run_testssl_script(url)
