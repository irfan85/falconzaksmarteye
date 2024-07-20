import os
import time
import sys

def run_script(script_name):
    script_path = os.path.join("/home/kali/Documents/MY_CODES", script_name)
    try:
        os.system(f"python3 {script_path}")
    except Exception as e:
        print(f"Error running script {script_name}: {e}")
    input("\nPress Enter to return to the menu...")

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def print_centered_text(text):
    lines = text.split('\n')
    for line in lines:
        print(line.center(os.get_terminal_size().columns))

def display_main_title():
    title = "\033[1;36m\033[3m\033[1m Falconzak Smart Eye console\033[0m"
    subtitle = "\033[1;33m\033[1m- One tool for complete Security Assessment Posture with scoring system -\033[0m"
    print("\n" * 3)
    print_centered_text(title)
    print("\n")
    print_centered_text(subtitle)
    print("\n\n")

def display_unauthorized_access_notice():
    header = "\033[1;31m\033[4mUnauthorized Access Notice:\033[0m"  # Bold and underline in red
    notice = (
        "Access to this system is restricted to authorized users only. Unauthorized access, use, or modification of "
        "this system is strictly prohibited and may result in disciplinary action, criminal prosecution, or both. "
        "All activities on this system are monitored and recorded. Violators will be prosecuted to the fullest extent of the law."
    )
    print(f"{header}")
    print(f"\033[1;31m{notice}\033[0m\n")

def display_main_page():
    display_main_title()
    display_unauthorized_access_notice()
    input("Press Enter to continue...")

def main():
    clear_screen()
    display_main_page()

    while True:
        clear_screen()
        display_main_title()
        
        print("\033[1;32mSelect the appropriate option to know your Security Posture Assessment:\033[0m\n")
        print("A. For Windows OS.")
        print("B. For Linux OS.")
        print("C. SSL Vulnerability.")
        print("D. Exit.\n")

        choice = input("Enter your choice: ").strip().upper()

        if choice == "A":
            while True:
                clear_screen()
                display_main_title()
                print("\n\033[1;32mSelect an appropriate option:\033[0m\n")
                print("1. Is Antivirus Enabled.")
                print("2. Is/Are Disks Encrypted.")
                print("3. Is/Are Windows Updates Pending.")
                print("4. Is Malware Signature Update <30 days.")
                print("5. Is Windows Defender Enabled.")
                print("6. Is Firewall Enabled.")
                print("7. Is AD Password Policy Compliant.")
                print("8. Is Device Vulnerable.")
                print("9. Perform Full Scan with all above with score.")
                print("10. Go to main page.\n")

                windows_choice = input("Enter your choice: ").strip()
                if windows_choice == "1":
                    run_script("1.WIN_AV_CODE.py")
                elif windows_choice == "2":
                    run_script("2.WIN_DSK_ENCR_CODE.py")
                elif windows_choice == "3":
                    run_script("3.WIN_UPDATE_CODE.py")
                elif windows_choice == "4":
                    run_script("4.WIN_MALWARE_SIG_CODE.py")
                elif windows_choice == "5":
                    run_script("5.WIN_WINDEF_CODE.py")
                elif windows_choice == "6":
                    run_script("6.WIN_FIREWALL_CODE.py")
                elif windows_choice == "7":
                    run_script("7.PASSWORD_POLICY_DC_CODE.py")
                elif windows_choice == "8":
                    run_script("8.WIN_VULNARABILITY_SCAN_CODE.py")
                elif windows_choice == "9":
                    run_script("9.WIN_FULL_SCAN_CODE.py")
                elif windows_choice == "10":
                    break
                else:
                    print("\n\033[1;31mInvalid option, please enter a valid option.\033[0m")
                    input("Press Enter to continue...")

        elif choice == "B":
            while True:
                clear_screen()
                display_main_title()
                print("\n\033[1;32mSelect an appropriate option:\033[0m\n")
                print("1. Is Antivirus Enabled.")
                print("2. Is Firewall Enabled.")
                print("3. Is Password Policy Compliant.")
                print("4. Is Device Vulnerable.")
                print("5. Perform Full Scan with all above with score.")
                print("6. Go to main page.\n")

                linux_choice = input("Enter your choice: ").strip()
                if linux_choice == "1":
                    run_script("10.LIN_AV_CODE.py")
                elif linux_choice == "2":
                    run_script("11.LIN_FIREWALL_CODE.py")
                elif linux_choice == "3":
                    run_script("12.LIN_PASSWORD_POLICY_CODE.py")
                elif linux_choice == "4":
                    run_script("13.LIN_VULNARABILITY_SCAN_CODE.py")
                elif linux_choice == "5":
                    run_script("14.LIN_FULL_SCAN_CODE.py")
                elif linux_choice == "6":
                    break
                else:
                    print("\n\033[1;31mInvalid option, please enter a valid option.\033[0m")
                    input("Press Enter to continue...")

        elif choice == "C":
            while True:
                clear_screen()
                display_main_title()
                print("\n\033[1;32mSelect an appropriate option:\033[0m\n")
                print("1. Is SSL Vulnerable.")
                print("2. Go to main page.\n")

                ssl_choice = input("Enter your choice: ").strip()
                if ssl_choice == "1":
                    run_script("15.SSL_VULN_SCAN.py")
                elif ssl_choice == "2":
                    break
                else:
                    print("\n\033[1;31mInvalid option, please enter a valid option.\033[0m")
                    input("Press Enter to continue...")

        elif choice == "D":
            print("\nExiting the Falconzak Smart Eye console. Goodbye!\n")
            break
        else:
            print("\n\033[1;31mInvalid option, please enter a valid option.\033[0m")
            input("Press Enter to continue...")

if __name__ == "__main__":
    main()
