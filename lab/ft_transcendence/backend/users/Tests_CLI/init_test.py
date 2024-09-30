import os
import subprocess

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_menu():
    clear_screen()
    print("=== Authentication System Test Suite ===")
    print("0. Register")
    print("1. Login")
    print("2. Users")
    print("3. Logout")
    print("4. Password Reset")
    print("5. Password Update")
    print("6. Profile Update")
    print("7. Delete Account")
    print("8. 2FA")
    print("9. OAuth with 42")
    print("f. Friends")
    print("q. Quit")
    print("=======================================")

def run_test(script_name):
    clear_screen()
    print(f"Running {script_name} test...")
    subprocess.run(['python3.9', f'{script_name}.py'])
    input("\nPress Enter to return to the main menu...")

def main():
    while True:
        print_menu()
        choice = input("Enter your choice (0-10): ")
        
        if choice == '0':
            run_test('tests/register')
        elif choice == '1':
            run_test('tests/login')
        elif choice == '2':
            run_test('tests/users')
        elif choice == '3':
            run_test('tests/logout')
        elif choice == '4':
            run_test('tests/pass_reset')
        elif choice == '5':
            run_test('tests/pass_update')
        elif choice == '6':
            run_test('tests/profile')
        elif choice == '7':
            run_test('tests/delete')
        elif choice == '8':
            run_test('tests/2FA')
        elif choice == '9':
            run_test('tests/42_OAuth')
        elif choice == 'f':
            run_test('tests/friends')
        elif choice == 'q':
            print("Quitting...")
            break
        else:
            input("Invalid choice. Press Enter to try again...")

if __name__ == "__main__":
    main()