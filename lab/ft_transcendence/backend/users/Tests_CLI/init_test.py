import os
import subprocess

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_menu():
    clear_screen()
    print("=== Authentication System Test Suite ===")
    print("1. Register")
    print("2. Login")
    print("3. Logout")
    print("4. Password Reset")
    print("5. Password Update")
    print("6. User Update")
    print("7. Delete Account")
    print("8. 2FA")
    print("9. Exit")
    print("=======================================")

def run_test(script_name):
    clear_screen()
    print(f"Running {script_name} test...")
    subprocess.run(['python3.9', f'{script_name}.py'])
    input("\nPress Enter to return to the main menu...")

def main():
    while True:
        print_menu()
        choice = input("Enter your choice (1-8): ")
        
        if choice == '1':
            run_test('tests/register')
        elif choice == '2':
            run_test('tests/login')
        elif choice == '3':
            run_test('tests/logout')
        elif choice == '4':
            run_test('tests/pass_reset')
        elif choice == '5':
            run_test('tests/pass_update')
        elif choice == '6':
            run_test('tests/user_update')
        elif choice == '7':
            run_test('tests/delete')
        elif choice == '8':
            run_test('tests/2FA')
        elif choice == '9':
            print("Exiting. Goodbye!")
            break
        else:
            input("Invalid choice. Press Enter to try again...")

if __name__ == "__main__":
    main()