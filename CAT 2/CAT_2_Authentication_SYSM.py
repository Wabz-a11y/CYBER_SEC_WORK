"""
Password Strength Checker and Authentication System

This system demonstrates:
- Uses hidden password input (getpass)
- Password strength validation
- Secure hashing (SHA-256)
- Authentication logic
- Input validation
- Access control
"""

import hashlib
import re
from getpass import getpass


class PasswordSecurity:
    """ 
        Handles password strength validation and hashing. 
        Demonstrates secure password handling principles. 
    """
     
    # Checking password strength
    def check_strength(self, password):

        if len(password) < 8:
            print("\n Password should be 8 or more characters")
            return False

        if not re.search(r"[A-Z]", password):
            print("\n Password must contain at least one uppercase letter")
            return False

        if not re.search(r"[a-z]", password):
            print("\n Password must contain at least one lowercase letter")
            return False

        if not re.search(r"[0-9]", password):
            print("\n Password must contain at least one number")
            return False

        print("\n Strong Password")
        return True
    
    # Password hashing
    def hash_password(self, password):
        """ 
        Hashes the password using SHA-256. 
        This prevents storing plain-text passwords. 
        """
        return hashlib.sha256(password.encode()).hexdigest()


class User:
    """ 
    Represents a system user. 
    Secure design: stores only hashed password. 
    """
    def __init__(self, username, hashed_password):
        self.username = username
        self.hashed_password = hashed_password


class AuthenticationSystem:
    """ 
    Handles registration and login process. 
    Implements authentication and access control logic. 
    """
    def __init__(self):
        self.security = PasswordSecurity()
        self.registered_user = None
        self.failed_attempts = 0

    def register(self):
        """ 
        Registers a user securely after validating password strength. 
        """
        username = input("\n Enter username: ").strip()

        if username == "":
            print("Username required!")
            return
        
        # Username validation: letters only
        if not re.fullmatch(r"[A-Za-z]+", username):
            print("\n Username must contain letters only (no numbers or symbols).")
            return
    
        # Password hidden when typing
        password = getpass("Enter password: ")
        
        # Validate password strength
        if not self.security.check_strength(password):
            print("\n Registration failed. Use stronger password.")
            return
       
        # Hash password before storing
        hashed_password = self.security.hash_password(password)
        
        # Create user object (secure storage)
        self.registered_user = User(username, hashed_password)

        print("\n Registration successful! Password stored securely.")

    def login(self):
        """ 
        Authenticates user by comparing hashed passwords. 
        """
        if self.registered_user is None:
            print("\n No user registered.")
            return

        username = input("\n Enter username: ").strip()
        
        # Username validation during login
        if not re.fullmatch(r"[A-Za-z]+", username):
            print("\n Invalid username format.")
            return
    
        # Password hidden when typing
        password = getpass("Enter password: ")
        
        # Access Control Logic
        if username != self.registered_user.username:
            print("\n Invalid username.")
            return

        hashed_input = self.security.hash_password(password)

        if hashed_input == self.registered_user.hashed_password:
            print("\n Login successful! Access granted.")
            self.failed_attempts = 0
        else:
            print("\n Incorrect password. Access denied.")
            self.failed_attempts += 1

            if self.failed_attempts >= 3:
                print("\n Account locked after 3 failed attempts.")

# ===== MAIN PROGRAM =====
def main():
    system = AuthenticationSystem()

    while True:
        print("\n1. Register")
        print("2. Log In")
        print("3. Exit")

        choice = input("\n Choose option: ")

        if choice == "1":
            system.register()
        elif choice == "2":
            system.login()
        elif choice == "3":
            print("\n Exiting system. Goodbye!")
            break
        else:
            print("\n Invalid choice. Try again.")


if __name__ == "__main__":
    main()
