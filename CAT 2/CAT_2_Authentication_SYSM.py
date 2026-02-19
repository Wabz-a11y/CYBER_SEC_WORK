"""
Password Strength Checker and Authentication System

Features:
- Hidden password input using getpass
- Modern password hashing with Argon2id (memory-hard, resistant to GPU attacks)
- Password strength validation with basic composition rules
- Multiple user support (stored in memory)
- Personalized welcome message on login
- Basic per-user failed login attempt tracking
- Logged-in state with minimal menu
"""

import re                         
from getpass import getpass        

# ────────────────────────────────────────────────
# PASSWORD HASHING SETUP (Argon2id)
# ────────────────────────────────────────────────

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
except ImportError:
    # Inform user and exit if argon2-cffi is not installed
    print("ERROR: argon2-cffi library is required for secure password hashing.")
    print("Please install it:   pip install argon2-cffi")
    exit(1)

# Create Argon2id hasher with conservative 2024–2026 era parameters
# These values provide good protection against both offline brute-force and side-channel attacks
ph = PasswordHasher(
    time_cost=2,        
    memory_cost=19*1024,   
    parallelism=2,         
    hash_len=32,            
    salt_len=16,           
    encoding='utf-8'
)

# ────────────────────────────────────────────────
# PASSWORD VALIDATION & HASHING HELPER CLASS
# ────────────────────────────────────────────────

class PasswordSecurity:
    """
    Collection of static methods that handle password strength checking
    and secure hashing/verification using Argon2id.
    """

    @staticmethod
    def check_strength(password: str) -> tuple[bool, str]:
        """
        Validates password against basic but reasonable complexity rules.
        Returns (is_valid: bool, message: str)
        """
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        if len(password) > 32:
            return False, "Password is too long, maximum 32 characters."
        
        # Requirements for a strong password.
        if not re.search(r"[A-Z]", password):
            return False, "Must contain at least one Uppercase letter"
        if not re.search(r"[a-z]", password):
            return False, "Must contain at least one lowercase letter"
        if not re.search(r"[0-9]", password):
            return False, "Must contain at least one digit"
        if not re.search(r"[^A-Za-z0-9]", password):
            return False, "Must contain at least one special character"

        return True, "Strong password"

    @staticmethod
    def hash_password(password: str) -> str:
        """Creates a secure Argon2id password hash (includes random salt automatically)"""
        return ph.hash(password)

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Safely verifies a password against a stored Argon2 hash"""
        try:
            ph.verify(hashed, password)
            return True
        except VerifyMismatchError:
            return False


# ────────────────────────────────────────────────
# USER DATA MODEL
# ────────────────────────────────────────────────

class User:
    """
    Simple user model that stores:
    - the original username
    - the hashed password 
    """
    def __init__(self, username: str, password_hash: str):
        self.username = username      
        self.password_hash = password_hash


# ────────────────────────────────────────────────
# CORE AUTHENTICATION
# ────────────────────────────────────────────────

class AuthenticationSystem:
    """
    Main class that manages users, registration, login,
    failed attempt tracking, and current session state.
    """

    def __init__(self):
        self.users: dict[str, User] = {}
        self.failed_attempts: dict[str, int] = {}
        self.current_user: User | None = None
        self.security = PasswordSecurity()

    def register(self):
        """Handles new user registration with input validation and password strength check"""
        username = input("\nEnter desired username: ").strip()

        if not username:
            print("Username is required.")
            return

        # Reasonable username format: starts with letter, 3–32 chars,
        if not re.fullmatch(r"[a-zA-Z]{2,31}", username):
            print("Username must at least be more than 3 characters and contain letters only.")
            return

        username_lower = username.lower()
        if username_lower in self.users:
            print("Sorry, that username is already taken.")
            return

        # Use getpass so password is not displayed while typing
        password = getpass("Enter password: ")
        confirm = getpass("Confirm password: ")

    
        if password != confirm:
            print("Passwords do not match.")
            return

        # Enforce password policy
        ok, msg = self.security.check_strength(password)
        if not ok:
            print(msg)
            return

        # Hash password before storing (never store plaintext!)
        hashed = self.security.hash_password(password)
        self.users[username_lower] = User(username, hashed)

        print("\nRegistration successful!")
        print(f"Welcome to the system, {username}!")

    def login(self):
        """Authenticates user and sets current_user on success"""
        username_input = input("\nEnter username: ").strip()
        if not username_input:
            print("Username is required.")
            return

        username_lower = username_input.lower()
        if username_lower not in self.users:
            print("\nNo account found with that username.")
            return

        password = getpass("Enter password: ")

        user = self.users[username_lower]

        if self.security.verify_password(password, user.password_hash):
            print("\n" + "═" * 60)
            print("LOGIN SUCCESSFUL!")
            self.current_user = user
            print(f"\nWelcome back, {self.current_user.username}!")
            print("\n You are now logged in.")
            print("\n═" * 60 + "\n")

            # Successful login then reset failed attempt counter 
            self.failed_attempts.pop(username_lower, None)
        else:
            # Record failed attempt
            attempts = self.failed_attempts.get(username_lower, 0) + 1
            self.failed_attempts[username_lower] = attempts

            print("\nIncorrect password.")
            if attempts >= 3:
                print("Too many failed attempts.")
                print("\nAccount temporarily locked!")
            else:
                print(f"# {3 - attempts} attempt(s) remaining before temporary lock.")


# ────────────────────────────────────────────────
# MAIN PROGRAM LOOP (CLI INTERFACE)
# ────────────────────────────────────────────────

def main():
    """Entry point — creates system and runs interactive menu loop"""
    system = AuthenticationSystem()

    while True:
        print("\n" + "─"*40)

        # Show different menu depending on login state
        if system.current_user:
            print("1. My Profile    2. Logout")
            print(f"Logged in as: {system.current_user.username}")

        else:
            print("1. Register    2. Login   3. Exit")

        print("\n─"*40)

        choice = input("# ").strip()

        if system.current_user:
            # Logged-in user options
            if choice == "1":
                print(f"\nUsername: {system.current_user.username}")
                print("This would be your profile page...")
                print(" I'm glad to see you idling in our CYBER SEC SYSTEM!")

            elif choice == "2":
                print(f"\nGoodbye, {system.current_user.username}!")
                system.current_user = None
            elif choice == "3":
                break
        else:
            # Not logged in (registration & login flow)
            if choice == "1":
                system.register()
            elif choice == "2":
                system.login()
            elif choice == "3":
                print("\nGoodbye!")
                break
            else:
                print("Invalid choice.")


if __name__ == "__main__":
    main()