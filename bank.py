import os
import csv
import hashlib
import hmac
import secrets
from datetime import datetime

# -------------------- Files & Security Constants -------------------- #
USERS_FILE = "users.csv"
BALANCE_FILE = "balance.csv"
HISTORY_FILE = "history.csv"

SUSPICIOUS_LIMIT = 1000
PBKDF2_ALGO = "sha256"
PBKDF2_ITERATIONS_DEFAULT = 300_000
PBKDF2_SALT_BYTES = 16
PBKDF2_KEY_LEN = 32 

USERS_HEADER = ["Name", "SaltHex", "HashHex", "Iterations", "HashedPIN"]


# -------------------- Password Hashing -------------------- #
def hash_pin_pbkdf2(pin: str, iterations: int = PBKDF2_ITERATIONS_DEFAULT):

    salt = secrets.token_bytes(PBKDF2_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac(PBKDF2_ALGO, pin.encode("utf-8"), salt, iterations, dklen=PBKDF2_KEY_LEN)
    return salt.hex(), dk.hex(), iterations


def verify_pin_pbkdf2(pin: str, salt_hex: str, hash_hex: str, iterations: int):
    """
    Verify a PIN against stored PBKDF2 parameters using constant-time comparison.
    """
    try:
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        dk = hashlib.pbkdf2_hmac(PBKDF2_ALGO, pin.encode("utf-8"), salt, int(iterations), dklen=len(expected))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


def legacy_hash_sha256(pin: str) -> str:
    """Legacy one-shot SHA-256 hex digest (used only for backward compatibility)."""
    return hashlib.sha256(pin.encode("utf-8")).hexdigest()


# -------------------- Helpers: Users CSV Schema -------------------- #
def ensure_users_schema():
    """
    Make sure USERS_FILE exists with our unified header.
    - If file doesn't exist: create with header.
    - If file exists with different header: rewrite file with unified header,
      preserving all rows (adding missing fields as empty).
    """
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=USERS_HEADER)
            writer.writeheader()
        return

    # Read existing file and header
    with open(USERS_FILE, "r", newline="") as f:
        reader = csv.DictReader(f)
        existing_fields = reader.fieldnames or []
        rows = list(reader)

    # If header already matches (order doesn't matter), nothing to do
    if set(existing_fields) == set(USERS_HEADER):
        return

    # Re-write with unified header, preserving data
    with open(USERS_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=USERS_HEADER)
        writer.writeheader()
        for row in rows:
            out = {key: row.get(key, "") for key in USERS_HEADER}
            writer.writerow(out)


def read_all_users():
    ensure_users_schema()
    with open(USERS_FILE, "r", newline="") as f:
        return list(csv.DictReader(f))


def write_all_users(records):
    # Always write with unified header
    with open(USERS_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=USERS_HEADER)
        writer.writeheader()
        for row in records:
            # sanitize missing fields
            safe_row = {k: row.get(k, "") for k in USERS_HEADER}
            writer.writerow(safe_row)


# -------------------- Register & Login -------------------- #
def register_user():
    ensure_users_schema()
    name = input("Enter a name to register: ").strip().title()
    pin = input("Set a 4-digit PIN: ").strip()

    if len(pin) != 4 or not pin.isdigit():
        print("PIN must be exactly 4 digits.")
        return None, None

    users = read_all_users()
    # Check for duplicates
    for row in users:
        if row.get("Name") == name:
            print("User already exists.")
            return None, None

    # Create PBKDF2 record
    salt_hex, hash_hex, iters = hash_pin_pbkdf2(pin, PBKDF2_ITERATIONS_DEFAULT)

    # Append new user
    users.append({
        "Name": name,
        "SaltHex": salt_hex,
        "HashHex": hash_hex,
        "Iterations": str(iters),
        "HashedPIN": ""  # empty legacy column
    })
    write_all_users(users)

    print("User registered successfully!")
    return name, hash_hex


def login():
    ensure_users_schema()
    name = input("Enter your name: ").strip().title()
    pin = input("Enter your 4-digit PIN: ").strip()

    if not os.path.exists(USERS_FILE):
        print("No users registered yet.")
        return None

    users = read_all_users()

    for idx, row in enumerate(users):
        if row.get("Name") != name:
            continue

        # Prefer PBKDF2 path if present
        salt_hex = row.get("SaltHex", "").strip()
        hash_hex = row.get("HashHex", "").strip()
        iterations = row.get("Iterations", "").strip()

        if salt_hex and hash_hex and iterations:
            if verify_pin_pbkdf2(pin, salt_hex, hash_hex, int(iterations)):
                print(f"Welcome back {name}!")
                return name
            else:
                print("Invalid name or PIN.")
                return None

        # Legacy path: HashedPIN (one-shot SHA-256) -> verify then upgrade
        legacy = row.get("HashedPIN", "").strip()
        if legacy:
            if legacy == legacy_hash_sha256(pin):
                print(f"Welcome back {name}! (Upgrading your PIN security...)")
                # Upgrade to PBKDF2 and save
                new_salt_hex, new_hash_hex, iters = hash_pin_pbkdf2(pin, PBKDF2_ITERATIONS_DEFAULT)
                users[idx]["SaltHex"] = new_salt_hex
                users[idx]["HashHex"] = new_hash_hex
                users[idx]["Iterations"] = str(iters)
                users[idx]["HashedPIN"] = ""  # clear legacy column
                write_all_users(users)
                return name
            else:
                print("Invalid name or PIN.")
                return None

        # If neither PBKDF2 nor legacy present (shouldn't happen)
        print("User record is incomplete. Please contact support.")
        return None

    print("Invalid name or PIN.")
    return None


# -------------------- Balance & Transactions -------------------- #
def load_balance(name):
    if os.path.exists(BALANCE_FILE):
        with open(BALANCE_FILE, "r", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row["Name"] == name:
                    try:
                        return float(row["Balance"])
                    except ValueError:
                        return 0.0
    return 0.0


def save_balance(name, balance):
    records = []
    if os.path.exists(BALANCE_FILE):
        with open(BALANCE_FILE, "r", newline="") as f:
            records = list(csv.DictReader(f))

    updated = False
    for row in records:
        if row["Name"] == name:
            row["Balance"] = f"{balance:.2f}"
            updated = True
            break
    if not updated:
        records.append({"Name": name, "Balance": f"{balance:.2f}"})

    with open(BALANCE_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["Name", "Balance"])
        writer.writeheader()
        writer.writerows(records)


def log_transaction(name, trans_type, amount, balance):
    file_exists = os.path.exists(HISTORY_FILE)
    with open(HISTORY_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        if not file_exists or os.stat(HISTORY_FILE).st_size == 0:
            writer.writerow(["Name", "Type", "Amount", "Balance", "Timestamp"])
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        writer.writerow([name, trans_type, f"{amount:.2f}", f"{balance:.2f}", timestamp])


def show_history(name):
    if os.path.exists(HISTORY_FILE):
        print("\n--- Transaction History ---")
        with open(HISTORY_FILE, "r", newline="") as f:
            reader = csv.DictReader(f)
            found = False
            for row in reader:
                if row["Name"] == name:
                    print(f"{row['Timestamp']} | {row['Type']} | ${row['Amount']} | Balance: ${row['Balance']}")
                    found = True
            if not found:
                print("No transactions found for this user.")
    else:
        print("No transaction history found.")


def print_receipt(trans_type, amount, balance):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("\n📄 --- Transaction Receipt ---")
    print(f"Type      : {trans_type}")
    print(f"Amount    : ${amount:.2f}")
    print(f"Balance   : ${balance:.2f}")
    print(f"Timestamp : {timestamp}")
    print("-----------------------------\n")


def deposit(name):
    try:
        amount = float(input("Enter the amount to deposit: "))
        if amount <= 0:
            print("Invalid amount.")
            return 0
        if amount >= SUSPICIOUS_LIMIT:
            print("⚠️ Suspicious deposit: please verify with your bank.")
        return amount
    except ValueError:
        print("Please enter a valid number.")
        return 0


def withdraw(balance, name):
    try:
        amount = float(input("Enter the amount to withdraw: "))
        if amount > balance:
            print("Insufficient funds.")
            return 0
        if amount <= 0:
            print("Amount must be positive.")
            return 0
        if amount >= SUSPICIOUS_LIMIT:
            print("⚠️ Suspicious withdrawal: please verify with your bank.")
        return amount
    except ValueError:
        print("Please enter a valid number.")
        return 0


# -------------------- Main Program -------------------- #
def main():
    print("Welcome to the Bank 🏦")
    print("1. Login")
    print("2. Register")

    option = input("Select an option (1 or 2): ")
    name = None

    if option == "1":
        name = login()
    elif option == "2":
        name, _ = register_user()
    else:
        print("Invalid option.")

    if not name:
        print("Exiting program.")
        return

    balance = load_balance(name)

    is_running = True
    while is_running:
        print(f"\nWelcome {name} 😊 ")
        print("1. Show Balance")
        print("2. Deposit")
        print("3. Withdraw")
        print("4. Show Transaction History")
        print("5. Exit 🛑")

        try:
            choice = int(input("Enter a valid option (1-5): "))
        except ValueError:
            print("Invalid input. Please enter a number.")
            continue

        if choice == 1:
            print(f"\n{name}, your balance is: ${balance:.2f}")

        elif choice == 2:
            amount = deposit(name)
            if amount:
                balance += amount
                log_transaction(name, "Deposit", amount, balance)
                print_receipt("Deposit", amount, balance)

        elif choice == 3:
            amount = withdraw(balance, name)
            if amount:
                balance -= amount
                log_transaction(name, "Withdrawal", amount, balance)
                print_receipt("Withdrawal", amount, balance)

        elif choice == 4:
            show_history(name)

        elif choice == 5:
            save_balance(name, balance)
            print("🙏 Thank you! Your balance and history have been saved 💾")
            print("Have a Nice Day 😊")
            is_running = False

        else:
            print("Invalid choice 🛑")


if __name__ == "__main__":
    main()
