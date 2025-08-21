**CLI Banking System**


A console-based Python application that simulates a simple banking system. It lets users register and log in with secure PIN hashing, check balances, make deposits/withdrawals, print receipts, and view transaction history—all stored in CSV files.

**Features**
🔐 PBKDF2-HMAC-SHA256 PIN hashing with random salt and high iteration count
👤 User registration & login (legacy SHA-256 hashes auto-upgrade to PBKDF2)
💰 Deposit and withdraw funds with configurable suspicious-amount warnings
🧾 Printable receipts after each transaction
📜 Per-user transaction history with timestamps
💾 CSV-based storage; no external database required
🛡️ Constant-time digest comparison to reduce timing attacks
⚙️ Easily configurable file paths and security parameters

**Prerequisites**
- Python 3.9 or higher
- A terminal (Windows PowerShell, macOS Terminal, or Linux shell)

**Installation**
Clone the repository:

  git clone https://github.com/vamsikumarGedela/Banking-System.git
  cd Banking-System
  
**Optionally create and activate a virtual environment:**

  python -m venv .venv
  # Windows (PowerShell)
  .\.venv\Scripts\Activate.ps1
  # macOS / Linux
  source .venv/bin/activate

**Run the application**

  python bank.py

Usage
Execute the application as shown above and follow on-screen prompts:

- Choose Login or Register
- Enter your name and a 4-digit PIN
- Select actions: Show Balance, Deposit, Withdraw, Show Transaction History, Exit
- Large transactions will show a suspicious amount warning (configurable)

**Example session**

  Date: 2025-08-21
  Welcome to the Bank!

  1. Login
  2. Register
  Select an option (1 or 2): 2
  Enter a name to register: Alice
  Set a 4-digit PIN: 1234
  User registered successfully!

  Welcome, Alice!
  1. Show Balance
  2. Deposit
  3. Withdraw
  4. Show Transaction History
  5. Exit
  Enter a valid option (1-5): 2
  Enter the amount to deposit: 200
  --- Transaction Receipt ---
  Type      : Deposit
  Amount    : $200.00
  Balance   : $200.00
  Timestamp : 2025-08-21 12:34:56
  ---------------------------

**Project Structure**

 Banking-System/
  ├── bank.py            # Main CLI application
  ├── users.csv          # Created/updated at runtime (credentials metadata)
  ├── balance.csv        # Created/updated at runtime (balances per user)
  ├── history.csv        # Created/updated at runtime (transaction log)
  ├── README.md          # Project README
  └── LICENSE            # License information (optional)

**Testing**
- Registration & login: Try registering a new user, then log in.
- Invalid input handling: Enter non-4-digit PINs or invalid menu options; the app should reprompt.
- Suspicious amounts: Deposit or withdraw values above the configured threshold to trigger warnings.
- History & receipts: Verify transactions appear in history.csv and receipts are printed after each action.
- Hash upgrade (if applicable): If a legacy SHA-256 entry exists, log in to trigger PBKDF2 upgrade.

**Configuration**
At the top of bank.py, adjust constants to your needs:
- File paths: USERS_FILE, BALANCE_FILE, HISTORY_FILE
- Security: PBKDF2_ALGO, PBKDF2_ITERATIONS_DEFAULT, PBKDF2_SALT_BYTES, PBKDF2_KEY_LEN
- Risk flag: SUSPICIOUS_LIMIT

**Contributing**
Contributions are welcome! To contribute:

1. Fork the repository
2. Create a new branch (git checkout -b feature/YourFeature)
3. Commit your changes (git commit -m 'Add new feature')
4. Push to the branch (git push origin feature/YourFeature)
5. Open a pull request

**License**
Distributed under the MIT License. See LICENSE for details.

**Author**
vamsikumar — Initial development
GitHub Profile: https://github.com/vamsikumarGedela
