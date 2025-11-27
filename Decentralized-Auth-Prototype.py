import tkinter as tk
from tkinter import messagebox
import web3 as Web3
from web3 import Web3
from solcx import compile_source, set_solc_version

set_solc_version("0.8.0")

# ---------------- Blockchain Setup ---------------- #
# This block connects to the local Ganache blockchain and defines the primary "admin" account that will pay for and authorize transactions.
# means the designated "admin" account serves two critical functions on the blockchain: paying for network fees and cryptographically approving all actions.

ganache_url = "HTTP://127.0.0.1:7545"      # Ganache local blockchain URL local server address
w3 = Web3(Web3.HTTPProvider(ganache_url))
print("Connected:", w3.is_connected())

# Your Ganache account address 
admin_account = w3.eth.accounts[0]

# Replacing with Ganache full private key for account[0]
private_key = "0x64abea6da98523d67246ef942321295706ccd4c0f732c33034c5f8ac4a1d23c5"  

# This multi-line string contains the entire source code for the AuthSystem smart contract, which holds all the security logic.
contract_source = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AuthSystem {
    struct User {
        bytes32 passwordHash;
        uint8 failedAttempts;
        bool locked;
    }

    mapping(bytes32 => User) public users; // username => User
    mapping(address => bool) public admins;

    uint public totalAttempts;
    uint public successfulAttempts;
    uint public failedAttempts;
    uint public lockedAccounts;

    event AuthAttempt(bytes32 username, bool success, uint timestamp);

    constructor() {
        admins[msg.sender] = true;
    }

    modifier onlyAdmin() {
        require(admins[msg.sender], "Not an admin");
        _;
    }

    function register(bytes32 _username, bytes32 _passwordHash) public {
        require(users[_username].passwordHash == 0, "Username already registered");
        users[_username] = User(_passwordHash, 0, false);
    }

    function authenticate(bytes32 _username, bytes32 _passwordHash) public returns (bool) {
        User storage user = users[_username];
        require(!user.locked, "Account locked");
        totalAttempts++;

        if (user.passwordHash == _passwordHash) {
            user.failedAttempts = 0;
            successfulAttempts++;
            emit AuthAttempt(_username, true, block.timestamp);
            return true;
        } else {
            user.failedAttempts++;
            failedAttempts++;
            if (user.failedAttempts >= 3) {
                user.locked = true;
                lockedAccounts++;
            }
            emit AuthAttempt(_username, false, block.timestamp);
            return false;
        }
    }

    function resetAccount(bytes32 _username) public onlyAdmin {
        users[_username].failedAttempts = 0;
        users[_username].locked = false;
    }

    function getSuccessRate() public view returns (uint) {
        if (totalAttempts == 0) return 0;
        return (successfulAttempts * 100) / totalAttempts;
    }

    function getFraudDetectionEfficiency() public view returns (uint) {
        if (totalAttempts == 0) return 0;
        return (failedAttempts * 100) / totalAttempts;
    }

    function getAccountLockRate() public view returns (uint) {
        if (totalAttempts == 0) return 0;
        return (lockedAccounts * 100) / totalAttempts;
    }
}
'''

#This section compiles the Solidity code and deploys it to the Ganache blockchain

compiled_sol = compile_source(contract_source, output_values=['abi', 'bin']) #The Application Binary Interface (ABI) is a JSON file that defines the contract's functions and how to call them. Web3.py uses this to understand how to interact with the contract.
contract_id, contract_interface = compiled_sol.popitem()
abi = contract_interface['abi']
bytecode = contract_interface['bin']

AuthSystem = w3.eth.contract(abi=abi, bytecode=bytecode)
nonce = w3.eth.get_transaction_count(admin_account)

# This new block includes error handling
try:
    tx = AuthSystem.constructor().build_transaction({
        'from': admin_account,
        'nonce': nonce,
        'gas': 3000000,
        'gasPrice': w3.to_wei('20', 'gwei')
    })
    signed_tx = w3.eth.account.sign_transaction(tx, private_key=private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    auth_contract = w3.eth.contract(address=tx_receipt.contractAddress, abi=abi)
    print("✅ Contract deployed at:", tx_receipt.contractAddress)
except TypeError as e:
    if "from field must match key's" in str(e):
        print("❌ CONFIGURATION ERROR: Incorrect private key. Application will exit.")
        exit() # Exit the script because the contract can't be deployed
    else:
        print(f"❌ Deployment failed with a type error: {e}")
        exit()
except Exception as e:
    print(f"❌ Contract deployment failed: {e}")
    exit()


# ---------------- Tkinter UI ---------------- #
root = tk.Tk()
root.title("Blockchain Login System")
root.geometry("500x450")
root.configure(bg="#f0f0f5")  # soft background

container = tk.Frame(root, bg="#f0f0f5")
container.pack(fill="both", expand=True, padx=20, pady=20)

def clear_frame():
    for widget in container.winfo_children():
        widget.destroy()

# ---------- Main Menu ----------
def show_main_menu():
    clear_frame()
    tk.Label(container, text="Welcome to the Blockchain System", font=("Arial", 18, "bold"),
             bg="#f0f0f5", fg="#333").pack(pady=30)
    tk.Button(container, text="Register (New User)", width=25, bg="#4CAF50", fg="white",
              font=("Arial", 12, "bold"), relief="raised", bd=3, command=show_register).pack(pady=10)
    tk.Button(container, text="Login (Already Registered)", width=25, bg="#2196F3", fg="white",
              font=("Arial", 12, "bold"), relief="raised", bd=3, command=show_login).pack(pady=10)
    tk.Button(container, text="Admin", width=25, bg="#FF5722", fg="white",
              font=("Arial", 12, "bold"), relief="raised", bd=3, command=prompt_admin_password).pack(pady=10)

# ---------- Register Interface ----------
def show_register():
    clear_frame()
    container.configure(bg="#e8f5e9")  # soft green
    tk.Label(container, text="Register New User", font=("Arial", 16, "bold"),
             bg="#e8f5e9", fg="#2e7d32").pack(pady=20)
    tk.Label(container, text="Username:", font=("Arial", 12), bg="#e8f5e9").pack(pady=5)
    entry_username = tk.Entry(container, width=30, bd=3, relief="groove")
    entry_username.pack(pady=5)
    tk.Label(container, text="Password:", font=("Arial", 12), bg="#e8f5e9").pack(pady=5)
    entry_password = tk.Entry(container, show="*", width=30, bd=3, relief="groove")
    entry_password.pack(pady=5)

    def register_user():
        username = entry_username.get()
        pw = entry_password.get()
        if not username or not pw:
            messagebox.showerror("Error", "Enter both username and password!")
            return
        try:
            hashed_user = w3.keccak(text=username)
            hashed_pw = w3.keccak(text=pw)
            nonce = w3.eth.get_transaction_count(admin_account)
            tx_register = auth_contract.functions.register(hashed_user, hashed_pw).build_transaction({
                'from': admin_account,
                'nonce': nonce,
                'gas': 300000,
                'gasPrice': w3.to_wei('20', 'gwei')
            })
            signed_register = w3.eth.account.sign_transaction(tx_register, private_key=private_key)
            tx_hash = w3.eth.send_raw_transaction(signed_register.raw_transaction)
            w3.eth.wait_for_transaction_receipt(tx_hash)
            messagebox.showinfo("Success", f"User {username} registered successfully!")
            show_main_menu()
        except TypeError as e:
            if "from field must match key's" in str(e):
                messagebox.showerror("Configuration Error", "Incorrect private key.")
            else:
                messagebox.showerror("Error", f"Registration failed with a type error: {e}")
        except Exception as e:
                messagebox.showerror("Error", f"Registration failed: {e}")
    
    tk.Button(container, text="Register", bg="#388E3C", fg="white", width=20,
              font=("Arial", 12, "bold"), relief="raised", bd=3, command=register_user).pack(pady=10)
    tk.Button(container, text="Back", width=20, command=show_main_menu).pack(pady=5)

# ---------- Login Interface ----------
def show_login():
    clear_frame()
    container.configure(bg="#e3f2fd")  # soft blue
    tk.Label(container, text="Login", font=("Arial", 16, "bold"),
             bg="#e3f2fd", fg="#1565c0").pack(pady=20)
    tk.Label(container, text="Username:", font=("Arial", 12), bg="#e3f2fd").pack(pady=5)
    entry_username = tk.Entry(container, width=30, bd=3, relief="groove")
    entry_username.pack(pady=5)
    tk.Label(container, text="Password:", font=("Arial", 12), bg="#e3f2fd").pack(pady=5)
    entry_password = tk.Entry(container, show="*", width=30, bd=3, relief="groove")
    entry_password.pack(pady=5)

    def login_user():
        username = entry_username.get()
        pw = entry_password.get()
        if not username or not pw:
            messagebox.showerror("Error", "Enter both username and password!")
            return
        try:
            hashed_user = w3.keccak(text=username)
            hashed_pw = w3.keccak(text=pw)
            nonce = w3.eth.get_transaction_count(admin_account)
            tx_auth = auth_contract.functions.authenticate(hashed_user, hashed_pw).build_transaction({
                'from': admin_account,
                'nonce': nonce,
                'gas': 300000,
                'gasPrice': w3.to_wei('20', 'gwei')
            })
            signed_auth = w3.eth.account.sign_transaction(tx_auth, private_key=private_key)
            tx_hash = w3.eth.send_raw_transaction(signed_auth.raw_transaction)
            w3.eth.wait_for_transaction_receipt(tx_hash)

            user_data = auth_contract.functions.users(hashed_user).call()
            if user_data[2]:
                messagebox.showerror("Locked", "🚫 Account locked due to failed attempts!")
            elif user_data[0] == hashed_pw:
                show_welcome_back(username)
            else:
                messagebox.showwarning("Failed", f"❌ Wrong password. Failed attempts: {user_data[1]}")
        except TypeError as e:
                if "from field must match key's" in str(e):
                    messagebox.showerror("Configuration Error", "Incorrect private key.")
                else:
                        messagebox.showerror("Error", f"Login failed with a type error: {e}")
        except Exception as e:
            error_message = str(e)
            if "Account locked" in error_message:
                messagebox.showerror("Locked", "🚫 Account locked due to too many failed attempts!")
            elif "nonce" in error_message:
                messagebox.showerror("Nonce Error", "⚠️ Transaction nonce mismatch. Please restart Ganache or wait a few seconds.")
            else:
                messagebox.showerror("Error", f"Login failed: {e}")


    tk.Button(container, text="Login", bg="#1976D2", fg="white", width=20,
              font=("Arial", 12, "bold"), relief="raised", bd=3, command=login_user).pack(pady=10)
    tk.Button(container, text="Back", width=20, command=show_main_menu).pack(pady=5)

# ---------- Welcome Back Screen ----------
def show_welcome_back(username):
    clear_frame()
    container.configure(bg="#fff3e0")  # soft orange
    tk.Label(container, text=f"Welcome Back, {username}!", font=("Arial", 18, "bold"),
             bg="#fff3e0", fg="#e65100").pack(pady=50)
    tk.Button(container, text="Logout", bg="#fb8c00", fg="white", width=20,
              font=("Arial", 12, "bold"), relief="raised", bd=3, command=show_main_menu).pack(pady=20)

# ---------- Admin Password Prompt ----------
def prompt_admin_password():
    clear_frame()
    container.configure(bg="#fce4ec")  # soft pink
    tk.Label(container, text="Enter Admin Password:", font=("Arial", 16), bg="#fce4ec", fg="#880e4f").pack(pady=20)
    entry_admin_pw = tk.Entry(container, show="*", width=30, bd=3, relief="groove")
    entry_admin_pw.pack(pady=5)

    def check_password():                   #The admin password is hardcoded as "abcd" for demonstration purposes.#
        if entry_admin_pw.get() == "abcd":
            show_admin_panel()
        else:
            messagebox.showerror("Error", "Wrong Admin Password")
            show_main_menu()

    tk.Button(container, text="Submit", width=20, command=check_password, bg="#d81b60", fg="white",
              font=("Arial", 12, "bold"), relief="raised", bd=3).pack(pady=10)
    tk.Button(container, text="Back", width=20, command=show_main_menu).pack(pady=5)

# ---------- Admin Interface ----------
def show_admin_panel():
    clear_frame()
    container.configure(bg="#f3e5f5")  # soft purple
    tk.Label(container, text="Admin Panel", font=("Arial", 16, "bold"),
             bg="#f3e5f5", fg="#6a1b9a").pack(pady=20)

    def reset_account():
        def do_reset():
            username = entry_reset.get()
            if not username:
                messagebox.showerror("Error", "Enter username to reset!")
                return
            try:
                hashed_user = w3.keccak(text=username)
                nonce = w3.eth.get_transaction_count(admin_account)
                tx_reset = auth_contract.functions.resetAccount(hashed_user).build_transaction({
                    'from': admin_account,
                    'nonce': nonce,
                    'gas': 300000,
                    'gasPrice': w3.to_wei('20', 'gwei')
                })
                signed_reset = w3.eth.account.sign_transaction(tx_reset, private_key=private_key)
                tx_hash = w3.eth.send_raw_transaction(signed_reset.raw_transaction)
                w3.eth.wait_for_transaction_receipt(tx_hash)
                messagebox.showinfo("Reset", f"✅ Account {username} reset successfully!")
                reset_win.destroy()
            except TypeError as e:
                if "from field must match key's" in str(e):
                    messagebox.showerror("Configuration Error", "Incorrect private key.")
                else:
                    messagebox.showerror("Error", f"Reset failed with a type error: {e}")
            except Exception as e:
                messagebox.showerror("Error", f"Reset failed: {e}")

        reset_win = tk.Toplevel(root)
        reset_win.title("Reset Account")
        reset_win.configure(bg="#f3e5f5")
        tk.Label(reset_win, text="Enter Username to Reset:", bg="#f3e5f5").pack(pady=5)
        entry_reset = tk.Entry(reset_win, bd=3, relief="groove")
        entry_reset.pack(pady=5)
        tk.Button(reset_win, text="Reset", bg="#8e24aa", fg="white", command=do_reset).pack(pady=10)

    def show_metrics():
        try:
            success_rate = auth_contract.functions.getSuccessRate().call()
            fraud_eff = auth_contract.functions.getFraudDetectionEfficiency().call()
            lock_rate = auth_contract.functions.getAccountLockRate().call()
            metrics_text = f"Authentication Success Rate: {success_rate}%\n"
            metrics_text += f"Fraud Detection Efficiency: {fraud_eff}%\n"
            metrics_text += f"Account Lock Rate: {lock_rate}%"
            messagebox.showinfo("System Metrics", metrics_text)
        except Exception as e:
            messagebox.showerror("Error", f"Metrics fetch failed: {e}")

    tk.Button(container, text="Reset Account", bg="#8e24aa", fg="white", width=25,
              font=("Arial", 12, "bold"), command=reset_account).pack(pady=10)
    tk.Button(container, text="Show Metrics", bg="#6a1b9a", fg="white", width=25,
              font=("Arial", 12, "bold"), command=show_metrics).pack(pady=10)
    tk.Button(container, text="Back", width=20, command=show_main_menu).pack(pady=10)

# ---------- Start the App ----------
show_main_menu()
root.mainloop()
