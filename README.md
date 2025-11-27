****Blockchain-Based Decentralized Authentication System Prototype****

  MSc Dissertation Project > Author: Prakash Nayak Amgoth

  Institution: Heriot-Watt University, School of Mathematics and Computer Science

**📜 Overview**

This repository contains the source code for a Blockchain-Based Authentication System, developed as a technical prototype for an MSc Cybersecurity dissertation titled "The Role of Blockchain in Strengthening Cybersecurity: A Decentralized Approach to Data Integrity and Authentication."

By replacing traditional centralized databases with Ethereum smart contracts, this prototype mitigates risks associated with credential theft, brute-force attacks, and audit log tampering.

**🚀 Key Features**



* **Decentralized Identity**: User credentials are hashed (Keccak-256) and stored on the Ethereum blockchain, eliminating single points of failure.
* **Immutable Audit Logs**: Every login attempt (successful or failed) is recorded as a tamper-proof event on the ledger.
* **Smart Contract Logic**: Authentication rules are enforced by Solidity code, ensuring transparency and deterministic execution.
* **Brute-Force Protection**: Automated account locking mechanism triggers after 3 consecutive failed attempts.
* **Role-Based Access Control (RBAC)**: Admin-only functions (e.g., account resets) are cryptographically restricted to the contract deployer.
* **Real-time Metrics**: A built-in dashboard displays authentication success rates and fraud detection efficiency.


**🛠️ Technology Stack**
* Frontend: Python (Tkinter)
* Backend/Logic: Solidity (Smart Contract v0.8.0)
* Blockchain Interaction: Web3.py
* Local Blockchain: Ganache (Ethereum Simulator)
* Compiler: Py-Solc-X

**📂 Project Structure**


`├── Decentralized-Auth-Prototype.py      # Main application file (GUI + Blockchain Logic)`

`├── README.md                            # Project documentation`

`├── requirements.txt                     # List of python dependencies`


**⚙️ Prerequisites**

Before running the application, ensure you have the following installed:

Python 3.8+

Ganache: Download and install Ganache GUI (or use ganache-cli).

C++ Build Tools: Required for compiling Solidity on some Windows systems.

**📥 Installation & Setup**

Clone the repository:

    git clone [https://github.com/YOUR_USERNAME/Blockchain-Auth-Cybersecurity-Thesis.git](https://github.com/YOUR_USERNAME/Blockchain-Auth-Cybersecurity-Thesis.git)
cd Blockchain-Auth-Cybersecurity-Thesis


Install Python dependencies:

    pip install web3 py-solc-x


Configure Ganache:

Open Ganache and "Quickstart" a workspace.

Note the RPC Server URL (usually `HTTP://127.0.0.1:7545`).

Copy the Private Key of the first account (Index 0).

Update the Script:

Open `Decentralized-Auth-Prototype.py` in a text editor.

Update the private_key variable with the key copied from Ganache:

    # In Decentralized-Auth-Prototype.py
    private_key = "0x..." # Paste your Ganache Private Key here


**▶️ Usage**

Run the application using Python:

python Decentralized-Auth-Prototype.py


User Guide:

1. **Register**: Create a new account. The username and password hash will be stored on the local blockchain.

2. **Login**: Authenticate using your credentials.

    * Test Security: Try entering a wrong password 3 times to trigger the account lockout.

3. **Admin Panel:**

    * Enter the admin password (default hardcoded as abcd for the prototype).

    * View system metrics or reset locked accounts using the RBAC functions.

**📊 Architecture**

The system follows a layered architecture where the Python GUI communicates with the Ethereum Network via Web3.py.


**⚠️ Disclaimer**

This software is a Proof of Concept (PoC) developed for academic research purposes. It uses a local testnet (Ganache) and hardcoded keys for demonstration. It is not intended for production use on the Ethereum Mainnet without significant security hardening (e.g., wallet integration, secure key management, gas optimization).

**📄 License**

This project is open-source and available for educational use.
