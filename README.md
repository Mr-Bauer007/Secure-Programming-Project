# 🔐 TESTING THE SECURITY OF AN AI-BUILT APPLICATION: SECURE FILE ENCRYPTION/DECRYPTION TOOL IN A CLIENT-SERVER SETTING

# Project Overview

This project aims to ascertain the security of an application built with Chatgpt 4o mini. The idea here is to give just enough context to the AI application to understand that security is expected while providing as minimal help as possible. The prompts used to achieve the project can be summarised as follows:
- Stating the context and requirements of the project, with emphasis on security, and requesting a project outline
- Building the application
- Troubleshooting errors
- Evaluation against OWASP criteria
- Usability and security tests

## 📝 Application Overview

A secure client-server application for encrypting and decrypting files, with the goal of ensuring **confidentiality**, **integrity**, and **safety** of data both in transit and at rest.

- The **server** handles encryption and decryption using strong cryptographic standards.
- The **client** provides a graphical interface for users to interact securely with the system.
- Files are encrypted using a user-provided password and can be decrypted using the same key.
- All communication between the client and server is secured via **HTTPS/TLS**.

### 🖥️ GUI Features
- **Encryption Dialog:** Upload a file and provide a password to encrypt it.
- **Decryption Dialog:** Select an encrypted file and enter the password to decrypt it.
- **File Handling:** Encrypted files are saved locally; decrypted files are saved to a download folder.

---

## 🧱 Technology Stack

| Component           | Technology     |
|--------------------|----------------|
| Language            | Python         |
| Backend Framework   | Flask API      |
| GUI Client          | Tkinter (Python) |
| Encryption          | AES-GCM        |
| Key Derivation      | PBKDF2         |
| Communication       | HTTPS/TLS      |
| Authentication      | API Keys       |

---

## 🧭 System Architecture

### 🔗 Client
- Uploads files for encryption/decryption
- Sends passwords securely for key derivation
- Downloads encrypted/decrypted files

### 🛡️ Server
- Handles incoming requests over HTTPS
- Encrypts files using AES-GCM
- Derives keys from passwords using PBKDF2
- Verifies data integrity with AES-GCM
- Returns processed files to the client

---

## 🔒 Security Measures

- 🔐 HTTPS/TLS for encrypted communication
- 🧪 AES-GCM for authenticated encryption
- 🧬 PBKDF2 for secure password-based key derivation
- 🔑 API Key authentication for client access
- 📉 Rate limiting to protect against brute-force attacks

---

## ✅ Tests and Results

The application underwent both **automated** and **manual** security testing.

### 🔍 Unit & Integration Tests
- Tested encryption/decryption of `.txt` files
- Pytest was used to validate:
  - Encryption/decryption accuracy
  - API endpoint functionality
  - Input validation and error handling

### 🛠️ Security Tooling
| Tool           | Purpose                                                                 |
|----------------|-------------------------------------------------------------------------|
| **CycloneDX**  | Generate SBOM (Software Bill of Materials) to identify dependencies     |
| **Pipdeptree** | Visualize Python dependency tree from SBOM                              |
| **Pip-audit**  | Scan packages for known vulnerabilities                                 |
| **Bandit**     | Static code analysis for security issues in Python code                |

---

## ⚙️ Prerequisites & Setup

### 🔧 Environment Setup

```bash
# Clone the repository
git clone https://github.com/Mr-Bauer007/Secure-Programming-Project
cd secure-file-encryption

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate  #Linux

# Install dependencies
pip install -r requirements.txt
# Generate test results
./security_audit.sh
