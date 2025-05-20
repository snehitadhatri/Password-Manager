# Password Manager

A secure, user-friendly password manager built with Python and Tkinter. It allows users to store, retrieve, and delete website credentials using strong encryption. Access is protected with a master password.

## Features

- Secure credential storage with AES encryption (Fernet)
- Master password authentication
- GUI built with Tkinter
- Data saved in encrypted JSON file
- Ability to add, retrieve, and delete credentials

## Technologies Used

- Python
- Tkinter (GUI)
- `cryptography` module for encryption
- `hashlib` + `base64` for master key derivation
- JSON for local storage

## How It Works

1. On first run, user sets a master password (stored as a key).
2. The master password is hashed and encoded to create a secure key.
3. All data is encrypted/decrypted using this key.
4. Credentials are stored in a local `passwords.json` file (encrypted).
5. User can:
   - Add new credentials (website, username, password)
   - Retrieve saved credentials
   - Delete existing credentials

## Installation

1. Clone this repository or download the source code.
2. Install required packages:
   ```bash
   pip install cryptography

3. Run the application:

  ```bash
  python password_manager.py
  ```


## Files

main.py – Main application file.

requirements.txt – install required libraries.


## Future Enhancements

Cloud sync for encrypted data backup

Password generation and strength meter

Biometric login or 2FA

Browser plugin for autofill


## License

This project is open-source and free to use for educational purposes.


---

Author: Snehita Dhatri Siddabattuni
Project: Final Year / Internship Submission

---
