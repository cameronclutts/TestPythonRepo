# vulnerabilities.py

import os
import subprocess
import pickle
import hashlib

# ---- CRITICAL VULNERABILITY: Remote Code Execution (RCE) ----
# Description: This code allows arbitrary command execution via user input.
def critical_vulnerability():
    user_input = input("Enter command to run: ")  # User-controlled input
    subprocess.run(user_input, shell=True)  # 🚨 UNSAFE: Allows RCE


# ---- HIGH VULNERABILITY: Deserialization Attack ----
# Description: Loading untrusted data using pickle can lead to arbitrary code execution.
def high_vulnerability():
    data = input("Enter pickled data: ")  # Simulated external input
    loaded_data = pickle.loads(data)  # 🚨 UNSAFE: Arbitrary code execution


# ---- MEDIUM VULNERABILITY: Weak Password Hashing ----
# Description: MD5 is a weak hashing algorithm prone to collision attacks.
def medium_vulnerability():
    password = input("Enter password: ")
    hashed_password = hashlib.md5(password.encode()).hexdigest()  # 🚨 UNSAFE: MD5 is weak
    print(f"Stored hash: {hashed_password}")


# ---- LOW VULNERABILITY: Hardcoded Credentials ----
# Description: Storing sensitive data in plaintext can lead to security risks.
def low_vulnerability():
    API_KEY = "12345-ABCDE-SECRET"  # 🚨 UNSAFE: Hardcoded sensitive information
    print(f"Using API Key: {API_KEY}")  # Exposing the key in logs

# Execute vulnerabilities for demonstration
if __name__ == "__main__":
    print("Running vulnerabilities...")

    try:
        critical_vulnerability()
    except Exception as e:
        print(f"Critical vulnerability triggered: {e}")

    try:
        high_vulnerability()
    except Exception as e:
        print(f"High vulnerability triggered: {e}")

    try:
        medium_vulnerability()
    except Exception as e:
        print(f"Medium vulnerability triggered: {e}")

    try:
        low_vulnerability()
    except Exception as e:
        print(f"Low vulnerability triggered: {e}")
