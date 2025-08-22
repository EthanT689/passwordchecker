import re
import hashlib
import requests

# ===============================
# Password Strength Checker
# ===============================
def check_strength(password):
    """Checks the strength of a password."""
    strength = {"length": False, "uppercase": False, "lowercase": False, 
                "digit": False, "special": False}

    if len(password) >= 8:
        strength["length"] = True
    if re.search(r"[A-Z]", password):
        strength["uppercase"] = True
    if re.search(r"[a-z]", password):
        strength["lowercase"] = True
    if re.search(r"\d", password):
        strength["digit"] = True
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        strength["special"] = True

    score = sum(strength.values())
    if score == 5:
        overall = "Very Strong"
    elif score == 4:
        overall = "Strong"
    elif score == 3:
        overall = "Moderate"
    else:
        overall = "Weak"

    return overall, strength

# ===============================
# Check if password has been breached
# using HaveIBeenPwned API (k-anonymity)
# ===============================
def check_breached(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_password[:5]
    suffix = sha1_password[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    hashes = response.text.splitlines()
    
    for line in hashes:
        h, count = line.split(':')
        if h == suffix:
            return int(count)
    return 0

# ===============================
# Main Program
# ===============================
if __name__ == "__main__":
    pwd = input("Enter a password to check: ")

    strength_label, details = check_strength(pwd)
    print(f"Password strength: {strength_label}")
    print(f"Details: {details}")

    try:
        count = check_breached(pwd)
        if count > 0:
            print(f"Warning: This password has been seen {count} times in data breaches!")
        else:
            print("Good news: This password was NOT found in known breaches.")
    except requests.exceptions.RequestException:
        print("Could not check breaches (network/API issue).")
