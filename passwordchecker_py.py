import re
import string
import nltk
from nltk.corpus import words

# Download words dataset if not already downloaded
nltk.download("words")
english_words = set(words.words())  # Load dictionary words

def check_password_strength(password):
    score = 0  # Score to determine password strength

    # Check Length
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1

    # Check for Uppercase and Lowercase Characters
    if any(char.islower() for char in password) and any(char.isupper() for char in password):
        score += 1

    # Check for Numbers
    if any(char.isdigit() for char in password):
        score += 1

    # Check for Special Characters
    if any(char in string.punctuation for char in password):
        score += 1

    # Check for Dictionary Words (Weak Passwords)
    if password.lower() in english_words:
        score -= 2  # Penalize weak passwords

    # Final Strength Result
    if score <= 2:
        return "Weak Password ❌"
    elif score <= 4:
        return "Moderate Password ⚠️"
    else:
        return "Strong Password ✅"




import math
import string

def calculate_entropy(password):
    length = len(password)
    character_set = 0  # Possible character choices

    # Count the types of characters used
    if any(char.islower() for char in password):
        character_set += 26  # a-z
    if any(char.isupper() for char in password):
        character_set += 26  # A-Z
    if any(char.isdigit() for char in password):
        character_set += 10  # 0-9
    if any(char in string.punctuation for char in password):
        character_set += len(string.punctuation)  # Special characters

    if character_set == 0:
        return 0  # No valid characters in password

    # Calculate entropy
    entropy = length * math.log2(character_set)
    return entropy




import bcrypt

# Function to hash a password
def hash_password(password):
    salt = bcrypt.gensalt()  # Generate a random salt
    hashed = bcrypt.hashpw(password.encode(), salt)  # Hash the password
    return hashed

# Function to verify password against stored hash
def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)


if __name__ == "__main__":
    password = input("Enter a password: ")

    # Calculate entropy
    entropy = calculate_entropy(password)
    print(f"Password Entropy: {entropy:.2f} bits")

    if entropy < 40:
        print("🔴 Very Weak Password")
    elif entropy < 60:
        print("🟠 Moderate Password")
    else:
        print("🟢 Strong Password")

    # Hash the password
    hashed_password = hash_password(password)
    print(f"🔐 Hashed Password: {hashed_password.decode()}")  # Convert bytes to string for display

    # Verify the password
    entered_password = input("Re-enter password to verify: ")
    if check_password(entered_password, hashed_password):
        print("✅ Password Matched")
    else:
        print("❌ Password Mismatch")

