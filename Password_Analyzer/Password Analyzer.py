import re

def analyze_password_strength(password):
    # Check if the password meets different security characteristics
    strength = {
        "length": len(password) >= 8,
        "uppercase": bool(re.search(r'[A-Z]', password)),
        "lowercase": bool(re.search(r'[a-z]', password)),
        "digit": bool(re.search(r'[0-9]', password)),
        "special_char": bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    }

    # Calculate a score based on the number of criteria met
    score = sum(strength.values())
    
    # Determine password strength based on the score
    if score == 5:
        return "Strong"
    elif score >= 3:
        return "Moderate"
    else:
        return "Weak"

# Example of usage
password = "P@ssw0rd123"
strength = analyze_password_strength(password)
print("Password strength:", strength)
