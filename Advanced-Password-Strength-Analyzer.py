import math
import re

# ================= CONFIG =================
COMMON_PASSWORD_FILE = "rockyou.txt"
SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?/"

LEET_MAP = {
    '0': 'o', '@': 'a', '$': 's', '1': 'l',
    '3': 'e', '5': 's', '7': 't'
}

# ================= HELPERS =================

def normalize_leet(password):
    return ''.join(LEET_MAP.get(c.lower(), c.lower()) for c in password)

def calculate_entropy(password):
    charset = 0
    if re.search(r"[a-z]", password): charset += 26
    if re.search(r"[A-Z]", password): charset += 26
    if re.search(r"[0-9]", password): charset += 10
    if re.search(rf"[{re.escape(SPECIAL_CHARS)}]", password):
        charset += len(SPECIAL_CHARS)

    if charset == 0:
        return 0

    return round(len(password) * math.log2(charset), 2)

def has_repetition(password):
    return bool(re.search(r"(.)\1{2,}", password))

def has_sequence(password):
    sequences = ["123", "abc", "qwerty", "asdf", "password"]
    p = password.lower()
    return any(seq in p for seq in sequences)

def is_common_password(password):
    try:
        with open(COMMON_PASSWORD_FILE, "r", errors="ignore") as file:
            for line in file:
                if password.lower() == line.strip().lower():
                    return True
        return False
    except FileNotFoundError:
        print("⚠ rockyou.txt file not found!")
        return False

def estimate_bruteforce_time(entropy, guesses_per_sec=1e9):
    attempts = 2 ** entropy
    seconds = attempts / guesses_per_sec

    if seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds / 60)} minutes"
    elif seconds < 86400:
        return f"{int(seconds / 3600)} hours"
    elif seconds < 31536000:
        return f"{int(seconds / 86400)} days"
    else:
        return f"{int(seconds / 31536000)} years"

# ================= ANALYZER =================

def analyze_password(password):
    score = 0
    feedback = []

    entropy = calculate_entropy(password)
    normalized = normalize_leet(password)

    # Length check
    if len(password) >= 14:
        score += 25
    elif len(password) >= 10:
        score += 15
    else:
        feedback.append("Password too short (14+ recommended)")

    # Entropy check
    if entropy >= 80:
        score += 30
    elif entropy >= 60:
        score += 20
    else:
        feedback.append("Low entropy (predictable password)")

    # Character variety
    if re.search(r"[A-Z]", password): score += 5
    if re.search(r"[a-z]", password): score += 5
    if re.search(r"[0-9]", password): score += 5
    if re.search(rf"[{re.escape(SPECIAL_CHARS)}]", password): score += 5

    # Pattern checks
    if has_repetition(password):
        score -= 10
        feedback.append("Repeated characters detected")

    if has_sequence(password):
        score -= 10
        feedback.append("Keyboard / sequential pattern detected")

    # Common password check (rockyou)
    if is_common_password(password) or is_common_password(normalized):
        score = 0
        feedback.append("Password found in leaked password database (RockYou)")

    score = max(0, min(score, 100))

    # Strength level
    if score < 30:
        level = "Very Weak ❌"
    elif score < 50:
        level = "Weak ⚠️"
    elif score < 70:
        level = "Moderate"
    elif score < 85:
        level = "Strong ✅"
    else:
        level = "Very Strong 🔥"

    return {
        "score": score,
        "entropy": entropy,
        "level": level,
        "bruteforce": estimate_bruteforce_time(entropy),
        "feedback": feedback
    }

# ================= MAIN =================

if __name__ == "__main__":
    print("\n🔐 Advanced Password Strength Analyzer (Cybersecurity Edition)\n")

    password = input("Enter password: ")
    result = analyze_password(password)

    print("\n========== RESULT ==========")
    print(f"Strength Level : {result['level']}")
    print(f"Score          : {result['score']} / 100")
    print(f"Entropy        : {result['entropy']} bits")
    print(f"Crack Time     : {result['bruteforce']}")

    if result["feedback"]:
        print("\nIssues Found:")
        for issue in result["feedback"]:
            print(f" - {issue}")
    else:
        print("\nNo major weaknesses detected ✔")

    print("\n============================\n")
