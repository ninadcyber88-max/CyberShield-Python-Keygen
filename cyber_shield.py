import secrets
import string
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class StrengthReport:
    score: int
    max_score: int
    level: str
    feedback: List[str]
    checks: Dict[str, bool]


# Recommended clean special characters set (avoids quotes/backslashes/whitespace)
SAFE_SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?"


def check_strength(password: str) -> StrengthReport:
    """
    Evaluates password entropy and structure in a single pass.
    """
    has_lower = False
    has_upper = False
    has_digit = False
    has_symbol = False

    symbol_set = set(SAFE_SYMBOLS)

    # Single pass over characters
    for char in password:
        if char.islower():
            has_lower = True
        elif char.isupper():
            has_upper = True
        elif char.isdigit():
            has_digit = True
        elif char in symbol_set or char in string.punctuation:
            has_symbol = True

    checks = {
        "length_8_plus": len(password) >= 8,
        "length_12_plus": len(password) >= 12,
        "has_lowercase": has_lower,
        "has_uppercase": has_upper,
        "has_digits": has_digit,
        "has_symbols": has_symbol,
    }

    # Scoring weights
    score = sum(checks.values())
    feedback = []

    if not checks["length_8_plus"]:
        feedback.append("Increase length to at least 8 characters (12+ recommended).")
    if not checks["has_lowercase"]:
        feedback.append("Add lowercase letters.")
    if not checks["has_uppercase"]:
        feedback.append("Add uppercase letters.")
    if not checks["has_digits"]:
        feedback.append("Add numeric digits.")
    if not checks["has_symbols"]:
        feedback.append("Add special symbols.")

    if score <= 2 or len(password) < 8:
        level = "Weak"
    elif score <= 4:
        level = "Medium"
    else:
        level = "Strong"

    return StrengthReport(
        score=score,
        max_score=len(checks),
        level=level,
        feedback=feedback,
        checks=checks,
    )


def generate_password(
    length: int = 16,
    require_lower: bool = True,
    require_upper: bool = True,
    require_digits: bool = True,
    require_symbols: bool = True,
    symbols: str = SAFE_SYMBOLS,
) -> str:
    """
    Cryptographically secure password generator that guarantees at least one 
    character from each selected category, followed by a cryptographically 
    secure shuffle (Fisher-Yates via secrets).
    """
    if length < 4:
        raise ValueError("Password length must be at least 4 characters.")

    pools = []
    guaranteed = []

    if require_lower:
        pools.append(string.ascii_lowercase)
        guaranteed.append(secrets.choice(string.ascii_lowercase))
    if require_upper:
        pools.append(string.ascii_uppercase)
        guaranteed.append(secrets.choice(string.ascii_uppercase))
    if require_digits:
        pools.append(string.digits)
        guaranteed.append(secrets.choice(string.digits))
    if require_symbols:
        pools.append(symbols)
        guaranteed.append(secrets.choice(symbols))

    if not pools:
        raise ValueError("At least one character pool must be enabled.")

    combined_pool = "".join(pools)
    remaining_length = length - len(guaranteed)
    remaining_chars = [secrets.choice(combined_pool) for _ in range(remaining_length)]

    # Combine guaranteed characters and fill characters
    password_chars = guaranteed + remaining_chars

    # Secure in-place Fisher-Yates shuffle using SystemRandom
    secrets.SystemRandom().shuffle(password_chars)

    return "".join(password_chars)


# --- Example Execution ---
if __name__ == "__main__":
    # 1. Generate guaranteed strong password
    new_pwd = generate_password(length=16)
    print(f"Generated Key: {new_pwd}")

    # 2. Audit strength
    report = check_strength(new_pwd)
    print(f"Strength Status: {report.level} ({report.score}/{report.max_score})")
    print(f"Missing Criteria: {report.feedback or 'None (All criteria passed)'}")
