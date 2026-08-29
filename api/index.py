import json
import secrets
import string
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

SAFE_SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?"


def check_strength(password: str):
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in SAFE_SYMBOLS or c in string.punctuation for c in password)

    checks = {
        "length_8_plus": len(password) >= 8,
        "length_12_plus": len(password) >= 12,
        "has_lowercase": has_lower,
        "has_uppercase": has_upper,
        "has_digits": has_digit,
        "has_symbols": has_symbol,
    }

    score = sum(checks.values())
    feedback = []

    if not checks["length_8_plus"]:
        feedback.append("Increase length to at least 8 characters.")
    if not checks["has_lowercase"]:
        feedback.append("Add lowercase letters.")
    if not checks["has_uppercase"]:
        feedback.append("Add uppercase letters.")
    if not checks["has_digits"]:
        feedback.append("Add numbers.")
    if not checks["has_symbols"]:
        feedback.append("Add special characters.")

    if score <= 2 or len(password) < 8:
        level = "Weak"
    elif score <= 4:
        level = "Medium"
    else:
        level = "Strong"

    return {
        "score": score,
        "max_score": len(checks),
        "level": level,
        "feedback": feedback,
    }


def generate_password(length: int = 16):
    pools = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        SAFE_SYMBOLS,
    ]
    guaranteed = [secrets.choice(p) for p in pools]
    combined = "".join(pools)
    remaining = [secrets.choice(combined) for _ in range(length - len(guaranteed))]

    password_chars = guaranteed + remaining
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        path = parsed.path

        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        if "/api/generate" in path:
            length = int(params.get("length", [16])[0])
            response = {"password": generate_password(length)}
        elif "/api/audit" in path:
            pwd = params.get("password", [""])[0]
            response = check_strength(pwd)
        else:
            response = {"status": "CyberShield API Active"}

        self.wfile.write(json.dumps(response).encode("utf-8"))
