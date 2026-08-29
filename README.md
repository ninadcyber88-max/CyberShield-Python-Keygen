# 🛡️ CyberShield // Python Password Auditor & Keygen

A cryptographically secure password evaluation suite and guaranteed-entropy key generator built with Python standard libraries (`secrets`, `dataclasses`, `string`).

---

## ⚡ Features

* **Single-Pass Evaluation (`check_strength`):** Analyzes password composition (lowercase, uppercase, numbers, symbols, length) in a single loop for optimal performance.
* **Granular Feedback (`StrengthReport`):** Returns scoring metadata and structured recommendations to improve weak passwords.
* **Cryptographically Guaranteed Entropy (`generate_password`):** Guarantees at least one character from each character pool and randomizes sequence using a secure Fisher-Yates shuffle via `secrets.SystemRandom`.
* **Zero Dependencies:** Runs on standard Python 3.8+ without external third-party packages.

---

## 🚀 Usage

### 1. Run Directly
```bash
python cyber_shield.py
