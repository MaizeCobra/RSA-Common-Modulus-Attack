# RSA Common Modulus Attack — Demonstration & Prevention

A Python-based interactive GUI application that demonstrates, proves, and prevents the **RSA Common Modulus Attack** — a classical cryptographic vulnerability arising from flawed key management.

---

## Required Software

| Dependency | Version | Install |
|---|---|---|
| Python | 3.9 or higher | [python.org](https://python.org) |
| matplotlib | latest | `pip install matplotlib` |
| numpy | latest | `pip install numpy` |

> **No external cryptography libraries are used.** All RSA math (`miller_rabin`, `modinv`, `extended_gcd`) is implemented from scratch using only Python's `math` standard library.

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/RSA-Common-Modulus-Attack.git
cd RSA-Common-Modulus-Attack

# 2. Install dependencies
pip install matplotlib numpy
```

---

## How to Run

```bash
python main.py
```

This launches the GUI application.

---

## Step-by-Step Execution

Once the GUI opens:

1. **Run Vulnerability Test** — simulates weak-RNG key generation where two users share a prime factor `p`. The GCD attack is executed and private keys are recovered. Results appear in the log panel.

2. **Show Graphs (G1–G4)** — renders the primary analysis dashboard:
   - G1: Before/After Attack Success Rate
   - G2: Attack Time vs Key Size
   - G3: CIA Triad Security Properties
   - G4: Key Generation Latency Overhead

3. **Show Comparison (G5–G9)** — renders the comparative analysis suite:
   - G5: Execution Time — Attacks vs Prevention Methods
   - G6: Algorithmic Complexity — GCD vs Brute-Force
   - G7: Prevention Method Trade-off (Block Rate / Latency / Scalability)
   - G8: Overhead Cost — Vulnerable vs SecureKeyRegistry
   - G9: Full Scorecard — Best Prevention Strategy

---

## Project Structure

```
├── main.py                   # Entry point — launches the GUI
├── rsa_common_modulus.py     # Core RSA logic, attack, SecureKeyRegistry
├── comparison.py             # Benchmarking: 3 attack + 3 prevention methods
├── graphs.py                 # All 9 graph functions (matplotlib)
├── gui.py                    # Tkinter GUI application
├── Literature_Survey.md      # 10-reference academic literature survey
├── mathematical_proof.md     # Full mathematical proof of both attack vectors
└── system_and_attack_model.md# System model, pseudo-algorithms, code flow
```
