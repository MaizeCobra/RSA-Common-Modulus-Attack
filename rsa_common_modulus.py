"""
rsa_common_modulus.py
---------------------
RSA Common Modulus Attack — all crypto logic implemented from scratch.
No external cryptographic libraries used.
Uses only: Python built-ins, random, math, time
"""

import random
import math
import time


# ──────────────────────────────────────────────
# 1.  MILLER-RABIN PRIMALITY TEST (from scratch)
# ──────────────────────────────────────────────

def _miller_rabin_round(n: int, a: int) -> bool:
    """Single witness round. Returns True if n is *probably* prime."""
    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    x = pow(a, d, n)
    if x == 1 or x == n - 1:
        return True

    for _ in range(r - 1):
        x = pow(x, 2, n)
        if x == n - 1:
            return True
    return False


def is_prime(n: int, rounds: int = 5) -> bool:
    """
    Miller-Rabin primality test.
    rounds=5 is sufficient for educational use (not industrial).
    """
    if n < 2:
        return False
    # Small primes fast-path
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    if n in small_primes:
        return True
    if any(n % p == 0 for p in small_primes):
        return False

    # Choose witnesses
    witnesses = [2, 3, 5, 7, 11]
    if n > 3_215_031_751:
        witnesses += [13, 17, 19, 23]

    # Add random witnesses for extra confidence
    witnesses += [random.randrange(2, n - 1) for _ in range(rounds)]

    return all(_miller_rabin_round(n, a) for a in witnesses if a < n)


# ──────────────────────────────────────────────
# 2.  PRIME GENERATION
# ──────────────────────────────────────────────

def generate_prime(bits: int) -> int:
    """Generate a random prime with the specified bit length."""
    while True:
        # Set MSB and LSB so the number is exactly `bits` bits and odd
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1)) | 1      # ensure correct size + odd
        if is_prime(candidate):
            return candidate


# ──────────────────────────────────────────────
# 3.  RSA KEY GENERATION
# ──────────────────────────────────────────────

def _modinv(a: int, m: int) -> int:
    """
    Extended Euclidean Algorithm — modular inverse of a mod m.
    Returns x such that (a * x) % m == 1.
    """
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"Modular inverse does not exist: gcd({a},{m})={g}")
    return x % m


def _extended_gcd(a: int, b: int):
    """Returns (gcd, x, y) such that a*x + b*y = gcd."""
    if a == 0:
        return b, 0, 1
    g, x1, y1 = _extended_gcd(b % a, a)
    return g, y1 - (b // a) * x1, x1


def generate_rsa_keypair(bits: int = 512):
    """
    Generate an RSA key pair (n, e, d, p, q).
    Returns dict with all components.
    """
    half_bits = bits // 2

    while True:
        p = generate_prime(half_bits)
        q = generate_prime(half_bits)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)

        # Common public exponent
        e = 65537
        if math.gcd(e, phi) != 1:
            continue

        d = _modinv(e, phi)
        return {"n": n, "e": e, "d": d, "p": p, "q": q, "bits": bits}


def generate_shared_modulus_keypairs(bits: int = 512):
    """
    Vulnerable scenario: two users' moduli share a common prime factor p.
      n1 = p * q1   (User 1)
      n2 = p * q2   (User 2, different q but SAME p — the vulnerability)

    This simulates poor key-generation: both users' RNG produced the same
    prime p.  An attacker computes GCD(n1, n2) = p, trivially factoring both.

    Returns (keypair1, keypair2) with n1 != n2 but sharing prime p.
    """
    half_bits = bits // 2

    while True:
        # Shared (weak) prime — the vulnerability
        p = generate_prime(half_bits)

        # Each user picks an independent second prime
        q1 = generate_prime(half_bits)
        q2 = generate_prime(half_bits)
        if q1 == p or q2 == p or q1 == q2:
            continue

        n1 = p * q1
        n2 = p * q2
        if n1 == n2:
            continue

        phi1 = (p - 1) * (q1 - 1)
        phi2 = (p - 1) * (q2 - 1)

        e1 = 65537
        e2 = 65537   # Both users can use same e — doesn't matter

        if math.gcd(e1, phi1) != 1 or math.gcd(e2, phi2) != 1:
            continue

        d1 = _modinv(e1, phi1)
        d2 = _modinv(e2, phi2)

        kp1 = {"n": n1, "e": e1, "d": d1, "p": p, "q": q1, "bits": bits}
        kp2 = {"n": n2, "e": e2, "d": d2, "p": p, "q": q2, "bits": bits}
        return kp1, kp2


# ──────────────────────────────────────────────
# 4.  COMMON MODULUS ATTACK
# ──────────────────────────────────────────────

def common_modulus_attack(n1: int, n2: int):
    """
    Given two RSA moduli, compute GCD to find a shared prime factor.

    If n1 == n2  →  GCD = n (trivially broken, same keys).
    If n1 != n2 but share p  →  GCD = p.

    Returns (p, q1, q2) or None if attack fails.
    """
    g = math.gcd(n1, n2)
    if g == 1 or g == n1 or g == n2:
        return None   # Attack failed — moduli are coprime or identical
    p = g
    q1 = n1 // p
    q2 = n2 // p
    return p, q1, q2


def recover_private_key_from_factors(n: int, e: int, p: int, q: int) -> int:
    """Recover private key d given the factorisation of n."""
    phi = (p - 1) * (q - 1)
    d = _modinv(e, phi)
    return d


def run_attack_on_shared_modulus(kp1: dict, kp2: dict):
    """
    Attack two keypairs that share the same n.
    Returns attack result dict.
    """
    n1, n2 = kp1["n"], kp2["n"]
    e1, e2 = kp1["e"], kp2["e"]
    d1_real, d2_real = kp1["d"], kp2["d"]

    result = common_modulus_attack(n1, n2)
    if result is None:
        return {
            "success": False,
            "reason": "GCD = 1 (moduli are coprime, attack failed)",
            "n1": n1, "e1": e1, "e2": e2,
        }

    p, q1, q2 = result
    recovered_d1 = recover_private_key_from_factors(n1, e1, p, q1)
    recovered_d2 = recover_private_key_from_factors(n2, e2, p, q2)

    # Verify recovery
    d1_correct = (recovered_d1 == d1_real)
    d2_correct = (recovered_d2 == d2_real)

    return {
        "success": True,
        "p": p,
        "q1": q1,
        "q2": q2,
        "recovered_d1": recovered_d1,
        "recovered_d2": recovered_d2,
        "d1_correct": d1_correct,
        "d2_correct": d2_correct,
        "n": n1,
        "e1": e1,
        "e2": e2,
    }


# ──────────────────────────────────────────────
# 5.  PREVENTION MECHANISM
# ──────────────────────────────────────────────

class SecureKeyRegistry:
    """
    Tracks all generated moduli n.
    Raises an error (or regenerates) if the same n is reused.
    """
    def __init__(self):
        self._registered: set = set()

    def is_unique(self, n: int) -> bool:
        return n not in self._registered

    def register(self, n: int):
        self._registered.add(n)

    def clear(self):
        self._registered.clear()


# Global registry for prevention-mode
_registry = SecureKeyRegistry()


def generate_secure_keypair(bits: int = 512):
    """Generate a keypair ensuring n is globally unique."""
    while True:
        kp = generate_rsa_keypair(bits)
        if _registry.is_unique(kp["n"]):
            _registry.register(kp["n"])
            return kp


def reset_registry():
    """Reset the global key registry (use between test runs)."""
    _registry.clear()


# ──────────────────────────────────────────────
# 6.  TEST RUNNER
# ──────────────────────────────────────────────

def run_tests(n_tests: int = 25, bits: int = 512, use_prevention: bool = False,
              progress_callback=None):
    """
    Run n_tests cases.

    Without prevention: generate shared-modulus keypairs → attack should succeed.
    With prevention:    generate unique-modulus keypairs → attack should fail.

    progress_callback(test_num, total, result_dict) called after each test.
    Returns list of result dicts with timing info.
    """
    results = []
    reset_registry()

    for i in range(1, n_tests + 1):
        t_start = time.perf_counter()

        if use_prevention:
            # Secure: each user gets an independent, unique n
            try:
                kp1 = generate_secure_keypair(bits)
                kp2 = generate_secure_keypair(bits)
            except Exception as exc:
                result = {
                    "test_num": i,
                    "success": False,
                    "reason": f"Key generation error: {exc}",
                    "elapsed": time.perf_counter() - t_start,
                    "bits": bits,
                    "prevention": True,
                }
                results.append(result)
                if progress_callback:
                    progress_callback(i, n_tests, result)
                continue

            # Attack should fail because n values are different
            attack_result = common_modulus_attack(kp1["n"], kp2["n"])
            elapsed = time.perf_counter() - t_start

            result = {
                "test_num": i,
                "success": attack_result is not None,
                "elapsed": elapsed,
                "bits": bits,
                "prevention": True,
                "n1": kp1["n"],
                "n2": kp2["n"],
                "reason": "Shared prime found (unexpected)" if attack_result else
                          "Attack failed — unique moduli (expected)",
            }

        else:
            # Vulnerable: both users share the same n
            try:
                kp1, kp2 = generate_shared_modulus_keypairs(bits)
            except Exception as exc:
                result = {
                    "test_num": i,
                    "success": False,
                    "reason": f"Key generation error: {exc}",
                    "elapsed": time.perf_counter() - t_start,
                    "bits": bits,
                    "prevention": False,
                }
                results.append(result)
                if progress_callback:
                    progress_callback(i, n_tests, result)
                continue

            raw = run_attack_on_shared_modulus(kp1, kp2)
            elapsed = time.perf_counter() - t_start

            result = {
                "test_num": i,
                "success": raw.get("success", False),
                "elapsed": elapsed,
                "bits": bits,
                "prevention": False,
                "n": kp1["n"],
                "e1": kp1["e"],
                "e2": kp2["e"],
                "p": raw.get("p"),
                "recovered_d1": raw.get("recovered_d1"),
                "recovered_d2": raw.get("recovered_d2"),
                "d1_correct": raw.get("d1_correct"),
                "d2_correct": raw.get("d2_correct"),
                "reason": raw.get("reason", ""),
            }

        results.append(result)
        if progress_callback:
            progress_callback(i, n_tests, result)

    return results


def summarise_results(results: list) -> dict:
    """Compute summary statistics for a test run."""
    total = len(results)
    successes = sum(1 for r in results if r["success"])
    failures = total - successes
    success_rate = (successes / total * 100) if total > 0 else 0
    avg_time = sum(r["elapsed"] for r in results) / total if total > 0 else 0

    return {
        "total": total,
        "successes": successes,
        "failures": failures,
        "success_rate": success_rate,
        "avg_time": avg_time,
    }


# ──────────────────────────────────────────────
# 7.  MATHEMATICAL PROOF (as strings for GUI)
# ──────────────────────────────────────────────

MATH_PROOF = """
MATHEMATICAL PROOF — Why Shared Modulus Breaks RSA
===================================================

Setup:
  User 1: public key  (n, e1),  private key d1  where e1·d1 ≡ 1 (mod φ(n))
  User 2: public key  (n, e2),  private key d2  where e2·d2 ≡ 1 (mod φ(n))
  Both users share the SAME modulus n = p·q.

Attack — factoring via GCD:
  An attacker observes n in both public keys.
  GCD(n, n) = n  — trivially the entire modulus.

  More powerfully, if two DIFFERENT moduli n1 and n2 share a factor p:
    GCD(n1, n2) = p   [Euclidean algorithm, O(log n) time]
    q1 = n1 / p,   q2 = n2 / p
    φ(n1) = (p-1)(q1-1),  φ(n2) = (p-1)(q2-1)
    d1 = e1⁻¹ mod φ(n1),  d2 = e2⁻¹ mod φ(n2)
  → Both private keys are recovered in polynomial time.

Why sharing n is catastrophic:
  Even if e1 ≠ e2, both private keys satisfy:
    d1 ≡ e1⁻¹ (mod (p-1)(q-1))
    d2 ≡ e2⁻¹ (mod (p-1)(q-1))
  Knowing φ(n) = (p-1)(q-1) is equivalent to knowing the factorisation.

Prevention — Unique Moduli:
  If n1 ≠ n2 and GCD(n1, n2) = 1 (coprime):
    GCD attack yields 1 — no information gained.
    Factoring each ni independently is computationally infeasible
    for 2048-bit+ keys (best known: General Number Field Sieve).
  → Uniqueness check during key generation entirely prevents the attack.
"""
