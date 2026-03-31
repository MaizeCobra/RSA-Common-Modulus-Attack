"""
comparison.py
-------------
Phase 2: Comparative Analysis of RSA Common Modulus Attack & Prevention approaches.

Three attack methods compared:
  A. GCD Shared Prime Attack       — our approach (O(log n))
  B. Bézout Message Recovery       — algebraic plaintext recovery (no key needed)
  C. Brute-Force Trial Division    — naive baseline (O(√n))

Three prevention methods compared:
  X. SecureKeyRegistry             — our approach (global uniqueness check)
  Y. Independent Key Generation   — no shared entropy, fresh PRNG per user
  Z. Pairwise GCD Audit           — post-generation scan of all moduli pairs

No external cryptographic libraries used.
"""

import math
import random
import time
import tracemalloc

from rsa_common_modulus import (
    generate_prime,
    generate_rsa_keypair,
    generate_shared_modulus_keypairs,
    generate_secure_keypair,
    common_modulus_attack,
    run_attack_on_shared_modulus,
    reset_registry,
    _modinv,
)


# ──────────────────────────────────────────────
# UTILITY: Memory measurement
# ──────────────────────────────────────────────

def measure_memory(fn, *args, **kwargs):
    """
    Call fn(*args, **kwargs), return (result, peak_memory_kb).
    Uses tracemalloc to track peak allocated memory in KB.
    """
    tracemalloc.start()
    result = fn(*args, **kwargs)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return result, peak / 1024  # → KB


# ──────────────────────────────────────────────
# ATTACK METHOD A — GCD Shared Prime Attack (ours)
# ──────────────────────────────────────────────

def attack_gcd(bits: int = 512):
    """
    Method A: GCD-based shared prime factor attack.
    Generates a vulnerable keypair and attacks it.
    Returns dict with success, time, memory.
    """
    def _run():
        kp1, kp2 = generate_shared_modulus_keypairs(bits)
        result = run_attack_on_shared_modulus(kp1, kp2)
        return result["success"]

    t0 = time.perf_counter()
    (success, mem_kb) = measure_memory(_run)
    elapsed = time.perf_counter() - t0

    return {
        "method": "A: GCD Shared Prime",
        "success": success,
        "time_s": elapsed,
        "memory_kb": mem_kb,
        "bits": bits,
    }


# ──────────────────────────────────────────────
# ATTACK METHOD B — Bézout Algebraic Message Recovery
# ──────────────────────────────────────────────

def _bezout_recover(n: int, e1: int, e2: int, c1: int, c2: int) -> int:
    """
    Given two ciphertexts of the SAME plaintext under same n but different e:
      C1 = M^e1 mod n,  C2 = M^e2 mod n
    Recover M using extended Euclidean:
      Find x, y  s.t.  e1*x + e2*y = 1  (requires gcd(e1,e2)=1)
      M = C1^x * C2^y mod n
    """
    # Extended GCD to find Bézout coefficients
    def ext_gcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x1, y1 = ext_gcd(b % a, a)
        return g, y1 - (b // a) * x1, x1

    g, x, y = ext_gcd(e1, e2)
    if g != 1:
        return None  # Attack requires gcd(e1,e2)=1

    # Handle negative exponents via modular inverse
    if x < 0:
        c1_inv = pow(c1, -1, n)
        result = (pow(c1_inv, -x, n) * pow(c2, y, n)) % n
    elif y < 0:
        c2_inv = pow(c2, -1, n)
        result = (pow(c1, x, n) * pow(c2_inv, -y, n)) % n
    else:
        result = (pow(c1, x, n) * pow(c2, y, n)) % n

    return result


def attack_bezout(bits: int = 512):
    """
    Method B: Bézout algebraic message recovery.
    Same plaintext M is encrypted under (n, e1) and (n, e2) with coprime e values.
    Uses e1=3, e2=65537 (guaranteed coprime).
    Returns dict with success, time, memory.
    """
    e1, e2 = 3, 65537   # gcd(3, 65537) = 1

    def _run():
        half = bits // 2
        while True:
            p = generate_prime(half)
            q = generate_prime(half)
            if p == q:
                continue
            n = p * q
            phi = (p - 1) * (q - 1)
            if math.gcd(e1, phi) != 1 or math.gcd(e2, phi) != 1:
                continue
            break

        # Choose a random plaintext message (small for speed)
        M = random.randint(2, min(2**32, n - 1))

        C1 = pow(M, e1, n)
        C2 = pow(M, e2, n)

        M_recovered = _bezout_recover(n, e1, e2, C1, C2)
        return M_recovered == M

    t0 = time.perf_counter()
    success, mem_kb = measure_memory(_run)
    elapsed = time.perf_counter() - t0

    return {
        "method": "B: Bézout Recovery",
        "success": success,
        "time_s": elapsed,
        "memory_kb": mem_kb,
        "bits": bits,
    }


# ──────────────────────────────────────────────
# ATTACK METHOD C — Brute-Force Trial Division
# ──────────────────────────────────────────────

def _trial_division(n: int):
    """
    Naive trial division: try every odd integer from 3 up to √n.
    Returns (p, q) if found, else None.
    Works in O(√n) — only feasible for tiny n.
    """
    if n % 2 == 0:
        return 2, n // 2
    i = 3
    limit = math.isqrt(n) + 1
    while i <= limit:
        if n % i == 0:
            return i, n // i
        i += 2
    return None


def attack_brute_force(bits: int = 32):
    """
    Method C: Brute-force trial division on genuinely small keys.
    We use bits=32 (default) as the actual test size — this WILL run and succeed.
    For context, bits=512 would take ~10^60 operations; we annotate that fact.

    Returns dict with success, time, memory, bits, extrapolated_512_ops.
    """
    def _run():
        half = bits // 2
        p = generate_prime(half)
        q = generate_prime(half)
        if p == q:
            q = generate_prime(half)
        n = p * q

        result = _trial_division(n)
        if result is None:
            return False
        p_found, q_found = result
        return (p_found == p and q_found == q) or (p_found == q and q_found == p)

    t0 = time.perf_counter()
    success, mem_kb = measure_memory(_run)
    elapsed = time.perf_counter() - t0

    # Extrapolation: ops needed for √(2^512) ≈ 2^256
    ops_32bit  = 2 ** (bits // 2)
    ops_512bit = 2 ** 256
    scale_factor = ops_512bit / ops_32bit if ops_32bit > 0 else float("inf")
    # Assume ~10^9 ops/sec on modern hardware
    est_seconds_512 = scale_factor / 1e9

    return {
        "method": "C: Brute-Force Trial Division",
        "success": success,
        "time_s": elapsed,
        "memory_kb": mem_kb,
        "bits": bits,
        "tested_bits": bits,
        "extrapolated_512_ops": ops_512bit,
        "extrapolated_512_years": est_seconds_512 / (3600 * 24 * 365),
    }


# ──────────────────────────────────────────────
# ATTACK COMPARISON RUNNER
# ──────────────────────────────────────────────

def run_attack_comparison(n_tests: int = 10, bits: int = 512,
                          progress_callback=None):
    """
    Run n_tests of each attack method and return averaged results.

    Method C (brute-force) always uses 32-bit keys regardless of `bits`.
    Returns list of 3 summary dicts (one per method).
    """
    methods = {
        "A": [],
        "B": [],
        "C": [],
    }

    for i in range(1, n_tests + 1):
        r_a = attack_gcd(bits)
        r_b = attack_bezout(bits)
        r_c = attack_brute_force(32)   # always 32-bit for brute force

        methods["A"].append(r_a)
        methods["B"].append(r_b)
        methods["C"].append(r_c)

        if progress_callback:
            progress_callback(i, n_tests)

    def _summarise(runs):
        total = len(runs)
        success_rate = sum(r["success"] for r in runs) / total * 100
        avg_time = sum(r["time_s"] for r in runs) / total
        avg_mem = sum(r["memory_kb"] for r in runs) / total
        return {
            "method": runs[0]["method"],
            "bits": runs[0]["bits"],
            "success_rate": success_rate,
            "avg_time_s": avg_time,
            "avg_time_ms": avg_time * 1000,
            "avg_memory_kb": avg_mem,
            "efficiency": success_rate / (avg_time * 1000) if avg_time > 0 else 0,
            # extra for brute force
            "extrapolated_512_years": runs[0].get("extrapolated_512_years"),
            "tested_bits": runs[0].get("tested_bits", runs[0]["bits"]),
        }

    return [_summarise(methods["A"]), _summarise(methods["B"]), _summarise(methods["C"])]


# ──────────────────────────────────────────────
# PREVENTION METHOD X — SecureKeyRegistry (ours)
# ──────────────────────────────────────────────

def prevention_registry(bits: int = 512):
    """
    Method X: Our SecureKeyRegistry — global modulus uniqueness check.
    Generates 2 secure unique keys, then tests if GCD attack still succeeds.
    """
    def _run():
        reset_registry()
        kp1 = generate_secure_keypair(bits)
        kp2 = generate_secure_keypair(bits)
        result = common_modulus_attack(kp1["n"], kp2["n"])
        return result is not None  # True = attack succeeded (bad)

    t0 = time.perf_counter()
    attack_succeeded, mem_kb = measure_memory(_run)
    elapsed = time.perf_counter() - t0

    return {
        "method": "X: SecureKeyRegistry",
        "attack_blocked": not attack_succeeded,
        "time_s": elapsed,
        "memory_kb": mem_kb,
        "bits": bits,
    }


# ──────────────────────────────────────────────
# PREVENTION METHOD Y — Independent Key Generation
# ──────────────────────────────────────────────

def prevention_independent(bits: int = 512):
    """
    Method Y: Each user independently generates their own (p, q) from fresh entropy.
    No shared state — simulates truly isolated key generation per user.
    In our model: both call generate_rsa_keypair independently without sharing primes.
    """
    def _run():
        # Seed differently to simulate independent users
        random.seed()
        kp1 = generate_rsa_keypair(bits)
        random.seed()
        kp2 = generate_rsa_keypair(bits)
        result = common_modulus_attack(kp1["n"], kp2["n"])
        return result is not None

    t0 = time.perf_counter()
    attack_succeeded, mem_kb = measure_memory(_run)
    elapsed = time.perf_counter() - t0

    return {
        "method": "Y: Independent Keygen",
        "attack_blocked": not attack_succeeded,
        "time_s": elapsed,
        "memory_kb": mem_kb,
        "bits": bits,
    }


# ──────────────────────────────────────────────
# PREVENTION METHOD Z — Pairwise GCD Audit
# ──────────────────────────────────────────────

def prevention_gcd_audit(bits: int = 512, n_users: int = 5):
    """
    Method Z: Post-generation pairwise GCD audit across all user keys.
    Generates n_users keypairs independently, then audits all pairs.
    If GCD > 1 between any pair → regenerate both.
    Returns whether final set is confirmed clean.
    """
    def _run():
        keypairs = [generate_rsa_keypair(bits) for _ in range(n_users)]

        # Audit all pairs — any shared factor triggers rejection
        for i in range(len(keypairs)):
            for j in range(i + 1, len(keypairs)):
                g = math.gcd(keypairs[i]["n"], keypairs[j]["n"])
                if g > 1:
                    return False  # Would regenerate in production

        # Attack attempt on first two
        result = common_modulus_attack(keypairs[0]["n"], keypairs[1]["n"])
        return result is not None  # True = attack found a flaw

    t0 = time.perf_counter()
    attack_succeeded, mem_kb = measure_memory(_run)
    elapsed = time.perf_counter() - t0

    return {
        "method": "Z: Pairwise GCD Audit",
        "attack_blocked": not attack_succeeded,
        "time_s": elapsed,
        "memory_kb": mem_kb,
        "bits": bits,
        "n_users": n_users,
    }


# ──────────────────────────────────────────────
# PREVENTION COMPARISON RUNNER
# ──────────────────────────────────────────────

def run_prevention_comparison(n_tests: int = 10, bits: int = 512,
                              progress_callback=None):
    """
    Run n_tests of each prevention method and return averaged results.
    Returns list of 3 summary dicts (one per method).
    """
    methods = {"X": [], "Y": [], "Z": []}

    for i in range(1, n_tests + 1):
        methods["X"].append(prevention_registry(bits))
        methods["Y"].append(prevention_independent(bits))
        methods["Z"].append(prevention_gcd_audit(bits))

        if progress_callback:
            progress_callback(i, n_tests)

    def _summarise(runs):
        total = len(runs)
        block_rate = sum(r["attack_blocked"] for r in runs) / total * 100
        avg_time = sum(r["time_s"] for r in runs) / total
        avg_mem = sum(r["memory_kb"] for r in runs) / total
        return {
            "method": runs[0]["method"],
            "bits": runs[0]["bits"],
            "block_rate": block_rate,          # % of attacks blocked
            "attack_success_rate": 100 - block_rate,
            "avg_time_s": avg_time,
            "avg_time_ms": avg_time * 1000,
            "avg_memory_kb": avg_mem,
            # Security improvement % vs baseline (vulnerable = 0% blocked)
            "security_improvement_pct": block_rate,
        }

    return [_summarise(methods["X"]), _summarise(methods["Y"]), _summarise(methods["Z"])]


# ──────────────────────────────────────────────
# CIA TRIAD METRICS
# ──────────────────────────────────────────────

def compute_cia_metrics(attack_results_before: list, attack_results_after: list) -> dict:
    """
    Compute Confidentiality, Integrity, Authentication rates for before/after.

    Definitions (for RSA common modulus):
      Confidentiality  = 100% - attack_success_rate  (messages stay private)
      Integrity        = % of cases where private key d was NOT recovered
      Authentication   = % of cases where attacker CANNOT forge a signature
                         (= Integrity, since forging requires d)

    Returns dict with before/after values for each CIA property.
    """
    def _rates(results):
        total = len(results)
        if total == 0:
            return 0, 0, 0
        # A result is a dict; in attack comparison results, success means attack worked
        success_count = sum(
            1 for r in results
            if r.get("success", False) or r.get("success_rate", 0) > 50
        )
        attack_rate = success_count / total * 100
        conf = 100 - attack_rate
        integ = 100 - attack_rate   # private key compromised = same as attack success
        auth = 100 - attack_rate    # cannot forge without d
        return conf, integ, auth

    conf_b, integ_b, auth_b = _rates(attack_results_before)
    conf_a, integ_a, auth_a = _rates(attack_results_after)

    return {
        "before": {"confidentiality": conf_b, "integrity": integ_b, "authentication": auth_b},
        "after":  {"confidentiality": conf_a, "integrity": integ_a, "authentication": auth_a},
    }
