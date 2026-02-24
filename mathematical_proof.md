# Mathematical Background: RSA Common Modulus Attack

This document provides a rigorous mathematical explanation of the RSA Common Modulus attack, fulfilling the requirements for theoretical background, analysis, and a hand-calculated mathematical proof.

---

## A. Mathematical Model

### Variables
- $p, q$ : Large distinct prime numbers.
- $n$ : The RSA modulus, calculated as $n = p \times q$.
- $\phi(n)$ : Euler's totient function, calculated as $\phi(n) = (p-1)(q-1)$.
- $e_1, e_2$ : Public encryption exponents chosen by User 1 and User 2 respectively.
- $d_1, d_2$ : Private decryption exponents for User 1 and User 2.
- $k_1, k_2$ : Integers representing the multiple of $\phi(n)$ in the congruences for $d_1$ and $d_2$.
- $M$ : A plaintext message encrypted by the system.
- $C_1, C_2$ : The ciphertexts produced by encrypting $M$ under $(n, e_1)$ and $(n, e_2)$.

### Assumptions
1. **Shared Modulus Vulnerability**: User 1 and User 2 accidentally share the exact same modulus $n$. This usually occurs when a central authority generates keys and distributes the same $n$ to multiple users to save computational resources, or due to a flawed pseudo-random number generator (PRNG).
2. **Distinct Exponents**: Both users have distinct public exponents ($e_1 \neq e_2$).
3. **Coprime Exponents**: The public exponents $e_1$ and $e_2$ are coprime, meaning their greatest common divisor is 1: $\gcd(e_1, e_2) = 1$.
4. **Public Knowledge**: An attacker can intercept the ciphertexts $C_1$ and $C_2$, and has access to the public keys $(n, e_1)$ and $(n, e_2)$.

### Equations
1. **Modulus calculation**: $n = p \times q$
2. **Euler's Totient**: $\phi(n) = (p-1)(q-1)$
3. **Key Generation (Modular Inverse)**: 
   - $e_1 \cdot d_1 \equiv 1 \pmod{\phi(n)}$
   - $e_2 \cdot d_2 \equiv 1 \pmod{\phi(n)}$
4. **Encryption**: 
   - $C_1 \equiv M^{e_1} \pmod n$
   - $C_2 \equiv M^{e_2} \pmod n$
5. **Decryption**: $M \equiv C^d \pmod n$

---

## B. Mathematical Analysis

### Why the baseline system is insecure
The fundamental security of the RSA cryptosystem relies on the computational difficulty of entirely factoring the large integer $n$ back into its prime components $p$ and $q$. Without knowing $p$ and $q$, one cannot compute $\phi(n)$, and therefore cannot calculate the private key $d$ directly.

However, the baseline system becomes critically insecure if a centralized generation authority (or a flawed PRNG) issues keys where multiple users share the *exact same modulus* $n$, even if they are given unique $e$ and $d$ pairs. 

### How the attack exploits it
There are mathematically two distinct vectors to exploit this vulnerability:

**Attack Vector 1: The GCD attack on Shared Prime Factors (Simulated in the GUI)**
If two users are given different moduli ($n_1 \neq n_2$), but their RNGs were poorly seeded causing them to share a *single* prime factor $p$ (i.e., $n_1 = p \cdot q_1$ and $n_2 = p \cdot q_2$), an attacker can use the Euclidean Algorithm.
The attacker computes $\gcd(n_1, n_2)$. Because both moduli contain $p$, the greatest common divisor is $p$.
Once $p$ is exposed, finding $q_1$ is trivial division ($q_1 = n_1 / p$). The attacker has instantly factored the keys without brute force.

**Attack Vector 2: The Same-Message Common Modulus Attack (The Textbook Proof)**
If two users share the exact same modulus $n$, and an attacker intercepts a single plaintext message $M$ that was encrypted and sent to *both* users, the attacker can recover the plaintext $M$ without needing to factor $n$ or find the private keys at all. 

This exploits the universally true mathematical property of Bézout's Identity. Because $\gcd(e_1, e_2) = 1$, the Extended Euclidean Algorithm guarantees there exist integers $x$ and $y$ such that:
$e_1 \cdot x + e_2 \cdot y = 1$

The attacker intercepts $C_1$ and $C_2$. By raising each ciphertext to these $x$ and $y$ powers and multiplying them, the attacker isolates $M^1$, revealing the original decrypted message algebraically. 

---

## C. Proof Requirement

This section provides a complete hand-calculated mathematical proof of **Attack Vector 2** (recovering the plaintext without the private key when $n$ is shared), using small integer sizes to clearly trace the mathematics.

### Step 1: System Setup
1. **Select Primes**: Let $p = 5$ and $q = 11$.
2. **Calculate Modulus ($n$)**: $n = p \times q = 5 \times 11 = 55$. 
   - *This $n=55$ is the shared modulus given to both users.*
3. **Calculate Totient ($\phi(n)$)**: $\phi(n) = (p-1)(q-1) = 4 \times 10 = 40$.
4. **Select Public Exponents ($e$)**: 
   - User 1 selects $e_1 = 3$. (Verify $\gcd(3, 40) = 1$)
   - User 2 selects $e_2 = 7$. (Verify $\gcd(7, 40) = 1$)
   - *Note: ensure $\gcd(e_1, e_2) = \gcd(3, 7) = 1$. This is required for the attack.*

### Step 2: Encrypting the Message
Let the secret message $M = 2$ be sent to both User 1 and User 2.
1. **Encrypt for User 1**: $C_1 \equiv M^{e_1} \pmod n$
   - $C_1 \equiv 2^3 \pmod{55}$
   - $C_1 \equiv 8 \pmod{55}$
   - Ciphertext 1 is **8**.
2. **Encrypt for User 2**: $C_2 \equiv M^{e_2} \pmod n$
   - $C_2 \equiv 2^7 \pmod{55}$
   - $C_2 \equiv 128 \pmod{55}$
   - $128 = (2 \times 55) + 18$, so $C_2 \equiv 18 \pmod{55}$
   - Ciphertext 2 is **18**.

*The attacker now intercepts $C_1 = 8$, $C_2 = 18$, and knows the public keys $(n=55, e_1=3)$ and $(n=55, e_2=7)$.*

### Step 3: The Attack - Bézout's Identity
The attacker knows $\gcd(e_1, e_2) = \gcd(3, 7) = 1$. By Bézout's identity, there exist integers $x$ and $y$ such that:
$x \cdot e_1 + y \cdot e_2 = 1$

The attacker uses the Extended Euclidean Algorithm on 3 and 7 to find $x$ and $y$:
- $7 = 2 \times 3 + 1$
- Rearranging to isolate the remainder 1: $1 = 7 - (2 \times 3)$
- Thus, $1 = (1 \times 7) + (-2 \times 3)$
- Therefore, $y = 1$ (for $e_2$) and $x = -2$ (for $e_1$).

We mathematically verify: $(-2 \times 3) + (1 \times 7) = -6 + 7 = 1$. The identity holds.

### Step 4: The Attack - Message Recovery
The attacker will leverage the property of exponents to isolate $M$. 
Given $C_1 \equiv M^{e_1} \pmod n$ and $C_2 \equiv M^{e_2} \pmod n$, the attacker calculates:
$(C_1)^x \times (C_2)^y \equiv (M^{e_1})^x \times (M^{e_2})^y \pmod n$
$(C_1)^x \times (C_2)^y \equiv M^{x \cdot e_1} \times M^{y \cdot e_2} \pmod n$
$(C_1)^x \times (C_2)^y \equiv M^{x \cdot e_1 + y \cdot e_2} \pmod n$

Since we know $x \cdot e_1 + y \cdot e_2 = 1$, the right side simplifies entirely to $M^1$, which is just $M$:
$M \equiv (C_1)^x \times (C_2)^y \pmod n$

### Step 5: Calculating the Result
The attacker substitutes the known values into the recovery equation: $M \equiv (C_1)^x \times (C_2)^y \pmod n$.
- $C_1 = 8$, $x = -2$
- $C_2 = 18$, $y = 1$
- $n = 55$

$M \equiv 8^{-2} \times 18^1 \pmod{55}$

Because $x$ is negative, $8^{-2}$ is the modular multiplicative inverse of $8^2$ modulo 55.
- Calculate $8^2 = 64 \equiv 9 \pmod{55}$
- Find the inverse of 9 modulo 55, denoted as $9^{-1}$. We need $9 \times v \equiv 1 \pmod{55}$.
- Testing multiples of 55 plus 1: $(55 \times 8) + 1 = 441$. Does $441 / 9$ yield an integer? Yes, $441 / 9 = 49$.
- So, $9^{-1} \equiv 49 \pmod{55}$.
- Thus, $8^{-2} \equiv 49 \pmod{55}$.

Now finish the calculation:
$M \equiv 49 \times 18 \pmod{55}$
$49 \times 18 = 882$
$882 \div 55 = 16.036$
$16 \times 55 = 880$
$882 - 880 = 2$

$M = 2$

**Proof Complete.** The attacker has algebraically recovered the exact original plaintext ($M = 2$) using only publicly intercepted variables, entirely breaking the RSA cryptosystem.
