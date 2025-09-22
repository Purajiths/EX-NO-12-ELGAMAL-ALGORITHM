# EX-NO-12-ELGAMAL-ALGORITHM

## AIM:
To Implement ELGAMAL ALGORITHM

## ALGORITHM:

1. ElGamal Algorithm is a public-key cryptosystem based on the Diffie-Hellman key exchange and relies on the difficulty of solving the discrete logarithm problem.

2. Initialization:
   - Select a large prime \( p \) and a primitive root \( g \) modulo \( p \) (these are public values).
   - The receiver chooses a private key \( x \) (a random integer), and computes the corresponding public key \( y = g^x \mod p \).

3. Key Generation:
   - The public key is \( (p, g, y) \), and the private key is \( x \).

4. Encryption:
   - The sender picks a random integer \( k \), computes \( c_1 = g^k \mod p \), and \( c_2 = m \times y^k \mod p \), where \( m \) is the message.
   - The ciphertext is the pair \( (c_1, c_2) \).

5. Decryption:
   - The receiver computes \( s = c_1^x \mod p \), and then calculates the plaintext message \( m = c_2 \times s^{-1} \mod p \), where \( s^{-1} \) is the modular inverse of \( s \).

6. Security: The security of the ElGamal algorithm relies on the difficulty of solving the discrete logarithm problem in a large prime field, making it secure for encryption.

## Program:
```
#include <stdio.h>

// Fast modular exponentiation (base^exp % mod)
// Uses __int128 for safe intermediate multiplication on 64-bit compilers (gcc/clang).
long long int modExp(long long int base, long long int exp, long long int mod) {
    long long int result = 1 % mod;
    base %= mod;
    if (mod == 1) return 0;
    while (exp > 0) {
        if (exp & 1) result = (long long)((__int128)result * base % mod);
        base = (long long)((__int128)base * base % mod);
        exp >>= 1;
    }
    return result;
}

int main() {
    long long int p, g;
    long long int privateKeyPurajith, publicKeyPurajith;
    long long int k, message, c1, c2, decryptedMessage;

    // Display student details
    printf("Name    : Purajith\n");
    printf("Reg No. : 212223040158\n\n");

    // Inputs
    printf("Enter a large prime number (p): ");
    if (scanf("%lld", &p) != 1) return 0;
    if (p <= 2) {
        printf("p should be a prime > 2.\n");
        return 0;
    }

    printf("Enter a generator (g): ");
    if (scanf("%lld", &g) != 1) return 0;
    if (g <= 1) {
        printf("g should be > 1.\n");
        return 0;
    }

    // Purajith's private key
    printf("Enter Purajith's private key (1 .. p-2 recommended): ");
    if (scanf("%lld", &privateKeyPurajith) != 1) return 0;
    // normalize private key into [1, p-2]
    privateKeyPurajith %= (p - 1);
    if (privateKeyPurajith <= 0) privateKeyPurajith += (p - 1);
    if (privateKeyPurajith == 0) privateKeyPurajith = 1;

    // Compute public key
    publicKeyPurajith = modExp(g, privateKeyPurajith, p);
    printf("Purajith's public key: %lld\n", publicKeyPurajith);

    // Ramesh (other party) encrypts message
    printf("Enter the message to encrypt (as a number, < p recommended): ");
    if (scanf("%lld", &message) != 1) return 0;
    message %= p; // reduce message into field

    printf("Enter a random number k (1 .. p-2 recommended): ");
    if (scanf("%lld", &k) != 1) return 0;
    k %= (p - 1);
    if (k <= 0) k += (p - 1);

    // Encryption: c1 = g^k mod p, c2 = message * publicKey^k mod p
    c1 = modExp(g, k, p);
    c2 = (long long)((__int128)message * modExp(publicKeyPurajith, k, p) % p);
    printf("Encrypted message (c1, c2): (%lld, %lld)\n", c1, c2);

    // Decryption using modular inverse:
    // s = c1^privateKey mod p, inv_s = s^(p-2) mod p (Fermat) -> decrypted = c2 * inv_s % p
    long long int s = modExp(c1, privateKeyPurajith, p);
    long long int inv_s = modExp(s, p - 2, p); // requires p to be prime
    decryptedMessage = (long long)((__int128)c2 * inv_s % p);
    printf("Decrypted message: %lld\n", decryptedMessage);

    if (decryptedMessage == message) {
        printf("Success: decrypted message matches original.\n");
    } else {
        printf("Warning: decrypted message does NOT match original.\n");
    }

    return 0;
}
```

## Output:
<img width="1620" height="777" alt="image" src="https://github.com/user-attachments/assets/181b6cb1-a0df-4c51-a040-2709d1c2250e" />



## Result:
The program is executed successfully.
