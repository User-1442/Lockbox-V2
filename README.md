Lockbox V2: Technical Specification

LOCKBOX V2 is a custom file encryption system made to avoid normal cryptographic algorithms. This includes AES, RSA, and SHA. It uses a password and timestamp based dynamic key derivation function along with a non-standard byte scrambling mechanism. The intention is to explore whether a custom architecture can resist both brute-force and quantum attacks. [provided the attacker has only the ciphertext and no seed or algorithm details.]

Lockbox V2: Architecture summary

lock_key: Custom key derivation function that hashes the password and seed across 10,000 rounds with per-byte XOR and rotation.

custom_scramble: Encrypts each chunk of data using key, index, and bitwise operations

custom_unscramble: The reverse of scramble, used during decryption.

Seed(timestamp): Acts like a salt. Required to reconstruct the correct key. Not stored in the output file.

Lockbox V2: Key Derivation. (lock_key(password, seed))
This function generates a 32-byte key. Here's how:

1. It Concatenates the password and timestamp
2. It loops 10,000 times
    XORing each byte with it's index and the iteration
    Rotates bits left based on iteration
    Reverses the byte array each round
3. It truncates or pads the result to 32 bytes.

Lockbox V2: custom_scramble(chunk, key, index)
Each byte is modified by the following function:
out[i] = ((byte + key[i % key_len] + index) ^ ((i * 19) % 251)) & 0xFF
Every 3rd byte is rotated left by 1 bit.
Every odd-indexed chunk (based on index) is reversed
This adds position-dependent and key-dependent obfuscation.

Lockbox V2: custom_unscramble(...)
Function reverses the steps in custom_scramble, in the correct order which is:
Re-reverses the chunk if needed
Reverses bit rotations
Reverses XOR/addition logic

Lockbox V2: File Format
First 7 bytes: Magic string b'lockbox'
Rest: Fully encrypted byte stream.
The seed is NOT included. The user must retain it manually.

Lockbox V2: Security Philosophy

This encryption system is based on "security through secrecy of the method and seed" and not peer-reviewed cryptography.

It's build to resist the following attacks:
	Dictionary attacks(due to dynamic key generation)
	Byte-level analysis(due to nonlinear scrambles and reversals)
	Shor's algorithm(no RSA-style math)
It assumes the attackers do not know the scrambling method, seed format, or exact byte transformations.

Lockbox V2: Limitations
1. No authenticated encryption (tamper detection like GCM or HMAC)
2. No entropy based analysis done on ciphertext
3. No peer review or cryptanalysis yet
4. All security collapses if the seed or password are weak or lost.

Lockbox V2: Summary

Lockbox V2 is a novel, highly experimental encryption method that prioritizes custom architecture and human-managed key material. It's NOT suitable for real-world deployment but may serve as a learning tool, cryptographic puzzle, or foundation for further research.

Lockbox V2: How to use Lockbox V2.

1. Click on the exe. A terminal interface should pop up.
2. Type in the command, LB2 to start the Lockbox V2 algorithm
3. To use the encrypt wizard, type EC. to use the decrypt wizard, type DC.
4. Follow the instructions the wizard gives you. Make sure to use a strong password
5 IMPORTANT (for encryption)
When encrypting, the wizard will show you a seed (timestamp).
Save this seed and the password securely.
Without them your file CANNOT be decrypted by anyone.