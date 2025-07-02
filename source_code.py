from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type
from colorama import Fore
from datetime import datetime
import os
print(Fore.LIGHTGREEN_EX + "")
print("░▒▓█▓▒░      ░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░ ")
print("░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ")
print("░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ")
print("░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓███████▓▒░░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░  ")
print("░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ")
print("░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ")
print("░▒▓████████▓▒░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░")
print("Version: 2.0")
print("============================================================================================")
print("Welcome to LOCKBOX. Type help to see a list of commands. Or execute your own commands here.")
while True:
    command = input("LB>")
    def derive_key(password: str, salt: bytes) -> bytes:
        return hash_secret_raw(
            secret=password.encode(),
            salt=salt,
            time_cost=4,
            memory_cost=2**16,  # 64 MB
            parallelism=2,
            hash_len=32,
            type=Type.I
        )

    def encrypt_file(filepath: str, password: str):
        with open(filepath, 'rb') as f:
            data = f.read()

        salt = os.urandom(16)
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        encrypted = aesgcm.encrypt(nonce, data, None)

        with open(filepath + ".lockbox", 'wb') as f:
            f.write(salt + nonce + encrypted)

        print("Encrypted:", filepath + ".lockbox")

    def decrypt_file(filepath: str, password: str):
        with open(filepath, 'rb') as f:
            raw = f.read()

        salt = raw[:16]
        nonce = raw[16:28]
        encrypted = raw[28:]
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)

        try:
            decrypted = aesgcm.decrypt(nonce, encrypted, None)
            out_path = filepath.replace(".lockbox", ".decrypted")
            with open(out_path, 'wb') as f:
                f.write(decrypted)
            print("Decrypted:", out_path)
        except Exception as e:
            print("Decryption failed:", str(e))

    if command == "help":
        print("Commands: ")
        print("help or h to get to help menu")
        print("LB: Lists all versions of lockbox encryption.")
        print("LB1: Executes Lockbox V1 encryption. It's stable and easy to use. But vulnerable to advanced attacks. Currently Broken.")
        print("LB2: Executes Lockbox V2. Is nearly impossible to crack. Don't lose the key!")

    elif command == "LB1":
        print("Would you like to encrypt or decrypt a file? 1: Encrypt 2: Decrypt")
        enorde = int(input("LB1>"))
        if enorde == 1:
            filename = input("Type the exact path of the file you would like to encrypt.")
            password = input("Put in passcode for the file")
            encrypt_file(filename, password)

    elif command == "LB2":
        def lock_key(password: str, salt: str, rounds: int = 10000, key_len: int = 32) -> bytes:
            base = (password + salt).encode()
            for i in range(rounds):
                b = bytearray(base)
                for j in range(len(b)):
                    b[j] = (b[j] ^ (j * 31 + i)) & 0xFF
                    b[j] = ((b[j] << (i % 7 + 1)) | (b[j] >> (8 - (i % 7 + 1)))) & 0xFF
                base = bytes(b[::-1])  # reverse
            return base[:key_len].ljust(key_len, b'\x00')
        def custom_scramble(chunk: bytes, key: bytes, index: int) -> bytes:
            out = bytearray(chunk)
            for i in range(len(out)):
                out[i] = ((out[i] + key[i % len(key)] + index) ^ ((i * 19) % 251)) & 0xFF
                if i % 3 == 0:
                    out[i] = (out[i] << 1 | out[i] >> 7) & 0xFF
            if index % 2 == 1:
                out.reverse()
            return bytes(out)

        def custom_unscramble(chunk: bytes, key: bytes, index: int) -> bytes:
            out = bytearray(chunk)
            if index % 2 == 1:
                out.reverse()
            for i in range(len(out)):
                if i % 3 == 0:
                    out[i] = (out[i] >> 1 | out[i] << 7) & 0xFF
                out[i] = ((out[i] ^ ((i * 19) % 251)) - key[i % len(key)] - index) & 0xFF
            return bytes(out)

        def lockbox_q1_encrypt(data: bytes, password: str) -> tuple[bytes, str]:
            dt = datetime.now().strftime("%Y%m%d%H%M%S")
            print(f"[LOCKBOX-Q1] Encrypting with seed: {dt}")
            chunk_size = 64
            encrypted = bytearray()

            for i in range(0, len(data), chunk_size):
                chunk = data[i:i+chunk_size]
                key = lock_key(password, dt + str(i))
                encrypted.extend(custom_scramble(chunk, key, i // chunk_size))

            return bytes(encrypted), dt

        def lockbox_q1_decrypt(data: bytes, password: str, dt: str) -> bytes:
            chunk_size = 64
            decrypted = bytearray()

            for i in range(0, len(data), chunk_size):
                chunk = data[i:i+chunk_size]
                key = lock_key(password, dt + str(i))
                decrypted.extend(custom_unscramble(chunk, key, i // chunk_size))

            return bytes(decrypted)
    
        def write_lockbox_file(output_path: str, encrypted_data: bytes, timestamp: str):
            with open(output_path, 'wb') as f:
                f.write(b'lockbox')  # magic header
                f.write(encrypted_data)

        def read_lockbox_file(input_path: str) -> bytes:
            with open(input_path, 'rb') as f:
                header = f.read(7)
                if header != b'lockbox':
                    raise ValueError("Not a valid LOCKBOX file.")
                encrypted_data = f.read()
            return encrypted_data

    
        print("Welcome to LOCKBOX V2.")
        while True:
            commandV2 = input("LB2> ")
            if commandV2 == "help":
                print("EC: Encrypt using Lockbox V2 architecture")
                print("DC: Decrypts using Lockbox V2 architecture")
            elif commandV2 == "EC":
                print("Lockbox V2 Encryption Wizard")
                print("Please provide the full path to the file including the file name and extension")
                filenameV2 = input("LB2> ")
                print("Please provide a password for later decryption")
                passwordV2 = input("LB2> ")
                def encryptV2(filenameV2, passwordV2):
                    with open(filenameV2, "rb") as f:
                        encrypted, timestamp = lockbox_q1_encrypt(f.read(), passwordV2)
                    write_lockbox_file(filenameV2 + ".lockboxV2", encrypted, timestamp)
                encryptV2(filenameV2, passwordV2)
                print("Make sure to save the timestamp, and password of your lockbox file.")
            elif commandV2 == "DC":
                print("Lockbox V2 Decryption Wizard")
                print("Please provide the password for the file you encrypted")
                passwordV2 = input("LB2> ")
                print("Please put in the file path of the LOCKBOX file")
                filenameV2 = input("LB2> ")
                print("Please put in the seed that you used to create this file.")
                timestamp = input("LB2>")
                print("Please put in the file extension you would like to decrypt to. ex. txt, py, etc.")
                desired_extension = input("LB2> ")
                def decryptV2(filenameV2, passwordV2, timestamp, desired_extension):
                    data = read_lockbox_file(filenameV2)
                    decrypted_data = lockbox_q1_decrypt(data, passwordV2, timestamp)

                    output_file = filenameV2.replace(".lockboxV2", f".{desired_extension}")
                    with open(output_file, "wb") as f:
                        f.write(decrypted_data)

                    print(f"[LOCKBOX] Decrypted file saved to: {output_file}")

                decryptV2(filenameV2, passwordV2, timestamp, desired_extension)