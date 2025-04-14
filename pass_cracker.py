import argparse
import hashlib
import itertools
import string
import threading
from queue import Queue
import time

# -----------------------------------------------------------
# Utility: Hash a given password string with the selected algorithm
# -----------------------------------------------------------
def hash_string(text, algorithm='md5'):
    algo = algorithm.lower()
    try:
        if algo == 'md5':
            h = hashlib.md5()
        elif algo == 'sha1':
            h = hashlib.sha1()
        elif algo == 'sha256':
            h = hashlib.sha256()
        else:
            raise ValueError("Unsupported hashing algorithm provided.")
        h.update(text.encode('utf-8'))
        return h.hexdigest()
    except Exception as e:
        print(f"[!] Hashing failed: {e}")
        return None

# -----------------------------------------------------------
# Dictionary Attack: Try each word from the wordlist
# -----------------------------------------------------------
def dictionary_attack(target_hash, algorithm, wordlist_path, found_flag):
    try:
        with open(wordlist_path, 'r', errors='ignore') as file:
            for line in file:
                if found_flag.is_set():
                    return
                password_guess = line.strip()
                if hash_string(password_guess, algorithm) == target_hash:
                    print(f"\n[+] Password found (Dictionary): {password_guess}")
                    found_flag.set()
                    return
        print("\n[-] Dictionary attack did not succeed.")
    except FileNotFoundError:
        print("[!] Provided wordlist path is invalid.")
    except Exception as e:
        print(f"[!] Error during dictionary attack: {e}")

# -----------------------------------------------------------
# Brute Force Worker: Thread worker to process guesses from queue
# -----------------------------------------------------------
def brute_force_worker(passwords_queue, target_hash, algorithm, found_flag):
    while not passwords_queue.empty() and not found_flag.is_set():
        attempt = passwords_queue.get()
        if hash_string(attempt, algorithm) == target_hash:
            print(f"\n[+] Password found (Brute-force): {attempt}")
            found_flag.set()
        passwords_queue.task_done()

# -----------------------------------------------------------
# Password Generator: Yield all character combinations
# -----------------------------------------------------------
def generate_passwords(min_len, max_len, charset):
    for length in range(min_len, max_len + 1):
        for combination in itertools.product(charset, repeat=length):
            yield ''.join(combination)

# -----------------------------------------------------------
# Core Logic: Launches dictionary or brute-force attack based on input
# -----------------------------------------------------------
def password_cracker(args):
    target_hash = args.hash
    algorithm = args.algorithm.lower()
    wordlist = args.wordlist
    min_len = args.min
    max_len = args.max
    thread_count = args.threads

    print("[*] Initiating password cracking tool")
    print(f"[*] Target hash      : {target_hash}")
    print(f"[*] Algorithm chosen : {algorithm.upper()}")
    print(f"[*] Threads in use   : {thread_count}\n")

    start_time = time.time()
    found_flag = threading.Event()

    if wordlist:
        print("[*] Using dictionary attack strategy...")
        dictionary_attack(target_hash, algorithm, wordlist, found_flag)
    else:
        print("[*] Starting brute-force strategy...")
        characters = string.ascii_letters + string.digits
        passwords_queue = Queue()

        print("[*] Generating password combinations...")
        for pwd in generate_passwords(min_len, max_len, characters):
            passwords_queue.put(pwd)

        print(f"[*] Total combinations queued: {passwords_queue.qsize()}")

        threads = []
        for _ in range(thread_count):
            thread = threading.Thread(target=brute_force_worker,
                                      args=(passwords_queue, target_hash, algorithm, found_flag))
            thread.start()
            threads.append(thread)

        for t in threads:
            t.join()

        if not found_flag.is_set():
            print("\n[-] Brute-force attempt failed to find the password.")

    duration = round(time.time() - start_time, 2)
    print(f"\n[✓] Process completed in {duration} seconds")

# -----------------------------------------------------------
# Entry Point: Handle user input from command line
# -----------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="🔐 Password Cracker using Python\n\n"
                    "Crack a given hashed password using dictionary or brute-force techniques.\n"
                    "Supports MD5, SHA1, and SHA256 hashing algorithms.\n",
        epilog="""
Examples:

  Dictionary attack (using a wordlist):
    python cracker.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --algorithm md5 --wordlist rockyou.txt

  Brute-force attack (auto-generating passwords):
    python cracker.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --algorithm md5 --min 1 --max 4 --threads 8

Notes:
- The above hash is for the password 'password' using MD5.
- Wordlist files like rockyou.txt can be found on Kali Linux or online repositories.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('--hash', required=True, help="Target hash value to crack (e.g., MD5/SHA1/SHA256 hash)")
    parser.add_argument('--algorithm', required=True, choices=['md5', 'sha1', 'sha256'],
                        help="Hashing algorithm used to generate the hash (md5, sha1, sha256)")
    parser.add_argument('--wordlist', help="Path to wordlist file for dictionary attack (optional)")
    parser.add_argument('--min', type=int, default=1, help="Minimum length of passwords for brute-force attack")
    parser.add_argument('--max', type=int, default=4, help="Maximum length of passwords for brute-force attack")
    parser.add_argument('--threads', type=int, default=4, help="Number of threads to use (default = 4)")

    args = parser.parse_args()
    password_cracker(args)


if __name__ == '__main__':
    main()
