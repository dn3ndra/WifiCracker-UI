# WiFiCrackUI

WiFiCrackUI is a Python-based GUI application for WPA/WPA2 Wi-Fi penetration testing. It provides a user-friendly interface to scan nearby wireless networks, capture handshake packets, generate targeted password wordlists, and attempt to crack the captured handshakes using Hashcat.

This tool is intended for **educational use**, **penetration testing training**, and **authorized security audits only**.

---

## 🔧 Features

- 📡 **Scan Networks**: Detects nearby Wi-Fi access points using `airodump-ng`.
- 🔑 **Wordlist Generator**: Creates custom password lists based on SSID, BSSID, common patterns, and leet variations.
- 📥 **Capture WPA/WPA2 Handshakes**: Uses `airodump-ng` and `aireplay-ng` to collect and force handshake packets.
- 🧱 **Convert Handshake to Hashcat Format**: Uses `hcxpcapngtool` to convert `.cap` files to `.22000` format.
- 🔓 **Crack Wi-Fi Passwords**: Runs `hashcat` against the captured handshake with a selected wordlist.
- 🖼️ **GUI Interface**: PyQt5 interface for easier interaction, logging, and step-by-step process control.

---

## 📦 Dependencies

Make sure your system has the following tools and libraries installed:

### 🔧 System Tools

Install via `apt` (for Debian/Kali/Ubuntu):

```bash
sudo apt update
sudo apt install aircrack-ng hashcat hcxtools net-tools wireless-tools
```

Tools used:
- `airodump-ng`, `aireplay-ng` (from `aircrack-ng`)
- `hcxpcapngtool` (from `hcxtools`)
- `hashcat`
- `iw`, `ip`, `ifconfig` (for managing interfaces)

### 🐍 Python Package

Install PyQt5:

```bash
pip install PyQt5
```

---

## ▶️ How to Run

```bash
sudo python3 wificrackUI3.py
```

**Important:** You must run it with `sudo` because:
- It changes your wireless adapter mode (monitor/managed).
- It uses raw packet capture tools (airodump-ng, aireplay-ng).

---

## 🛠️ How to Use

1. **Start the App**
   - Run with `sudo` as shown above.

2. **Select Network Interface**
   - Choose your wireless adapter (e.g., `wlan0`).

3. **Scan Networks**
   - Click **"Refresh Networks"** to detect nearby access points.

4. **Generate Wordlist (Optional)**
   - Select a network.
   - Click **"Generate Custom Wordlist"** to create a targeted `.txt` file.
   - Save the file and use it in the next step.

5. **Load Wordlist**
   - Use the file picker to select any `.txt` wordlist (custom or common).

6. **Capture & Crack**
   - Select a network and click **"Capture & Crack"**.
   - The tool will:
     - Switch to monitor mode
     - Capture WPA handshake
     - Convert to hashcat format
     - Crack it using the wordlist and display logs

---

## 📁 Default File Locations

Captured data and wordlists are saved under:

```
/home/kali/rgsecu-pentest/tesUI/
```

Make sure this directory exists or edit the `CAPTURE_DIR` variable in the script to your desired path.

---

## ⚠️ Disclaimers

- ❗ **Use Responsibly**: This tool is for legal and ethical use only.
- ⚠️ **Authorization Required**: Never use this against networks you don't own or have written permission to test.
- 🧑‍💻 **Linux-Only**: This script is built for Linux environments with compatible wireless chipsets.
- 🧪 **Educational Purpose**: Ideal for CTFs, lab testing, or coursework in cybersecurity.

---

## 📄 License



---

## 👤 Author

If you use this tool in your thesis, coursework, or training labs, feel free to reach out or contribute via pull request.

---
