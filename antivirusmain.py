import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import hashlib
from datetime import datetime
import psutil
import subprocess
import platform
import requests

class AntivirusApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Suddhaplus Antivirus")
        self.total_scanned_files = 0
        self.threats_detected = 0
        self.label = tk.Label(root, text="Select a file to scan:")
        self.label.pack()
        self.browse_button = tk.Button(root, text="Browse", command=self.browse_file)
        self.browse_button.pack()
        self.scan_button = tk.Button(root, text="Scan File", command=self.scan_file)
        self.scan_button.pack()
        self.support_button = tk.Button(root, text="Contact Support", command=self.contact_support, font=('Arial', 12), fg='dark blue')
        self.support_button.pack(side=tk.LEFT, anchor=tk.SW)
        self.guides_button = tk.Button(root, text="User Guides", command=self.show_user_guides, font=('Arial', 12), fg='dark blue')
        self.guides_button.pack(side=tk.RIGHT, anchor=tk.SE)
        self.log_text = scrolledtext.ScrolledText(root, width=40, height=10, wrap=tk.WORD)
        self.log_text.pack()
        self.device_info_app = DeviceInfoApp(root, self)
        menu_bar = tk.Menu(root)
        root.config(menu=menu_bar)
        about_menu = tk.Menu(menu_bar, tearoff=0)
        about_menu.add_command(label="About", command=self.show_about)
        menu_bar.add_cascade(label="About", menu=about_menu)
        dashboard_menu = tk.Menu(menu_bar, tearoff=0)
        dashboard_menu.add_command(label="Dashboard", command=self.show_dashboard)
        menu_bar.add_cascade(label="Dashboard", menu=dashboard_menu)
        protection_menu = tk.Menu(menu_bar, tearoff=0)
        protection_menu.add_command(label="Quick Scan", command=self.quick_scan)
        menu_bar.add_cascade(label="Protection", menu=protection_menu)
        features_menu = tk.Menu(menu_bar, tearoff=0)
        features_menu.add_command(label="Encrypt Data", command=self.encrypt_data)
        features_menu.add_command(label="User Authentication", command=self.user_authentication)
        menu_bar.add_cascade(label="Features", menu=features_menu)

        self.selected_file_path = None

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        self.label.config(text=f"Selected File: {file_path}")
        self.selected_file_path = file_path

    def scan_file(self):
        if hasattr(self, 'selected_file_path'):
            file_path = self.selected_file_path
            try:
                file_hash = self.calculate_file_hash(file_path)
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log_message = f"{timestamp} - File: {file_path} - Hash: {file_hash}\n"
                self.total_scanned_files += 1
                self.scan_with_virustotal(file_path)
                if self.is_malicious(file_hash):
                    self.threats_detected += 1
                    messagebox.showwarning("Threat Detected", "Threat detected! File is not safe.")
                    log_message += "Threat detected! File is not safe.\n"
                else:
                    messagebox.showinfo("Clean File", "File is clean and safe.")
                    log_message += "File is clean and safe.\n"
                self.log_text.insert(tk.END, log_message)
            except Exception as e:
                messagebox.showerror("Error", f"Error scanning file: {e}")
        else:
            messagebox.showwarning("No File Selected", "Please select a file to scan.")

    def calculate_file_hash(self, file_path):
        with open(file_path, 'rb') as file:
            file_content = file.read()
            file_hash = hashlib.sha256(file_content).hexdigest()
        return file_hash

    def is_malicious(self, file_hash):
        known_malicious_hashes = ["1234567890abcdef", "abcdef1234567890"]
        return file_hash in known_malicious_hashes

    def contact_support(self):
        messagebox.showinfo("Contact Support", "Please email Praful@gmaiil.com for assistance.")

    def show_user_guides(self):
        user_guide = "User Guides:\n1. Make sure to select a file before clicking the 'Scan File' button.\n2. For any additional assistance, please contact support."
        messagebox.showinfo("User Guides", user_guide)

    def show_about(self):
        about_message = "Suddhaplus Antivirus\nVersion 1.0\nDeveloped by Praful"
        messagebox.showinfo("About", about_message)

    def show_dashboard(self):
        dashboard_message = f"Total Scanned Files: {self.total_scanned_files}\nThreats Detected: {self.threats_detected}"
        messagebox.showinfo("Dashboard", dashboard_message)

    def quick_scan(self):
        try:
            cpu_percentage = psutil.cpu_percent(interval=1)
            memory_info = psutil.virtual_memory()
            scan_result_message = f"Quick Scan Results:\nCPU Usage: {cpu_percentage}%\nAvailable RAM: {memory_info.available / (1024 ** 3):.2f} GB"
            messagebox.showinfo("Quick Scan Results", scan_result_message)
        except Exception as e:
            messagebox.showerror("Error", f"Error during quick scan: {e}")

    def encrypt_data(self):
        subprocess.Popen(["python", "features.py"])

    def user_authentication(self):
        subprocess.Popen(["python", "userauth.py"])

    def scan_with_virustotal(self, file_path):
        api_key = '21a0990f2c58b25c890582a95ff40ca2b81874aec07a110990b2b9a86e0458cd'
        api_url = 'https://www.virustotal.com/api/v3/files'
        headers = {'x-apikey': api_key}
        files = {'file': (file_path, open(file_path, 'rb'))}
        try:
            response = requests.post(api_url, headers=headers, files=files)
            response.raise_for_status()
            json_response = response.json()
            scan_results = json_response.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
            self.log_text.insert(tk.END, f"VirusTotal Scan Results:\n{scan_results}\n")
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Error scanning with VirusTotal API: {e}")

class DeviceInfoApp:
    def __init__(self, root, antivirus_app):
        self.root = root
        self.root.title("Suddha-plus Antivirus")
        self.os_info = platform.system() + " " + platform.release()
        self.processor_info = platform.processor()
        self.ram_info = str(round(psutil.virtual_memory().total / (1024 ** 3))) + " GB"
        self.os_label = tk.Label(root, text="Operating System: " + self.os_info)
        self.os_label.pack()
        self.processor_label = tk.Label(root, text="Processor: " + self.processor_info)
        self.processor_label.pack()
        self.ram_label = tk.Label(root, text="RAM: " + self.ram_info)
        self.ram_label.pack()
        self.antivirus_app = antivirus_app
        self.show_device_info()

    def get_device_info(self):
        return {
            "Operating System": self.os_info,
            "Processor": self.processor_info,
            "RAM": self.ram_info
        }

    def show_device_info(self):
        device_info = self.get_device_info()
        info_message = "\n".join([f"{key}: {value}" for key, value in device_info.items()])
        messagebox.showinfo("Suddha-plus Antivirus", info_message)

if __name__ == "__main__":
    root = tk.Tk()
    app = AntivirusApp(root)
    root.geometry("550x550")
    root.mainloop()
