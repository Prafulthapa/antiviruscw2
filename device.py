import tkinter as tk
from tkinter import messagebox
import platform
import psutil

class DeviceInfoApp:
    def __init__(self, root, antivirus_app):
        self.root = root
        self.root.title("Suddhaplus Antivirus")

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
        messagebox.showinfo("Suddhaplus Antivirus", info_message)

if __name__ == "__main__":
    root = tk.Tk()
    antivirus_app = None
    device_info_app = DeviceInfoApp(root, antivirus_app)
    root.mainloop()
