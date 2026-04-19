import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import threading
from ids import IDS

class IDS_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Intrusion Detection System Dashboard")
        self.root.geometry("900x600")
        self.root.configure(bg="#f4f6f9")  # light background

        self.ids = IDS()
        self.ids_thread = None

        
        title = tk.Label(root, text="🛡️ Intrusion Detection System",
                         font=("Arial", 18, "bold"),
                         fg="#2c3e50", bg="#f4f6f9")
        title.pack(pady=10)

        
        btn_frame = tk.Frame(root, bg="#f4f6f9")
        btn_frame.pack()

        self.start_btn = tk.Button(btn_frame, text="Start IDS",
                                  bg="#ffffff", fg="#28a745",
                                  activebackground="#d4edda",
                                  font=("Arial", 11, "bold"),
                                  width=15, command=self.start_ids)
        self.start_btn.grid(row=0, column=0, padx=10)

        self.stop_btn = tk.Button(btn_frame, text="Stop IDS",
                                 bg="#ffffff", fg="#dc3545",
                                 activebackground="#f8d7da",
                                 font=("Arial", 11, "bold"),
                                 width=15, command=self.stop_ids)
        self.stop_btn.grid(row=0, column=1, padx=10)

        
        stats_frame = tk.Frame(root, bg="#ffffff", bd=1, relief="solid")
        stats_frame.pack(pady=10, padx=20, fill="x")

        self.packet_label = tk.Label(stats_frame, text="Packets: 0",
                                     fg="#007bff", bg="#ffffff",
                                     font=("Arial", 11))
        self.packet_label.grid(row=0, column=0, padx=20, pady=5)

        self.alert_label = tk.Label(stats_frame, text="Alerts: 0",
                                    fg="#fd7e14", bg="#ffffff",
                                    font=("Arial", 11))
        self.alert_label.grid(row=0, column=1, padx=20, pady=5)

        
        self.output = ScrolledText(root, height=20, width=100,
                                  bg="#ffffff", fg="#2c3e50",
                                  insertbackground="black")
        self.output.pack(pady=10, padx=20)

        # Color tags for alerts
        self.output.tag_config("HIGH", foreground="red")
        self.output.tag_config("MEDIUM", foreground="orange")
        self.output.tag_config("LOW", foreground="blue")

        # Redirect logger
        self.ids.logger.info = self.log
        self.ids.logger.alert = self.alert

        # Auto update stats
        self.update_stats()

    def log(self, message):
        self.output.insert(tk.END, "[INFO] " + message + "\n")
        self.output.see(tk.END)

    def alert(self, level, attack_type, src_ip, details, reason=None):
        msg = f"[{level}] {attack_type} | {src_ip} | {details}"
        if reason:
            msg += f" | {reason}"

        self.output.insert(tk.END, "🚨 " + msg + "\n", level)
        self.output.see(tk.END)

    def start_ids(self):
        if not self.ids.running:
            self.ids_thread = threading.Thread(target=self.ids.start, daemon=True)
            self.ids_thread.start()
            self.log("IDS Started")

    def stop_ids(self):
        self.ids.running = False
        self.log("IDS Stopped")

    def update_stats(self):
        self.packet_label.config(text=f"Packets: {self.ids.packet_count}")
        self.alert_label.config(text=f"Alerts: {self.ids.logger.alert_count}")
        self.root.after(1000, self.update_stats)


# Run GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = IDS_GUI(root)
    root.mainloop()