# logger.py
import datetime
from colorama import Fore, Style, init

init(autoreset=True)

class AlertLogger:
    def __init__(self, log_file="ids_alerts.log"):
        self.log_file = log_file
        self.alert_count = 0
    
    def alert(self, level, attack_type, src_ip, details, reason=None):
        #print function alert and then save in file
        self.alert_count += 1
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
       #Show color according to level
        if level == "HIGH":
            color = Fore.RED
        elif level == "MEDIUM":
            color = Fore.YELLOW
        else:
            color = Fore.CYAN
        
        #Print in terminal
        msg = f"[{timestamp}] [{level}] {attack_type} | SRC: {src_ip} | {details}"
        if reason:
          msg += f" | Reason: {reason}"

        print(color + "🚨 ALERT #" + str(self.alert_count) + " — " + msg)
        
        # Save in file
        with open(self.log_file, "a") as f:
            f.write(msg + "\n")
    
    def info(self, message):
        print(Fore.BLUE + f"[INFO] {message}")


    #    python "C:\Users\dolik\OneDrive\Documents\Desktop\Intrusion Detection System\ids.py"