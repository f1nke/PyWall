import os
import threading
import time
import sys
import ctypes
import logging
from collections import Counter
from scapy.all import sniff, send
from scapy.layers.inet import IP, TCP

if not os.path.exists("logs"):
    os.makedirs("logs")

# Настраиваем логирование
logging.basicConfig(
    filename='logs/app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def run_as_admin():
    if not is_admin():
        # только с root
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable,
            " ".join(sys.argv) + " --admin", None, 1
        )
        sys.exit()


class PyWallEngine(threading.Thread):
    def __init__(self, rule_manager, app_gui=None):
        super().__init__()
        self.rule_manager = rule_manager
        self.app_gui = app_gui
        self.running = True
        self.daemon = True

        self.total_packets = 0
        self.dst_ips = Counter()

    def run(self):
        logging.info("[*] PyWall Engine запущен. Слушаем трафик...")
        threading.Thread(target=self.update_gui_loop, daemon=True).start()
        sniff(prn=self.process_packet, store=0, filter="tcp")

    def process_packet(self, packet):
        if not self.running:
            return

        if IP in packet:
            self.total_packets += 1
            dst_ip = packet[IP].dst
            self.dst_ips[dst_ip] += 1

            if TCP in packet:
                src_ip = packet[IP].src
                for rule in self.rule_manager.rules:
                    if rule.get('action') == 'block':
                        blocked_ip = rule.get('ip')
                        if blocked_ip and (dst_ip == blocked_ip or src_ip == blocked_ip):
                            rst_packet = IP(src=dst_ip, dst=src_ip) / TCP(
                                sport=packet[TCP].dport,
                                dport=packet[TCP].sport,
                                flags="R",
                                seq=packet[TCP].ack
                            )
                            send(rst_packet, verbose=0)
                            logging.warning(f"[!] Scapy: разорвано соединение с {blocked_ip}")

    def update_gui_loop(self):
            """Обновляем интерфейс раз в секунду, а лог топ-3 пишем раз в 30 секунд"""
            last_log_time = time.time()  # запоминаем время последней записи

            while self.running:
                time.sleep(1)
                if self.app_gui:
                    # Берем топ-3 IP
                    top_ips = self.dst_ips.most_common(3)
                    top_ip_str = ", ".join([f"{ip[0]} ({ip[1]})" for ip in top_ips]) if top_ips else "Нет данных"

                    self.app_gui.root.after(0, lambda: self.app_gui.lbl_total_packets.config(
                        text=f"Всего пакетов: {self.total_packets}"
                    ))
                    self.app_gui.root.after(0, lambda: self.app_gui.lbl_top_ip.config(
                        text=f"Топ IP: {top_ip_str}"
                    ))

                    # ЛОГИРОВАНИЕ ТОП-3 РАЗ В 10 СЕКУНД тестим похуй
                    current_time = time.time()
                    if current_time - last_log_time >= 10 and top_ips:
                        logging.info(f"=== Анализ трафика (всего пакетов: {self.total_packets}) ===")
                        for idx, (ip, count) in enumerate(top_ips, 1):
                            logging.info(f"  #{idx}: {ip} — {count} пакетов")

                        last_log_time = current_time  # Сбрасываем таймер


if __name__ == "__main__":
    # админка
    run_as_admin()

    import tkinter as tk
    from views import App

    #app
    root = tk.Tk()
    app = App(root)

    #gui ебать
    engine = PyWallEngine(app.rule_manager, app_gui=app)
    engine.start()

    #запуск нхуй я это все пишу да пох
    root.mainloop()