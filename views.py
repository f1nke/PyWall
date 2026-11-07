import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox
import socket
from core.rules import RuleManager
from core.executor import FirewallExecutor
import logging

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("PyWall - Simple Windows Firewall Manager")
        self.root.geometry("850x650")

        #  НАСТРОЙКА ЦВЕТОВ (черная)
        self.bg_color = "#1e1e1e"  # Темно-серый фон
        self.fg_color = "#ffffff"  # Белый текст
        self.entry_bg = "#2d2d2d"  # Фон полей ввода
        self.btn_bg = "#3c3c3c"  # Фон кнопок

        self.root.configure(bg=self.bg_color)  # Красим главное окно

        #
        self.rule_manager = RuleManager()
        self.executor = FirewallExecutor()

        self.create_widgets()
        self.refresh_list()
        # нам нахуй этот фон не нужон

    def create_widgets(self):
        # что то там со стилями
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
                        background=self.entry_bg,
                        foreground=self.fg_color,
                        fieldbackground=self.entry_bg,
                        rowheight=25)
        style.configure("Treeview.Heading",
                        background=self.btn_bg,
                        foreground=self.fg_color,
                        font=("Arial", 10, "bold"))
        style.map("Treeview", background=[('selected', '#0078D7')])  # Цвет выдилений

        # Рамка ввода)
        frame_input = tk.LabelFrame(self.root, text="Добавить новое правило",
                                    bg=self.bg_color, fg=self.fg_color, padx=10, pady=10)
        frame_input.pack(fill="x", padx=10, pady=5)

        # 1. Название
        tk.Label(frame_input, text="Название правила:", bg=self.bg_color, fg=self.fg_color).grid(row=0, column=0,
                                                                                                 sticky="w", pady=2)
        self.entry_name = tk.Entry(frame_input, width=30, bg=self.entry_bg, fg=self.fg_color, insertbackground="white")
        self.entry_name.grid(row=0, column=1, padx=5, pady=2, sticky="w")

        # 2. Порт
        tk.Label(frame_input, text="Порт (например 80):", bg=self.bg_color, fg=self.fg_color).grid(row=1, column=0,
                                                                                                   sticky="w", pady=2)
        self.entry_port = tk.Entry(frame_input, width=30, bg=self.entry_bg, fg=self.fg_color, insertbackground="white")
        self.entry_port.grid(row=1, column=1, padx=5, pady=2, sticky="w")

        # 3. Действие
        tk.Label(frame_input, text="Действие:", bg=self.bg_color, fg=self.fg_color).grid(row=2, column=0, sticky="w",
                                                                                         pady=2)
        self.combo_action = ttk.Combobox(frame_input, values=["block", "allow"], state="readonly", width=27)
        self.combo_action.current(0)
        self.combo_action.grid(row=2, column=1, padx=5, pady=2, sticky="w")

        # 4. Направление
        tk.Label(frame_input, text="Направление:", bg=self.bg_color, fg=self.fg_color).grid(row=3, column=0, sticky="w",
                                                                                            pady=2)
        self.combo_dir = ttk.Combobox(frame_input, values=["in", "out"], state="readonly", width=27)
        self.combo_dir.current(1)
        self.combo_dir.grid(row=3, column=1, padx=5, pady=2, sticky="w")

        # 5. IP-адрес
        tk.Label(frame_input, text="IP-адрес (IPv4):", bg=self.bg_color, fg=self.fg_color).grid(row=4, column=0, sticky="w", pady=2)
        self.entry_ip = tk.Entry(frame_input, width=30, bg=self.entry_bg, fg=self.fg_color, insertbackground="white")
        self.entry_ip.grid(row=4, column=1, padx=5, pady=2, sticky="w")

        #Домен
        tk.Label(frame_input, text="Домен (напр. github.com):", bg=self.bg_color, fg=self.fg_color).grid(row=5, column=0, sticky="w", pady=2)
        self.entry_domain = tk.Entry(frame_input, width=30, bg=self.entry_bg, fg=self.fg_color, insertbackground="white")
        self.entry_domain.grid(row=5, column=1, padx=5, pady=2, sticky="w")

        # 6. Кнопка добавить
        btn_add = tk.Button(frame_input, text="Добавить в список", command=self.add_new_rule,
                            bg=self.btn_bg, fg=self.fg_color, activebackground="#555555")
        btn_add.grid(row=6, column=0, columnspan=2, pady=10, sticky="we")

        # Таблица
        columns = ("Name", "Port_ip", "Action", "Direction")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")
        self.tree.heading("Name", text="Название")
        self.tree.heading("Port_ip", text="Порт/IPv4")
        self.tree.heading("Action", text="Действие")
        self.tree.heading("Direction", text="Направление")

        self.tree.column("Name", width=200)
        self.tree.column("Port_ip", width=150, anchor="center")
        self.tree.column("Action", width=100, anchor="center")
        self.tree.column("Direction", width=100, anchor="center")
        self.tree.pack(fill="both", expand=True, padx=10, pady=5)

        # стата
        frame_stats = tk.LabelFrame(self.root, text="Анализ трафика", bg=self.bg_color, fg=self.fg_color, padx=10,
                                    pady=5)
        frame_stats.pack(fill="x", padx=10, pady=5)

        self.lbl_total_packets = tk.Label(frame_stats, text="Всего пакетов: 0", font=("Arial", 10, "bold"),
                                          bg=self.bg_color, fg="#4CAF50")
        self.lbl_total_packets.pack(side="left", padx=10)

        self.lbl_top_ip = tk.Label(frame_stats, text="Топ IP: Нет данных", font=("Arial", 10), bg=self.bg_color, fg="#2196F3", cursor="hand2")
        self.lbl_top_ip.pack(side="left", padx=10)
        # клик
        self.lbl_top_ip.bind("<Button-1>", self.on_ip_click)

        # кнопочки
        frame_btns = tk.Frame(self.root, bg=self.bg_color)
        frame_btns.pack(fill="x", padx=10, pady=10)

        btn_apply = tk.Button(frame_btns, text="✅ Применить выбранное", command=self.apply_selected,
                              bg="#4CAF50", fg="white", activebackground="#45a049", height=2)
        btn_apply.pack(side="left", padx=5, expand=True, fill="x")

        btn_delete = tk.Button(frame_btns, text="❌ Удалить выбранное", command=self.delete_selected,
                               bg="#F44336", fg="white", activebackground="#da190b", height=2)
        btn_delete.pack(side="left", padx=5, expand=True, fill="x")

        self.status_label = tk.Label(self.root, text="Готово к работе", bd=1, relief="sunken",
                                     anchor="w", padx=5, bg=self.entry_bg, fg=self.fg_color)
        self.status_label.pack(side="bottom", fill="x")

        # КНОПКА ЛОГОВ
        btn_logs = tk.Button(frame_btns, text="📜 Посмотреть логи", command=self.show_logs,
                             bg="#2196F3", fg="white", activebackground="#0b7dda", height=2)
        btn_logs.pack(side="left", padx=5, expand=True, fill="x")

    def on_ip_click(self, event):
        # Берем текст из нашешего музыкального продакшена (он в формате "Топ IP: 192.168.1.1 (50)")
        text = self.lbl_top_ip.cget("text")
        if "Топ IP: " in text and "Нет данных" not in text:
            ip_part = text.split("Топ IP: ")[1].split(",")[0].split(" ")[0]
            # Вставляем в поле ввода IP
            self.entry_ip.delete(0, tk.END)
            self.entry_ip.insert(0, ip_part)
            self.status_label.config(text=f"IP {ip_part} скопирован в поле ввода.")

    # логика
    def add_new_rule(self):
        name = self.entry_name.get().strip()
        port = self.entry_port.get().strip()
        ip = self.entry_ip.get().strip()
        domain = self.entry_domain.get().strip()

        if not name:
            messagebox.showerror("Ошибка", "Название обязательно!")
            return

        #лочик для доменав
        if domain and not ip:
            domain_lower = domain.lower()

            # 1. Умная блокировка для гигантов (у которых куча IP)
            if "github" in domain_lower:
                ip = "140.82.112.0/20"
            elif "youtube" in domain_lower or "google" in domain_lower:
                ip = "142.250.0.0/16, 172.217.0.0/16, 216.58.0.0/16"
            elif "cloudflare" in domain_lower:
                ip = "104.16.0.0/13, 172.64.0.0/13"
            else:
                # ДЛЯ ЛЮБОГО ДРУГОГО САЙТА: собираем все IP
                try:
                    addr_info = socket.getaddrinfo(domain, None)
                    ips = set()
                    for item in addr_info:
                        ip_addr = item[4][0]
                        if "." in ip_addr:  # Только IPv4
                            ips.add(ip_addr)

                    if not ips:
                        messagebox.showerror("Ошибка", f"Не найдено IPv4 для {domain}")
                        return

                    # Берем все найденные IP.
                    # Если их больше 10, берем первые 10 что бы унас система не отъебнула так как у вас там печка, я что емеля я еду на печке
                    ip_list = list(ips)
                    if len(ip_list) > 10:
                        ip_list = ip_list[:10]

                    ip = ",".join(ip_list)

                except socket.gaierror:
                    messagebox.showerror("Ошибка", f"Не удалось найти IP для домена {domain}")
                    return

        if not port and not ip:
            messagebox.showerror("Ошибка", "Введите порт, IP или домен!")
            return

        new_rule = {
            "name": name,
            "port": port,
            "ip": ip,
            "action": self.combo_action.get(),
            "direction": self.combo_dir.get()
        }

        self.rule_manager.add_rule(new_rule)
        self.refresh_list()

        #чистим вилкой поля
        self.entry_name.delete(0, tk.END)
        self.entry_port.delete(0, tk.END)
        self.entry_ip.delete(0, tk.END)
        self.entry_domain.delete(0, tk.END)

        self.status_label.config(text=f"Правило '{name}' сохранено. Нажмите 'Применить'!")

    def refresh_list(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        for idx, rule in enumerate(self.rule_manager.rules):
            if rule.get('port') and rule.get('ip'):
                port_or_ip = f"{rule['port']} / {rule['ip']}"
            elif rule.get('port'):
                port_or_ip = rule['port']
            elif rule.get('ip'):
                port_or_ip = rule['ip']
            else:
                port_or_ip = "Любой"
            self.tree.insert("", "end", iid=idx, values=(rule['name'], port_or_ip, rule['action'], rule['direction']))

    def apply_selected(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Внимание", "Выберите правило!")
            return
        idx = int(selected[0])
        rule = self.rule_manager.rules[idx]
        success, message = self.executor.apply_rule(rule)
        if success:
            self.status_label.config(text=f"УСПЕХ: Правило '{rule['name']}' применено.")
            logging.info(
                f"Пользователь применил правило: {rule['name']} (IP: {rule.get('ip')}, Порт: {rule.get('port')})")
        else:
            messagebox.showerror("Ошибка", message)
            logging.error(f"Ошибка применения правила {rule['name']}: {message}")

    def delete_selected(self):
        selected = self.tree.selection()
        if not selected:
            return
        idx = int(selected[0])
        rule = self.rule_manager.rules[idx]
        self.executor.delete_rule(rule['name'])
        self.rule_manager.delete_rule(idx)
        self.refresh_list()
        self.status_label.config(text=f"Правило '{rule['name']}' удалено.")

    def show_logs(self):
        # 1. создаем новое окно
        log_window = tk.Toplevel(self.root)
        log_window.title("Логи работы PyWall (Live)")
        log_window.geometry("750x500")
        log_window.configure(bg=self.bg_color)

        # 2. текстовое поле с прокруткой
        scrollbar = tk.Scrollbar(log_window)
        scrollbar.pack(side="right", fill="y")

        text_area = tk.Text(log_window, yscrollcommand=scrollbar.set,
                            bg=self.entry_bg, fg=self.fg_color,
                            font=("Consolas", 10), wrap="word")
        text_area.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        scrollbar.config(command=text_area.yview)

        log_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "app.log")

        # переменная для хранения текущей позиции чтения
        self.log_last_pos = 0

        # функция для чтения новых строк
        def update_logs():
            if not log_window.winfo_exists():  # если окно закрыли то мы останваливаемся наконецто
                return

            try:
                if os.path.exists(log_file_path):
                    with open(log_file_path, "r", encoding="utf-8") as f:
                        # перемещаемся туда,куда то похуй
                        f.seek(self.log_last_pos)
                        new_data = f.read()

                        if new_data:
                            # запоминаем,
                            is_at_bottom = text_area.yview()[1] > 0.99

                            text_area.config(state="normal")  # разрешаем запись
                            text_area.insert(tk.END, new_data)
                            text_area.config(state="disabled")  # запрещаем редактирование

                            # обновляем позицию
                            self.log_last_pos = f.tell()

                            # если пользователь был внизу а сука
                            if is_at_bottom:
                                text_area.see(tk.END)
            except Exception as e:
                pass  # игнорируем ошибки нахуй

            # планируем следующий запуск на уничтожение система черз 1(1000)
            log_window.after(1000, update_logs)
        #запускаем
        update_logs()