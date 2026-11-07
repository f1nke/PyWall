import json
import os
import sys
from tkinter import messagebox
import tk

def get_base_path():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CONFIG_DIR = os.path.join(get_base_path(), 'config')
CONFIG_PATH = os.path.join(CONFIG_DIR, 'rules.json')

class RuleManager:
    def __init__(self):
        self.rules = self.load_rules()

    def load_rules(self):
        if not os.path.exists(CONFIG_DIR):
            os.makedirs(CONFIG_DIR, exist_ok=True)
        if not os.path.exists(CONFIG_PATH):
            return []
        try:
            with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return []
    def save_rules(self):
        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(self.rules, f, indent=4, ensure_ascii=False)

    def add_rule(self, rule_data):
        self.rules.append(rule_data)
        self.save_rules()

    def delete_rule(self, index):
        if 0 <= index < len(self.rules):
            del self.rules[index]
            self.save_rules()

    def save_rules(self):
        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(self.rules, f, indent=4, ensure_ascii=False)

    def add_new_rule(self):
        # Получаем текст и УБИРАЕМ пробелы по краям  стритиз
        name = self.entry_name.get().strip()
        port = self.entry_port.get().strip()

        # Проверка на пустоту
        if not name or not port:
            messagebox.showerror("Ошибка", "а мне что блокировать то?!")
            return

        # Проверка, что порт - это число, если нет ты что ебло
        if not port.isdigit():
            messagebox.showerror("Ошибка", "что ты вписал,!")
            return

        new_rule = {
            "name": name,
            "port": port,
            "action": self.combo_action.get(),
            "direction": self.combo_dir.get()
        }

        self.rule_manager.add_rule(new_rule)
        self.refresh_list()

        # Очищаем поля после добавления
        self.entry_name.delete(0, tk.END)
        self.entry_port.delete(0, tk.END)

        self.status_label.config(text=f"Правило '{name}' сохранено в список. Нажмите 'Применить'.")

    def delete_rule(self, index):
        if 0 <= index < len(self.rules):
            del self.rules[index]
            self.save_rules()