import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox

from core.rules import RuleManager
from core.executor import FirewallExecutor


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
        self.root.geometry("750x550")

        try:
            icon_path = resource_path("icon.ico")
            self.icon_img = tk.PhotoImage(file=icon_path)
            self.root.iconphoto(True, self.icon_img)
        except Exception as e:
            print(f"Иконка не загружена: {e}")

        self.rule_manager = RuleManager()
        self.executor = FirewallExecutor()

        self.create_widgets()
        self.refresh_list()

    def create_widgets(self):
        frame_input = tk.LabelFrame(self.root, text="Добавить новое правило", padx=10, pady=10)
        frame_input.pack(fill="x", padx=10, pady=5)

        tk.Label(frame_input, text="Название правила:").grid(row=0, column=0, sticky="w", pady=2)
        self.entry_name = tk.Entry(frame_input, width=30)
        self.entry_name.grid(row=0, column=1, padx=5, pady=2, sticky="w")

        tk.Label(frame_input, text="Порт (например 80):").grid(row=1, column=0, sticky="w", pady=2)
        self.entry_port = tk.Entry(frame_input, width=30)
        self.entry_port.grid(row=1, column=1, padx=5, pady=2, sticky="w")

        tk.Label(frame_input, text="Действие:").grid(row=2, column=0, sticky="w", pady=2)
        self.combo_action = ttk.Combobox(frame_input, values=["block", "allow"], state="readonly", width=27)
        self.combo_action.current(0)
        self.combo_action.grid(row=2, column=1, padx=5, pady=2, sticky="w")

        tk.Label(frame_input, text="Направление:").grid(row=3, column=0, sticky="w", pady=2)
        self.combo_dir = ttk.Combobox(frame_input, values=["in", "out"], state="readonly", width=27)
        self.combo_dir.current(0)
        self.combo_dir.grid(row=3, column=1, padx=5, pady=2, sticky="w")

        btn_add = tk.Button(frame_input, text="Добавить в список", command=self.add_new_rule, bg="#e1e1e1")
        btn_add.grid(row=4, column=0, columnspan=2, pady=10, sticky="we")

        columns = ("Name", "Port", "Action", "Direction")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")
        self.tree.heading("Name", text="Название")
        self.tree.heading("Port", text="Порт")
        self.tree.heading("Action", text="Действие")
        self.tree.heading("Direction", text="Направление")
        self.tree.column("Name", width=200)
        self.tree.column("Port", width=80, anchor="center")
        self.tree.column("Action", width=100, anchor="center")
        self.tree.column("Direction", width=100, anchor="center")
        self.tree.pack(fill="both", expand=True, padx=10, pady=5)

        frame_btns = tk.Frame(self.root)
        frame_btns.pack(fill="x", padx=10, pady=10)

        btn_apply = tk.Button(frame_btns, text="✅ Применить выбранное", command=self.apply_selected, bg="#bde0fe",
                              height=2)
        btn_apply.pack(side="left", padx=5, expand=True, fill="x")

        btn_delete = tk.Button(frame_btns, text="❌ Удалить выбранное", command=self.delete_selected, bg="#ffadad",
                               height=2)
        btn_delete.pack(side="left", padx=5, expand=True, fill="x")

        self.status_label = tk.Label(self.root, text="Готово к работе", bd=1, relief="sunken", anchor="w", padx=5)
        self.status_label.pack(side="bottom", fill="x")

    def add_new_rule(self):
        name = self.entry_name.get().strip()
        port = self.entry_port.get().strip()

        if not name or not port:
            messagebox.showerror("Ошибка", "Название и порт обязательны!")
            return
        if not port.isdigit():
            messagebox.showerror("Ошибка", "Порт должен быть числом!")
            return

        new_rule = {
            "name": name,
            "port": port,
            "action": self.combo_action.get(),
            "direction": self.combo_dir.get()
        }

        self.rule_manager.add_rule(new_rule)
        self.refresh_list()
        self.entry_name.delete(0, tk.END)
        self.entry_port.delete(0, tk.END)
        self.status_label.config(text=f"Правило '{name}' сохранено.")

    def refresh_list(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        for idx, rule in enumerate(self.rule_manager.rules):
            self.tree.insert("", "end", iid=idx, values=(rule['name'], rule['port'], rule['action'], rule['direction']))

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
        else:
            messagebox.showerror("Ошибка", message)

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