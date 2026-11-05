import ctypes
import sys
import os


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def run_as_admin():
    if len(sys.argv) < 2 or sys.argv[-1] != '--admin':
        # Перезапускаем себя с правами админа
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable,
            " ".join(sys.argv) + " --admin", None, 1
        )
        sys.exit()


if __name__ == "__main__":
    if not is_admin():
        run_as_admin()

    # --- ВОТ ЭТИ СТРОКИ ТЫ ПОТЕРЯЛ ---
    import tkinter as tk
    from views import App

    root = tk.Tk()
    app = App(root)
    root.mainloop()
    # ---------------------------------