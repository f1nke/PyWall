import subprocess
import ctypes
import os


class FirewallExecutor:
    @staticmethod
    def is_admin():
        """Проверка прав администратора"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False

    def _run_netsh(self, cmd_list):
        """Вспомогательный метод для запуска netsh без окна консоли"""
        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            result = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                startupinfo=startupinfo,
                encoding='cp866'  # Важно для русской Windows, иначе будут крокозябры
            )

            # В Windows netsh возвращает 0 при успехе
            if result.returncode == 0:
                return True, result.stdout.strip()
            else:
                # Иногда netsh пишет ошибки в stdout, а не stderr
                error_msg = result.stderr.strip() if result.stderr else result.stdout.strip()
                return False, error_msg
        except Exception as e:
            return False, str(e)

    def apply_rule(self, rule):
        """Применяет правило"""
        if not self.is_admin():
            return False, "Требуются права администратора!"

        name = rule.get('name', 'PyWall_Rule')
        action = 'block' if rule.get('action') == 'block' else 'allow'
        direction = 'in' if rule.get('direction') == 'in' else 'out'
        port = rule.get('port')

        # Сначала удаляем старое правило с таким же именем (чтобы не было дублей)
        self.delete_rule(name)

        cmd = [
            'netsh', 'advfirewall', 'firewall', 'add', 'rule',
            f'name={name}',
            f'dir={direction}',
            f'action={action}',
            'protocol=TCP',
            f'localport={port}'
        ]

        return self._run_netsh(cmd)

    def delete_rule(self, rule_name):
        """Удаляет правило"""
        if not self.is_admin():
            return False, "Требуются права администратора!"

        cmd = ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}']
        return self._run_netsh(cmd)