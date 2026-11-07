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
                encoding='cp866'  #windows дерьма
            )

            if result.returncode == 0:
                return True, result.stdout.strip()
            else:
                error_msg = result.stderr.strip() if result.stderr else result.stdout.strip()
                return False, error_msg
        except Exception as e:
            return False, str(e)

    def apply_rule(self, rule):
        if not self.is_admin():
            return False, "Требуются права администратора!"

        name = rule.get('name', 'PyWall_Rule')
        action = 'block' if rule.get('action') == 'block' else 'allow'
        direction = 'in' if rule.get('direction') == 'in' else 'out'
        port = rule.get('port')
        ip = rule.get('ip', '')

        self.delete_rule(name)

        # базовая команда минемум
        cmd = [
            'netsh', 'advfirewall', 'firewall', 'add', 'rule',
            f'name={name}',
            f'dir={direction}',
            f'action={action}',
            'profile=any'
        ]

        # 1. если указан IP
        if ip:
            # Убираем лишние пробелы и оборачиваем весь список в кавычки
            # Если IP один, кавычки тоже не помешают
            ip_clean = ip.replace(" ", "")  # убираем все пробелы
            cmd.append(f'remoteip="{ip_clean}"')

        # 2. если указан порт
        if port:
            if direction == 'out':
                cmd.extend(['protocol=TCP', f'remoteport={port}'])
            else:
                cmd.extend(['protocol=TCP', f'localport={port}'])

        success, msg = self._run_netsh(cmd)

        return success, msg

    def delete_rule(self, rule_name):
        """Удаляет правило"""
        if not self.is_admin():
            return False, "Требуются права администратора!"

        cmd = ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}']
        return self._run_netsh(cmd)