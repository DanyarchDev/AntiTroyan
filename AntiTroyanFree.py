import os
import shutil
import hashlib
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import psutil
import requests
from datetime import datetime

# Конфигурация (с вашим API-ключом)
CONFIG = {
    "VIRUSTOTAL_API_KEY": "89c0ee11d8fcbcea21f3780f5cce8a1e13862ef85fc6c116ac767582d237fa7a",
    "QUARANTINE_FOLDER": "AT_Free_Quarantine",
    "LOG_FILE": "at_free_log.txt",
    "MAX_SCAN_FILES": 5000  # Лимит для Free-версуии
}

class AntiTroyanFree:
    def __init__(self):
        self.setup_dirs()
        self.known_malware = self.load_malware_db()
        self.running = False

    def setup_dirs(self):
        """Создаёт необходимые папки"""
        try:
            os.makedirs(CONFIG["QUARANTINE_FOLDER"], exist_ok=True)
        except Exception as e:
            self.log_error(f"Ошибка создания папки: {e}")

    def load_malware_db(self):
        """Загружает базу сигнатур"""
        return {
            "d41d8cd98f00b204e9800998ecf8427e": "TestVirus.exe",
            "a94a8fe5ccb19ba61c4c0873d391e987": "Backdoor.Win32"
        }

    def fast_scan(self, path="C:\\"):
        """Быстрое сканирование диска"""
        found = []
        scanned = 0
        
        for root, _, files in os.walk(path):
            for file in files:
                if scanned >= CONFIG["MAX_SCAN_FILES"]:
                    break
                    
                file_path = os.path.join(root, file)
                if self.check_file(file_path):
                    found.append(file_path)
                scanned += 1
                
        return found

    def check_file(self, file_path):
        """Проверяет файл на угрозы"""
        try:
            if not os.path.exists(file_path):
                return False

            # Проверка по сигнатурам
            file_hash = self.get_file_hash(file_path)
            if file_hash in self.known_malware:
                return True

            # Проверка через VirusTotal (если API ключ есть)
            if CONFIG["VIRUSTOTAL_API_KEY"]:
                vt_result = self.check_virustotal(file_hash)
                if vt_result and vt_result.get('malicious', 0) > 0:
                    return True

            # Простая эвристика
            ext = os.path.splitext(file_path)[1].lower()
            if ext in ('.exe', '.bat', '.vbs', '.ps1'):
                file_size = os.path.getsize(file_path)
                if file_size > 50 * 1024 * 1024:  # >50MB = подозрительно
                    return True

            return False
        except Exception as e:
            self.log_error(f"Ошибка проверки файла {file_path}: {e}")
            return False

    def get_file_hash(self, file_path):
        """Вычисляет MD5 хеш файла"""
        try:
            with open(file_path, "rb") as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception as e:
            self.log_error(f"Ошибка хеширования {file_path}: {e}")
            return ""

    def check_virustotal(self, file_hash):
        """Проверяет файл через VirusTotal API"""
        if not file_hash or not CONFIG["VIRUSTOTAL_API_KEY"]:
            return None

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": CONFIG["VIRUSTOTAL_API_KEY"]}

        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                return response.json().get('data', {}).get('attributes', {})
        except Exception as e:
            self.log_error(f"VirusTotal error: {e}")
        return None

    def quarantine_file(self, file_path):
        """Перемещает файл в карантин"""
        try:
            if not os.path.exists(file_path):
                return False

            filename = os.path.basename(file_path)
            quarantine_path = os.path.join(CONFIG["QUARANTINE_FOLDER"], filename)
            
            # Убедимся, что файл не перезаписывается
            counter = 1
            while os.path.exists(quarantine_path):
                name, ext = os.path.splitext(filename)
                quarantine_path = os.path.join(
                    CONFIG["QUARANTINE_FOLDER"], 
                    f"{name}_{counter}{ext}"
                )
                counter += 1

            shutil.move(file_path, quarantine_path)
            return True
        except Exception as e:
            self.log_error(f"Ошибка карантина: {e}")
            return False

    def log_error(self, message):
        """Логирует ошибки"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CONFIG["LOG_FILE"], "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] ERROR: {message}\n")

class FreeUI:
    def __init__(self, root):
        self.root = root
        self.core = AntiTroyanFree()
        self.setup_ui()

    def setup_ui(self):
        """Настраивает интерфейс"""
        self.root.title("AntiTroyan Free")
        self.root.geometry("900x650")
        
        # Стиль
        style = ttk.Style()
        style.configure("TFrame", background="#f0f0f0")
        style.configure("TButton", padding=6, font=('Arial', 10))

        # Основные элементы
        frame = ttk.Frame(self.root)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Панель управления
        control_frame = ttk.Frame(frame)
        control_frame.pack(fill=tk.X, pady=5)

        self.scan_btn = ttk.Button(
            control_frame, 
            text="Быстрое сканирование (C:\\)",
            command=self.start_scan
        )
        self.scan_btn.pack(side=tk.LEFT, padx=5)

        self.status_label = ttk.Label(control_frame, text="Готов к работе")
        self.status_label.pack(side=tk.RIGHT, padx=5)

        # Лог
        self.log = scrolledtext.ScrolledText(
            frame,
            wrap=tk.WORD,
            width=100,
            height=30,
            font=('Consolas', 9)
        )
        self.log.pack(fill=tk.BOTH, expand=True)

    def start_scan(self):
        """Запускает сканирование в отдельном потоке"""
        self.scan_btn.config(state=tk.DISABLED)
        self.status_label.config(text="Сканирование...")
        self.log.insert(tk.END, "🔄 Начато сканирование...\n")

        def scan_thread():
            try:
                found = self.core.fast_scan()
                
                if found:
                    self.log.insert(tk.END, f"🚨 Найдено потенциальных угроз: {len(found)}\n")
                    for file in found:
                        self.log.insert(tk.END, f"• {file}\n")
                        
                        # Показываем диалог для каждого файла
                        self.root.after(0, self.ask_quarantine, file)
                else:
                    self.log.insert(tk.END, "✅ Угроз не обнаружено\n")
                
                self.root.after(0, self.scan_complete)
            except Exception as e:
                self.log.insert(tk.END, f"❌ Ошибка сканирования: {str(e)}\n")
                self.root.after(0, self.scan_complete)

        threading.Thread(target=scan_thread, daemon=True).start()

    def ask_quarantine(self, file_path):
        """Спрашивает пользователя о карантине"""
        filename = os.path.basename(file_path)
        if messagebox.askyesno(
            "Обнаружена угроза",
            f"Файл {filename} может быть опасен.\nОтправить в карантин?"
        ):
            if self.core.quarantine_file(file_path):
                self.log.insert(tk.END, f"✓ Файл перемещён в карантин\n")
            else:
                self.log.insert(tk.END, f"✗ Не удалось переместить файл\n")

    def scan_complete(self):
        """Завершение сканирования"""
        self.scan_btn.config(state=tk.NORMAL)
        self.status_label.config(text="Сканирование завершено")
        self.log.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = FreeUI(root)
    
    # Центрируем окно
    window_width = 900
    window_height = 650
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = (screen_width // 2) - (window_width // 2)
    y = (screen_height // 2) - (window_height // 2)
    root.geometry(f"{window_width}x{window_height}+{x}+{y}")
    
    root.mainloop()
