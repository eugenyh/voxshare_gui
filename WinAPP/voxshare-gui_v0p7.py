import customtkinter as ctk
import sounddevice as sd
import socket
import threading
import numpy as np
from PIL import Image, ImageTk
import struct
import time
import queue
from threading import Event
import opuslib
import json         # <--- Добавлено для JSON
import logging      # <--- Добавлено для логирования
import sys          # <--- Добавлено для sys.exit

# --- Глобальный словарь для настроек ---
config = {}

# --- Глобальные определения констант типов пакетов ---
# (Они остаются здесь для ясности и потенциального использования вне класса)
PACKET_TYPE_AUDIO = b"AUD"
PACKET_TYPE_PING = b"PING"

# --- Функции для работы с настройками и логированием ---

def get_default_config():
    """Возвращает словарь с настройками по умолчанию."""
    return {
        "gui": {
            "appearance_mode": "dark",
            "selector_geometry": "500x350",
            "main_geometry": "400x500"
        },
        "network": {
            "multicast_group": "239.255.42.99",
            "port": 5005,
            "ttl": 1,
            "socket_buffer_size": 65536,
            "ping_interval_sec": 2,
            "client_timeout_sec": 5
        },
        "audio": {
            "sample_rate": 48000,
            "channels": 1,
            "block_size": 960,
            "dtype": "int16",
            "opus_application": "voip",
            "playback_queue_size": 20
        },
        "logging": {
            "enabled": True,
            "log_file": "voxshare.log",
            "log_level": "INFO",
            "log_format": "%(asctime)s - %(levelname)s - %(threadName)s - %(message)s"
        }
    }

def load_config(filename="config.json"):
    """Загружает настройки из JSON файла или создает файл с настройками по умолчанию."""
    global config
    defaults = get_default_config()
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            loaded_config = json.load(f)
            # Обновляем defaults загруженными значениями (для частичных конфигов)
            # Необходимо рекурсивное обновление для вложенных словарей
            def update_recursive(d, u):
                for k, v in u.items():
                    if isinstance(v, dict):
                        # Если ключ существует в d и является словарем, обновляем его рекурсивно
                        if k in d and isinstance(d[k], dict):
                            d[k] = update_recursive(d[k], v)
                        # Иначе (ключа нет в d или он не словарь), просто присваиваем значение из u
                        else:
                            d[k] = v
                    else:
                        d[k] = v
                return d
            config = update_recursive(defaults, loaded_config)
            print(f"Настройки загружены из {filename}")

    except FileNotFoundError:
        print(f"Файл настроек {filename} не найден. Создаю файл с настройками по умолчанию.")
        config = defaults
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            print(f"Файл настроек {filename} создан.")
        except IOError as e:
            print(f"Ошибка: Не удалось создать файл настроек {filename}: {e}")
            # Продолжаем работу с настройками по умолчанию
    except json.JSONDecodeError as e:
        print(f"Ошибка: Не удалось декодировать JSON в файле {filename}: {e}")
        print("Используются настройки по умолчанию.")
        config = defaults
    except Exception as e:
        print(f"Неожиданная ошибка при загрузке настроек: {e}")
        print("Используются настройки по умолчанию.")
        config = defaults

def setup_logging():
    """Настраивает систему логирования на основе конфигурации."""
    log_config = config.get('logging', {})
    enabled = log_config.get('enabled', False)

    if not enabled:
        logging.disable(logging.CRITICAL) # Отключаем все логи ниже CRITICAL
        print("Логирование отключено в настройках.")
        return

    log_level_str = log_config.get('log_level', 'INFO').upper()
    log_file = log_config.get('log_file', 'voxshare.log')
    log_format = log_config.get('log_format', '%(asctime)s - %(levelname)s - %(message)s')

    log_level_map = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL
    }
    log_level = log_level_map.get(log_level_str, logging.INFO)

    # Настройка логирования
    # Удаляем существующие обработчики, чтобы избежать дублирования при перезапуске
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    try:
        logging.basicConfig(level=log_level,
                            format=log_format,
                            filename=log_file,
                            filemode='a', # 'a' - append, 'w' - overwrite
                            encoding='utf-8') # Добавлено для поддержки UTF-8 в логах
        # Опционально: Добавить вывод в консоль для отладки
        # console_handler = logging.StreamHandler(sys.stdout)
        # console_handler.setLevel(log_level)
        # console_handler.setFormatter(logging.Formatter(log_format))
        # logging.getLogger().addHandler(console_handler)

        logging.info("="*20 + " Запуск приложения " + "="*20)
        logging.info(f"Логирование настроено. Уровень: {log_level_str}, Файл: {log_file}")
        print(f"Логирование включено. Уровень: {log_level_str}, Файл: {log_file}")

    except IOError as e:
         print(f"Ошибка настройки логирования в файл {log_file}: {e}. Логирование будет отключено.")
         logging.disable(logging.CRITICAL)
    except Exception as e:
        print(f"Неожиданная ошибка настройки логирования: {e}. Логирование будет отключено.")
        logging.disable(logging.CRITICAL)


# --- Сопоставление строк из конфига с константами Opus ---
OPUS_APPLICATION_MAP = {
    "voip": opuslib.APPLICATION_VOIP,
    "audio": opuslib.APPLICATION_AUDIO,
    "restricted_lowdelay": opuslib.APPLICATION_RESTRICTED_LOWDELAY
}

# --- Класс для работы с сетью и Opus ---
class AudioTransceiver:
    def __init__(self, net_config, audio_config): # <--- Принимает конфиги
        self.net_config = net_config
        self.audio_config = audio_config

        try:
            self.local_ip = socket.gethostbyname(socket.gethostname())
        except socket.gaierror:
             logging.warning("Не удалось определить локальный IP по hostname, используется '127.0.0.1'")
             self.local_ip = "127.0.0.1" # Запасной вариант

        self.active_clients = {}
        self.clients_lock = threading.Lock()
        self.received_opus_packets = queue.Queue(
            maxsize=self.audio_config.get('playback_queue_size', 20) * 2
        )
        self.shutdown_event = Event()

        # --- Используем настройки из конфига ---
        self.mcast_grp = self.net_config.get('multicast_group', '239.255.42.99')
        self.port = self.net_config.get('port', 5005)
        self.ttl = self.net_config.get('ttl', 1)
        self.socket_buffer_size = self.net_config.get('socket_buffer_size', 65536)

        self.sample_rate = self.audio_config.get('sample_rate', 48000)
        self.channels = self.audio_config.get('channels', 1)
        self.block_size = self.audio_config.get('block_size', 960)
        self.dtype = self.audio_config.get('dtype', 'int16')
        opus_app_str = self.audio_config.get('opus_application', 'voip')
        self.opus_application = OPUS_APPLICATION_MAP.get(opus_app_str, opuslib.APPLICATION_VOIP)
        # ---------------------------------------

        # *** ИСПРАВЛЕНИЕ NameError: Сохраняем типы пакетов в self ***
        self.packet_type_audio = PACKET_TYPE_AUDIO
        self.packet_type_ping = PACKET_TYPE_PING
        # ***********************************************************

        # Инициализация Opus
        try:
            self.encoder = opuslib.Encoder(self.sample_rate, self.channels, self.opus_application)
            self.decoder = opuslib.Decoder(self.sample_rate, self.channels)
            logging.info(f"Opus инициализирован: Rate={self.sample_rate}, Channels={self.channels}, App={opus_app_str}")
        except opuslib.OpusError as e:
            logging.exception("Критическая ошибка инициализации Opus")
            raise RuntimeError(f"Ошибка инициализации Opus: {e}")
        except Exception as e:
             logging.exception("Неожиданная критическая ошибка инициализации Opus")
             raise RuntimeError(f"Неожиданная ошибка инициализации Opus: {e}")

        # Инициализация сокетов
        self.init_sockets()

    def init_sockets(self):
        """Инициализация multicast сокетов"""
        try:
            # Сокет для отправки
            self.sock_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock_send.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.ttl)

            # Сокет для приема
            self.sock_recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock_recv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Устанавливаем SO_RCVBUF перед bind в некоторых системах
            try:
                 self.sock_recv.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.socket_buffer_size)
                 logging.info(f"Установлен размер буфера приема сокета: {self.socket_buffer_size}")
            except socket.error as e:
                 logging.warning(f"Не удалось установить размер буфера приема сокета: {e}")

            self.sock_recv.bind(("", self.port)) # Привязка ко всем интерфейсам

            # Присоединение к multicast группе
            mreq = struct.pack("4sl", socket.inet_aton(self.mcast_grp), socket.INADDR_ANY)
            self.sock_recv.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

            logging.info(f"Сокеты инициализированы. Прием на порту {self.port}, группа {self.mcast_grp}")

        except socket.error as e:
            logging.exception("Критическая ошибка инициализации сокетов")
            raise RuntimeError(f"Ошибка инициализации сокетов: {e}")
        except Exception as e:
             logging.exception("Неожиданная критическая ошибка инициализации сокетов")
             raise RuntimeError(f"Неожиданная ошибка инициализации сокетов: {e}")


    def cleanup(self):
        """Очистка ресурсов"""
        logging.info("Начало очистки ресурсов AudioTransceiver...")
        self.shutdown_event.set()
        time.sleep(0.2) # Небольшая пауза для потоков

        if hasattr(self, 'sock_send'):
            try:
                self.sock_send.close()
                logging.info("Сокет отправки закрыт.")
            except Exception as e:
                logging.error(f"Ошибка при закрытии сокета отправки: {e}")

        if hasattr(self, 'sock_recv'):
            # Попытка покинуть группу
            try:
                mreq = struct.pack("4sl", socket.inet_aton(self.mcast_grp), socket.INADDR_ANY)
                self.sock_recv.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
                logging.info(f"Покинута multicast группа {self.mcast_grp}.")
            except socket.error as e:
                # Эта ошибка может быть нормальной, если сокет уже закрыт или не был присоединен
                logging.warning(f"Не удалось покинуть multicast группу (возможно, сокет уже закрыт): {e}")
            except Exception as e:
                 logging.error(f"Ошибка при попытке покинуть multicast группу: {e}")

            # Закрытие сокета приема
            try:
                self.sock_recv.close()
                logging.info("Сокет приема закрыт.")
            except Exception as e:
                 logging.error(f"Ошибка при закрытии сокета приема: {e}")

        logging.info("Очистка AudioTransceiver завершена.")

    # --- Методы encode_and_send_audio, send_ping, receive_packets ---
    # --- Заменяем print на logging ---
    def encode_and_send_audio(self, pcm_data_bytes):
        """Кодирование PCM данных в Opus и отправка"""
        try:
            encoded_data = self.encoder.encode(pcm_data_bytes, self.block_size)
            # Используем self.packet_type_audio
            self.sock_send.sendto(self.packet_type_audio + encoded_data, (self.mcast_grp, self.port))
            # logging.debug(f"Отправлен аудио пакет {len(encoded_data)} байт") # Очень много логов
        except opuslib.OpusError as e:
            logging.error(f"Ошибка кодирования Opus: {e}")
        except socket.error as e:
            logging.error(f"Ошибка отправки аудио: {e}")
        except Exception as e:
            logging.exception(f"Неожиданная ошибка при кодировании/отправке аудио")


    def send_ping(self):
        """Отправка ping-пакета"""
        try:
            # Используем self.packet_type_ping
            self.sock_send.sendto(self.packet_type_ping, (self.mcast_grp, self.port))
            logging.debug("Отправлен PING пакет")
        except socket.error as e:
            if not self.shutdown_event.is_set():
                 logging.error(f"Ошибка отправки ping: {e}")
        except Exception as e:
             if not self.shutdown_event.is_set():
                 logging.exception("Неожиданная ошибка при отправке ping")


    def receive_packets(self):
        """Получение пакетов в цикле"""
        logging.info("Поток приема пакетов запущен.")
        while not self.shutdown_event.is_set():
            try:
                data, addr = self.sock_recv.recvfrom(self.socket_buffer_size)
                logging.debug(f"Получен пакет {len(data)} байт от {addr}")

                if addr[0] == self.local_ip:
                    logging.debug("Пакет от себя проигнорирован.")
                    continue

                # Определяем тип пакета по первым байтам, используя self.packet_type_audio
                packet_type = data[:len(self.packet_type_audio)] # Длина префикса

                # Сравниваем с self.packet_type_audio и self.packet_type_ping
                if packet_type == self.packet_type_audio:
                    opus_packet = data[len(self.packet_type_audio):]
                    try:
                        self.received_opus_packets.put_nowait(opus_packet)
                        logging.debug(f"Аудио пакет ({len(opus_packet)} байт) добавлен в очередь.")
                    except queue.Full:
                        try:
                            dropped = self.received_opus_packets.get_nowait()
                            self.received_opus_packets.put_nowait(opus_packet)
                            logging.warning(f"Очередь полученных аудио пакетов полна. Отброшен пакет {len(dropped)} байт.")
                        except queue.Empty: pass
                        except queue.Full:
                             logging.warning("Очередь полна даже после удаления, новый пакет пропущен.")
                elif packet_type == self.packet_type_ping:
                    with self.clients_lock:
                        self.active_clients[addr[0]] = time.time()
                    logging.info(f"Получен PING от {addr[0]}. Клиент активен.")
                else:
                    logging.warning(f"Получен неизвестный тип пакета от {addr}: {data[:10]}...")


            except socket.timeout:
                 continue # Если сокет неблокирующий с таймаутом
            except socket.error as e:
                if self.shutdown_event.is_set():
                    logging.info("Сокет закрыт, поток приема завершается.")
                    break # Выход из цикла при штатном закрытии
                else:
                    # Ошибка может быть связана с тем, что сокет был закрыт другим потоком во время recvfrom
                    # Проверяем еще раз shutdown_event
                    if not self.shutdown_event.is_set():
                         logging.error(f"Ошибка сокета при получении пакета: {e}")
                    time.sleep(0.1) # Пауза при ошибке
            except Exception as e:
                 if not self.shutdown_event.is_set():
                    logging.exception("Неожиданная ошибка в receive_packets")
        logging.info("Поток приема пакетов завершен.")


    def decode_audio(self, opus_packet):
        """Декодирование Opus пакета в PCM"""
        try:
            pcm_data = self.decoder.decode(opus_packet, self.block_size)
            logging.debug(f"Декодирован пакет {len(opus_packet)} байт -> {len(pcm_data)} байт PCM")
            return pcm_data
        except opuslib.OpusError as e:
            logging.error(f"Ошибка декодирования Opus пакета ({len(opus_packet)} байт): {e}")
            return None
        except Exception as e:
             logging.exception(f"Неожиданная ошибка декодирования пакета ({len(opus_packet)} байт)")
             return None


    def get_decoded_audio_packet(self):
        """Извлекает Opus пакет из очереди и декодирует его"""
        try:
            opus_packet = self.received_opus_packets.get_nowait()
            decoded_pcm = self.decode_audio(opus_packet)
            if decoded_pcm:
                 audio_data = np.frombuffer(decoded_pcm, dtype=self.dtype)
                 expected_size = self.block_size * self.channels
                 if audio_data.size == expected_size:
                     return audio_data
                 else:
                     logging.warning(f"Неожиданный размер декодированного пакета ({audio_data.size} вместо {expected_size})")
                     return None
            else:
                return None # Ошибка декодирования
        except queue.Empty:
            return None # Очередь пуста
        except Exception as e:
             logging.exception("Неожиданная ошибка в get_decoded_audio_packet")
             return None


    def cleanup_inactive_clients(self):
        """Очистка неактивных клиентов"""
        current_time = time.time()
        inactive = []
        client_timeout = self.net_config.get('client_timeout_sec', 5)
        with self.clients_lock:
            inactive = [ip for ip, last_seen in self.active_clients.items()
                        if current_time - last_seen > client_timeout]

        if inactive:
            with self.clients_lock:
                for ip in inactive:
                    # Проверяем еще раз перед удалением, на случай если блокировка была долгой
                    if ip in self.active_clients and current_time - self.active_clients[ip] > client_timeout:
                        logging.info(f"Удаляем неактивного клиента: {ip} (последний раз видели {current_time - self.active_clients[ip]:.1f} сек назад)")
                        del self.active_clients[ip]


# --- GUI Выбора устройств ---
class AudioSelector(ctk.CTk):
    def __init__(self, gui_config): # <--- Принимает GUI конфиг
        super().__init__()
        self.gui_config = gui_config
        self.title("Выбор аудиоустройств")
        # --- Используем настройки геометрии из конфига ---
        geometry = self.gui_config.get('selector_geometry', '500x350')
        try:
            self.geometry(geometry)
        except Exception as e:
             logging.warning(f"Некорректная геометрия для AudioSelector в конфиге ('{geometry}'): {e}. Используется 500x350.")
             self.geometry("500x350")

        self.resizable(False, False)
        # Тема устанавливается глобально перед созданием окна

        self.input_device_index = None
        self.output_device_index = None

        self.create_widgets()

    def create_widgets(self):
        """Создание элементов интерфейса"""
        ctk.CTkLabel(self, text="Выберите микрофон:", font=("Arial", 14)).pack(pady=10)
        input_devices = self.get_device_list(input=True)
        self.input_combo = ctk.CTkComboBox(self, values=input_devices, width=400)
        if input_devices:
            self.input_combo.set(input_devices[0]) # Установить значение по умолчанию, если есть
        else:
             logging.warning("Не найдено ни одного устройства ввода.")
             # Можно добавить Label с сообщением об ошибке здесь
        self.input_combo.pack()

        ctk.CTkLabel(self, text="Выберите устройство вывода:", font=("Arial", 14)).pack(pady=20)
        output_devices = self.get_device_list(output=True)
        self.output_combo = ctk.CTkComboBox(self, values=output_devices, width=400)
        if output_devices:
            self.output_combo.set(output_devices[0]) # Установить значение по умолчанию, если есть
        else:
             logging.warning("Не найдено ни одного устройства вывода.")
             # Можно добавить Label с сообщением об ошибке здесь
        self.output_combo.pack()

        ctk.CTkButton(self, text="Продолжить", command=self.validate_and_launch).pack(pady=30)

        # Метка для вывода ошибок валидации
        self.error_label = ctk.CTkLabel(self, text="", text_color="red", font=("Arial", 12))
        self.error_label.pack(pady=(0, 10))

    def get_device_list(self, input=False, output=False):
        """Получение списка аудиоустройств"""
        try:
            devices = sd.query_devices()
            device_list = []
            for i, dev in enumerate(devices):
                 # Дополнительные проверки на None
                if not dev or not isinstance(dev, dict) or not dev.get('name'):
                    logging.warning(f"Пропущено некорректное устройство с индексом {i}: {dev}")
                    continue

                is_input = dev.get('max_input_channels', 0) > 0
                is_output = dev.get('max_output_channels', 0) > 0

                if (input and is_input) or (output and is_output):
                     # Добавим проверку кодировки имени устройства, если возможно
                     try:
                          dev_name = dev['name']
                          # Попытка декодирования/кодирования для проверки
                          # dev_name.encode(sys.stdout.encoding or 'utf-8', errors='ignore').decode(sys.stdout.encoding or 'utf-8')
                          device_list.append(f"{i}: {dev_name}")
                     except Exception as enc_e:
                          logging.warning(f"Проблема с именем устройства {i}: {dev.get('name')}. Ошибка: {enc_e}. Пропускаем.")


            logging.info(f"Найдено устройств {'ввода' if input else 'вывода'}: {len(device_list)}")
            return device_list

        except sd.PortAudioError as e:
             logging.exception("Ошибка PortAudio при получении списка устройств")
             if hasattr(self, 'error_label') and self.error_label.winfo_exists():
                self.error_label.configure(text=f"Ошибка чтения устройств: {e}")
             return []
        except Exception as e:
            logging.exception("Неожиданная ошибка при получении списка устройств")
            if hasattr(self, 'error_label') and self.error_label.winfo_exists():
                 self.error_label.configure(text=f"Критическая ошибка чтения устройств!")
            return []


    def validate_and_launch(self):
        """Проверка выбора устройств и запуск основного окна"""
        input_selection = self.input_combo.get()
        output_selection = self.output_combo.get()

        try:
            if not input_selection or not output_selection:
                 raise ValueError("Не выбрано одно или оба устройства.")
            if not ":" in input_selection or not ":" in output_selection:
                 raise ValueError("Некорректный формат выбранного устройства.")


            self.input_device_index = int(input_selection.split(":")[0])
            self.output_device_index = int(output_selection.split(":")[0])
            logging.info(f"Выбраны устройства: Ввод={self.input_device_index} ('{input_selection}'), Вывод={self.output_device_index} ('{output_selection}')")

            # Проверка настроек через sounddevice
            global config # Доступ к глобальному конфигу для аудио параметров
            audio_cfg = config.get('audio', {})
            rate = audio_cfg.get('sample_rate', 48000)
            chans = audio_cfg.get('channels', 1)
            dtype = audio_cfg.get('dtype', 'int16')

            try:
                 logging.debug(f"Проверка настроек ввода: dev={self.input_device_index}, rate={rate}, chans={chans}, dtype={dtype}")
                 sd.check_input_settings(device=self.input_device_index, channels=chans, samplerate=rate, dtype=dtype)
                 logging.debug(f"Проверка настроек вывода: dev={self.output_device_index}, rate={rate}, chans={chans}, dtype={dtype}")
                 sd.check_output_settings(device=self.output_device_index, channels=chans, samplerate=rate, dtype=dtype)
                 logging.info("Настройки аудиоустройств успешно проверены.")
            except sd.PortAudioError as pa_err:
                 logging.error(f"Ошибка проверки настроек PortAudio: {pa_err}")
                 raise ValueError(f"Устройство не поддерживает настройки ({rate}Hz, {chans}ch, {dtype}): {pa_err}")
            except ValueError as val_err: # Ошибка может быть и ValueError (e.g., invalid device index)
                 logging.error(f"Ошибка проверки настроек sounddevice (ValueError): {val_err}")
                 raise ValueError(f"Некорректный индекс устройства или ошибка: {val_err}")
            except Exception as e:
                 logging.exception("Ошибка проверки настроек sounddevice")
                 raise ValueError(f"Ошибка проверки устройства: {e}")

            if hasattr(self, 'error_label') and self.error_label.winfo_exists():
                self.error_label.configure(text="")
            self.destroy()
            # Передаем конфиги в основное окно
            main_app = VoxShareGUI(
                 input_device_index=self.input_device_index,
                 output_device_index=self.output_device_index,
                 gui_config=self.gui_config, # Передаем gui конфиг
                 net_config=config.get('network',{}), # Передаем network конфиг
                 audio_config=config.get('audio',{}) # Передаем audio конфиг
                 )
            main_app.mainloop()

        except (ValueError, AttributeError, IndexError) as e:
            error_message = f"Ошибка выбора: {e}"
            logging.warning(f"Ошибка валидации выбора устройств: {e}")
            if hasattr(self, 'error_label') and self.error_label.winfo_exists():
                 self.error_label.configure(text=error_message)
        except Exception as e:
             logging.exception("Неожиданная ошибка при валидации и запуске")
             if hasattr(self, 'error_label') and self.error_label.winfo_exists():
                 self.error_label.configure(text=f"Произошла критическая ошибка!")


# --- Основное GUI Приложения ---
class VoxShareGUI(ctk.CTk):
    # --- Принимает конфиги при инициализации ---
    def __init__(self, input_device_index, output_device_index, gui_config, net_config, audio_config):
        super().__init__()
        self.gui_config = gui_config
        self.net_config = net_config
        self.audio_config = audio_config

        self.title("VoxShare")
        # --- Используем геометрию из конфига ---
        geometry = self.gui_config.get('main_geometry', '400x500')
        try:
            self.geometry(geometry)
        except Exception as e:
             logging.warning(f"Некорректная геометрия для VoxShareGUI в конфиге ('{geometry}'): {e}. Используется 400x500.")
             self.geometry("400x500")

        self.resizable(False, False)
        # Тема устанавливается глобально

        self.input_device_index = input_device_index
        self.output_device_index = output_device_index
        self.is_pressing = False
        self.volume = 0.0
        self.volume_lock = threading.Lock()

        # Создаем экземпляр AudioTransceiver, передавая ему конфиги
        try:
            # Передаем нужные части конфига
            self.audio_transceiver = AudioTransceiver(
                net_config=self.net_config,
                audio_config=self.audio_config
                )
        except RuntimeError as e:
             logging.exception("Критическая ошибка при инициализации AudioTransceiver")
             # Показать ошибку и завершить работу?
             # import tkinter.messagebox as messagebox
             # messagebox.showerror("Критическая ошибка", f"Не удалось инициализировать аудио/сеть:\n{e}")
             self.destroy()
             # sys.exit(1) # Принудительный выход, если нужно
             return
        except Exception as e:
             logging.exception("Неожиданная критическая ошибка при инициализации AudioTransceiver")
             self.destroy()
             # sys.exit(1)
             return


        self.setup_gui()
        self.start_threads()

        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        logging.info("Основное окно VoxShareGUI инициализировано.")

    def setup_gui(self):
        """Настройка графического интерфейса"""
        ctk.CTkLabel(self, text="VoxShare", font=("Arial", 24)).pack(pady=20)
        try:
            # Пытаемся открыть изображение, обрабатываем ошибки PIL
            img = Image.open("logo.png").resize((150, 150), Image.Resampling.LANCZOS)
            self.logo_img = ctk.CTkImage(light_image=img, dark_image=img, size=(150, 150))
            logging.debug("Логотип logo.png загружен.")
        except FileNotFoundError:
             logging.warning("Файл logo.png не найден.")
             self.logo_img = None
        except Exception as e: # Ловим другие возможные ошибки PIL/ImageTk
            logging.warning(f"Не удалось загрузить или обработать logo.png: {e}")
            self.logo_img = None

        self.talk_btn = ctk.CTkButton(
            self, image=self.logo_img if self.logo_img else None,
            text="" if self.logo_img else "ГОВОРИТЬ",
            width=160, height=160,
            corner_radius=80, fg_color="#444", hover_color="#555"
        )
        self.talk_btn.pack(pady=30)
        self.talk_btn.bind("<ButtonPress-1>", self.on_press)
        self.talk_btn.bind("<ButtonRelease-1>", self.on_release)

        self.led = ctk.CTkLabel(self, text="", width=30, height=30, corner_radius=15, fg_color="#880000")
        self.led.pack(pady=10)

        self.volume_bar = ctk.CTkProgressBar(self, width=200, height=20)
        self.volume_bar.set(0)
        self.volume_bar.pack(pady=20)
        logging.debug("Элементы GUI основного окна созданы.")


    def start_threads(self):
        """Запуск рабочих потоков"""
        if not hasattr(self, 'audio_transceiver') or not self.audio_transceiver:
             logging.error("Ошибка: audio_transceiver не инициализирован, потоки не запускаются.")
             return

        logging.info("Запуск рабочих потоков...")
        # --- Передаем аудио параметры из audio_transceiver в потоки ---
        self.input_thread = threading.Thread(target=self.audio_input_thread, name="AudioInputThread", daemon=True)
        self.output_thread = threading.Thread(target=self.audio_output_thread, name="AudioOutputThread", daemon=True)
        # --------------------------------------------------------------
        self.receive_thread = threading.Thread(target=self.receive_thread, name="ReceiveThread", daemon=True)
        self.ping_thread = threading.Thread(target=self.ping_thread, name="PingThread", daemon=True)
        self.cleanup_thread = threading.Thread(target=self.client_cleanup_thread, name="ClientCleanupThread", daemon=True)

        self.input_thread.start()
        self.output_thread.start()
        self.receive_thread.start()
        self.ping_thread.start()
        self.cleanup_thread.start()

        self.after(100, self.update_gui) # Запуск обновления GUI
        logging.info("Все рабочие потоки запущены.")


    def audio_input_thread(self):
        """Поток для захвата аудио, кодирования и отправки"""
        # Получаем параметры из audio_transceiver, который взял их из конфига
        sample_rate = self.audio_transceiver.sample_rate
        channels = self.audio_transceiver.channels
        blocksize = self.audio_transceiver.block_size
        dtype = self.audio_transceiver.dtype

        def callback(indata: np.ndarray, frames: int, time_info, status: sd.CallbackFlags):
            if status:
                logging.warning(f"Статус обратного вызова ввода: {status}")
            if self.is_pressing and not self.audio_transceiver.shutdown_event.is_set():
                try:
                    pcm_data_bytes = indata.tobytes()
                    self.audio_transceiver.encode_and_send_audio(pcm_data_bytes)

                    # Обновление громкости
                    # Преобразуем в float32 для точности RMS
                    float_data = indata.astype(np.float32) / 32768.0 # Нормализация к [-1.0, 1.0]
                    rms = np.sqrt(np.mean(np.square(float_data)))
                    with self.volume_lock:
                        # Усиление для лучшей видимости на индикаторе
                        self.volume = float(rms) * 2.5 # Можно подстроить
                except Exception as e:
                    logging.exception(f"Ошибка в audio_input callback")
            else:
                 # Сброс громкости только если не нажата кнопка
                 if not self.is_pressing:
                    with self.volume_lock:
                        self.volume = 0.0

        try:
            logging.info(f"Открытие InputStream: Устройство={self.input_device_index}, Rate={sample_rate}, Block={blocksize}, Dtype={dtype}")
            with sd.InputStream(samplerate=sample_rate, channels=channels, dtype=dtype,
                                callback=callback, blocksize=blocksize,
                                device=self.input_device_index):
                logging.info("InputStream открыт. Ожидание сигнала завершения...")
                self.audio_transceiver.shutdown_event.wait()

        except sd.PortAudioError as e:
            logging.exception(f"Критическая ошибка аудио входа (PortAudioError) Устройство={self.input_device_index}")
            # TODO: Уведомить пользователя через GUI?
        except Exception as e:
            logging.exception(f"Критическая ошибка аудио входа (Другое) Устройство={self.input_device_index}")

        logging.info("Поток аудио входа завершается.")


    def audio_output_thread(self):
        """Поток для получения декодированного аудио и воспроизведения"""
        sample_rate = self.audio_transceiver.sample_rate
        channels = self.audio_transceiver.channels
        blocksize = self.audio_transceiver.block_size
        dtype = self.audio_transceiver.dtype

        def callback(outdata: np.ndarray, frames: int, time_info, status: sd.CallbackFlags):
            if status:
                logging.warning(f"Статус обратного вызова вывода: {status}")

            audio_data = self.audio_transceiver.get_decoded_audio_packet()

            if audio_data is not None and audio_data.size == frames * channels:
                 outdata[:] = audio_data.reshape(-1, channels)
                 logging.debug(f"Воспроизведен аудио пакет {len(audio_data)} сэмплов")
            else:
                # Если данных нет или размер неверный, выводим тишину
                outdata.fill(0)
                if audio_data is not None: # Логируем только если был пакет, но с неверным размером
                     logging.warning(f"Размер пакета для воспроизведения не совпал ({audio_data.size} vs {frames * channels}), воспроизведена тишина.")
                # Не логируем пустую очередь, это норма

        try:
            logging.info(f"Открытие OutputStream: Устройство={self.output_device_index}, Rate={sample_rate}, Block={blocksize}, Dtype={dtype}")
            with sd.OutputStream(samplerate=sample_rate, channels=channels, dtype=dtype,
                                 callback=callback, blocksize=blocksize,
                                 device=self.output_device_index):
                logging.info("OutputStream открыт. Ожидание сигнала завершения...")
                self.audio_transceiver.shutdown_event.wait()

        except sd.PortAudioError as e:
            logging.exception(f"Критическая ошибка аудио выхода (PortAudioError) Устройство={self.output_device_index}")
        except Exception as e:
             logging.exception(f"Критическая ошибка аудио выхода (Другое) Устройство={self.output_device_index}")

        logging.info("Поток аудио вывода завершается.")


    def receive_thread(self):
        """Поток для приема пакетов (запускает метод transceiver'а)"""
        if hasattr(self, 'audio_transceiver') and self.audio_transceiver:
             self.audio_transceiver.receive_packets() # Логирование внутри метода
        else:
             logging.error("ReceiveThread: audio_transceiver не существует.")


    def ping_thread(self):
        """Поток для отправки ping-пакетов"""
        logging.info("Поток отправки пингов запущен.")
        if not hasattr(self, 'audio_transceiver') or not self.audio_transceiver:
             logging.error("PingThread: audio_transceiver не существует.")
             return

        ping_interval = self.net_config.get('ping_interval_sec', 2)
        while not self.audio_transceiver.shutdown_event.is_set():
            self.audio_transceiver.send_ping()
            self.audio_transceiver.shutdown_event.wait(timeout=ping_interval)
        logging.info("Поток отправки пингов завершается.")

    def client_cleanup_thread(self):
        """Поток для очистки неактивных клиентов"""
        logging.info("Поток очистки клиентов запущен.")
        if not hasattr(self, 'audio_transceiver') or not self.audio_transceiver:
             logging.error("ClientCleanupThread: audio_transceiver не существует.")
             return

        cleanup_interval = 1.0 # Интервал проверки неактивных клиентов
        while not self.audio_transceiver.shutdown_event.is_set():
            self.audio_transceiver.cleanup_inactive_clients()
            self.audio_transceiver.shutdown_event.wait(timeout=cleanup_interval)
        logging.info("Поток очистки клиентов завершается.")


    def update_gui(self):
        """Обновление GUI (вызывается в основном потоке)"""
        try:
             # Проверка, существует ли еще окно и audio_transceiver
            if not self.winfo_exists() or not hasattr(self, 'audio_transceiver') or not self.audio_transceiver:
                # logging.debug("Окно GUI или audio_transceiver уже не существует, update_gui прерван.")
                return

            # Обновление индикатора громкости
            if hasattr(self, 'volume_bar') and self.volume_bar.winfo_exists():
                with self.volume_lock:
                    current_volume = min(1.0, max(0.0, self.volume))
                self.volume_bar.set(current_volume)
            # else: # Не логируем каждую итерацию, если виджет пропал
                 # logging.warning("Volume bar не найден или разрушен в update_gui.")

            # Планируем следующее обновление, если приложение не завершается
            if not self.audio_transceiver.shutdown_event.is_set():
                 self.after(50, self.update_gui)
            # else: # Не логируем каждую итерацию
                # logging.debug("Событие shutdown установлено, update_gui больше не планируется.")
        except Exception as e:
            logging.exception("Неожиданная ошибка в update_gui")


    def on_press(self, event):
        if not self.is_pressing:
             logging.info("Начало передачи (кнопка нажата)")
             self.is_pressing = True
             self.update_led(True)

    def on_release(self, event):
        if self.is_pressing:
             logging.info("Остановка передачи (кнопка отпущена)")
             self.is_pressing = False
             self.update_led(False)
             with self.volume_lock:
                 self.volume = 0.0
             # Проверка существования volume_bar перед установкой
             if hasattr(self, 'volume_bar') and self.volume_bar.winfo_exists():
                 self.volume_bar.set(0.0)


    def update_led(self, on):
        color = "#00ff00" if on else "#880000" # Зеленый/Красный
        # Проверка существования led перед конфигурацией
        if hasattr(self, 'led') and self.led.winfo_exists():
            self.led.configure(fg_color=color)
            logging.debug(f"LED индикатор установлен в {'ON' if on else 'OFF'}")
        # else: # Не логируем, если виджет пропал
             # logging.warning("LED виджет не найден или разрушен в update_led.")


    def on_closing(self):
        """Обработчик закрытия окна"""
        logging.info("Получен сигнал закрытия окна (WM_DELETE_WINDOW).")
        if hasattr(self, 'audio_transceiver') and self.audio_transceiver:
            self.audio_transceiver.cleanup() # Сигналим потокам и закрываем сокеты
        else:
             # Если transceiver не создан или уже удален, просто ставим флаг
             # (хотя Event здесь не будет, но для общей логики)
             # self.shutdown_event.set() # Условный флаг для GUI потока
             pass


        # Даем потокам немного времени на завершение перед уничтожением окна
        # time.sleep(0.3) # Может привести к зависанию GUI, лучше избегать sleep в GUI потоке

        logging.info("Уничтожение окна GUI...")
        try:
             self.destroy()
        except Exception as e:
             logging.exception("Ошибка при уничтожении главного окна")
        logging.info("Приложение завершило работу.")


# --- Точка входа ---
if __name__ == "__main__":
    # 1. Загрузка конфигурации
    load_config() # Загружает в глобальный словарь 'config'

    # 2. Настройка логирования на основе конфига
    setup_logging()

    # 3. Установка темы приложения
    try:
        gui_conf = config.get('gui', {})
        appearance_mode = gui_conf.get('appearance_mode', 'dark').lower()
        if appearance_mode not in ['dark', 'light', 'system']:
             logging.warning(f"Некорректный режим темы '{appearance_mode}' в конфиге. Используется 'dark'.")
             appearance_mode = 'dark'
        ctk.set_appearance_mode(appearance_mode)
        logging.info(f"Установлена тема интерфейса: {appearance_mode}")
    except Exception as e:
         logging.exception("Ошибка при установке темы интерфейса из конфига.")
         ctk.set_appearance_mode("dark") # Запасной вариант

    # 4. Проверка зависимостей (Opus)
    try:
        # Просто проверяем, что opuslib импортирован и доступен
        if not hasattr(opuslib, 'Encoder'):
             raise ImportError("opuslib не содержит ожидаемых атрибутов.")
        logging.info(f"Библиотека opuslib найдена и импортирована.")
        # Примечание: Проверка наличия самой .dll/.so/.dylib opus выполняется при создании Encoder/Decoder
    except ImportError:
        message = "Критическая ошибка: Библиотека opuslib не найдена. Установите ее: pip install opuslib"
        print(message)
        logging.critical(message)
        # Показать GUI сообщение об ошибке? (Раскомментировать, если нужно)
        # root = ctk.CTk()
        # root.withdraw() # Скрыть основное пустое окно
        # import tkinter.messagebox as messagebox
        # messagebox.showerror("Ошибка Зависимости", message + "\n\nТакже убедитесь, что установлена сама библиотека Opus.")
        # root.destroy()
        sys.exit(1) # Выход из приложения
    except Exception as e:
         message = f"Неожиданная ошибка при проверке opuslib: {e}"
         print(message)
         logging.critical(message)
         sys.exit(1)


    # 5. Запуск GUI
    try:
        # Передаем только gui часть конфига в селектор
        selector = AudioSelector(gui_config=config.get('gui', {}))
        selector.mainloop()
    except Exception as e:
        logging.exception("Критическая необработанная ошибка на верхнем уровне")
        # print(f"Критическая ошибка: {e}") # Логгер уже должен был записать
        # import traceback
        # traceback.print_exc() # Логгер уже должен был записать
        sys.exit(1) # Выход при критической ошибке

    logging.info("="*20 + " Приложение штатно завершено " + "="*20)
    print("Приложение завершено.")