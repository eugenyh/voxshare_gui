# -*- coding: utf-8 -*-
import customtkinter as ctk
import sounddevice as sd
import socket
import threading
import numpy as np
from PIL import Image, ImageTk
import struct
import time
import queue
from threading import Event, Lock
import opuslib
import json
import logging
import sys
import tkinter # Для проверки типа event

# --- Глобальный словарь для настроек ---
config = {}

# --- Глобальные определения констант типов пакетов ---
PACKET_TYPE_AUDIO = b"AUD"
PACKET_TYPE_PING = b"PING" # Префикс остается 4 байта

# --- Дополнительные константы ---
SPEAKER_TIMEOUT_THRESHOLD = 0.3 # Секунды, через которые статус "говорит" сбрасывается

def resource_path(relative_path):
    """ Получает корректный путь для ресурсов в EXE и в разработке """
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

# --- Функции для работы с настройками и логированием ---

def get_default_config():
    """Возвращает словарь с настройками по умолчанию."""
    return {
        "user": { # <--- Добавлена секция пользователя
            "nickname": ""
        },
        "gui": {
            "appearance_mode": "dark",
            "selector_geometry": "500x350",
            "main_geometry": "550x450"
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

# --- Функции load_config, setup_logging (без изменений) ---
def load_config(filename="config.json"):
    """Загружает настройки из JSON файла или создает файл с настройками по умолчанию."""
    global config
    defaults = get_default_config()
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            loaded_config = json.load(f)
            def update_recursive(d, u):
                for k, v in u.items():
                    if isinstance(v, dict):
                        if k in d and isinstance(d[k], dict):
                            d[k] = update_recursive(d[k], v)
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
        logging.disable(logging.CRITICAL)
        print("Логирование отключено в настройках.")
        return
    log_level_str = log_config.get('log_level', 'INFO').upper()
    log_file = log_config.get('log_file', 'voxshare.log')
    log_format = log_config.get('log_format', '%(asctime)s - %(levelname)s - %(threadName)s - %(message)s')
    log_level_map = {'DEBUG': logging.DEBUG, 'INFO': logging.INFO, 'WARNING': logging.WARNING, 'ERROR': logging.ERROR, 'CRITICAL': logging.CRITICAL}
    log_level = log_level_map.get(log_level_str, logging.INFO)
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    try:
        logging.basicConfig(level=log_level, format=log_format, filename=log_file, filemode='a', encoding='utf-8', force=True)
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
OPUS_APPLICATION_MAP = { "voip": opuslib.APPLICATION_VOIP, "audio": opuslib.APPLICATION_AUDIO, "restricted_lowdelay": opuslib.APPLICATION_RESTRICTED_LOWDELAY }

# --- Класс для работы с сетью и Opus ---
class AudioTransceiver:
    # *** ИЗМЕНЕНИЕ: Принимает user_config ***
    def __init__(self, user_config, net_config, audio_config):
        self.user_config = user_config
        self.net_config = net_config
        self.audio_config = audio_config

        # *** НОВОЕ: Сохраняем никнейм ***
        self.nickname = self.user_config.get('nickname', '').strip()
        # ---------------------------------

        try:
            self.local_ip = socket.gethostbyname(socket.gethostname())
        except socket.gaierror:
             logging.warning("Не удалось определить локальный IP по hostname, используется '127.0.0.1'")
             self.local_ip = "127.0.0.1"

        # *** ИЗМЕНЕНИЕ: Структура active_clients ***
        # Теперь хранит {ip: {'nickname': str, 'last_seen': float}}
        self.active_clients = {}
        # ******************************************
        self.clients_lock = Lock()
        self.received_opus_packets = queue.Queue(maxsize=self.audio_config.get('playback_queue_size', 20) * 2)
        self.shutdown_event = Event()
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
        self.packet_type_audio = PACKET_TYPE_AUDIO
        self.packet_type_ping = PACKET_TYPE_PING
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
        self.init_sockets()

    # --- init_sockets, cleanup, encode_and_send_audio (без изменений) ---
    def init_sockets(self):
        """Инициализация multicast сокетов"""
        try:
            self.sock_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock_send.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.ttl)
            self.sock_recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock_recv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                 self.sock_recv.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.socket_buffer_size)
                 logging.info(f"Установлен размер буфера приема сокета: {self.socket_buffer_size}")
            except socket.error as e:
                 logging.warning(f"Не удалось установить размер буфера приема сокета: {e}")
            self.sock_recv.bind(("", self.port))
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
        time.sleep(0.2)
        if hasattr(self, 'sock_send'):
            try: self.sock_send.close(); logging.info("Сокет отправки закрыт.")
            except Exception as e: logging.error(f"Ошибка при закрытии сокета отправки: {e}")
        if hasattr(self, 'sock_recv'):
            try:
                mreq = struct.pack("4sl", socket.inet_aton(self.mcast_grp), socket.INADDR_ANY)
                self.sock_recv.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
                logging.info(f"Покинута multicast группа {self.mcast_grp}.")
            except socket.error as e: logging.warning(f"Не удалось покинуть multicast группу (возможно, сокет уже закрыт): {e}")
            except Exception as e: logging.error(f"Ошибка при попытке покинуть multicast группу: {e}")
            try: self.sock_recv.close(); logging.info("Сокет приема закрыт.")
            except Exception as e: logging.error(f"Ошибка при закрытии сокета приема: {e}")
        logging.info("Очистка AudioTransceiver завершена.")

    def encode_and_send_audio(self, pcm_data_bytes):
        """Кодирование PCM данных в Opus и отправка"""
        if self.shutdown_event.is_set(): return
        try:
            encoded_data = self.encoder.encode(pcm_data_bytes, self.block_size)
            self.sock_send.sendto(self.packet_type_audio + encoded_data, (self.mcast_grp, self.port))
        except opuslib.OpusError as e: logging.error(f"Ошибка кодирования Opus: {e}")
        except socket.error as e: logging.error(f"Ошибка отправки аудио: {e}")
        except Exception as e: logging.exception(f"Неожиданная ошибка при кодировании/отправке аудио")

    def send_ping(self):
        """Отправка ping-пакета с никнеймом"""
        if self.shutdown_event.is_set(): return
        try:
            # *** ИЗМЕНЕНИЕ: Добавляем никнейм к пакету ***
            nickname_bytes = self.nickname.encode('utf-8')
            ping_packet = self.packet_type_ping + nickname_bytes
            # **********************************************
            self.sock_send.sendto(ping_packet, (self.mcast_grp, self.port))
            logging.debug(f"Отправлен PING пакет (ник: '{self.nickname}')")
        except socket.error as e:
            if not self.shutdown_event.is_set(): logging.error(f"Ошибка отправки ping: {e}")
        except Exception as e:
             if not self.shutdown_event.is_set(): logging.exception("Неожиданная ошибка при отправке ping")

    def receive_packets(self):
        """Получение пакетов в цикле"""
        logging.info("Поток приема пакетов запущен.")
        while not self.shutdown_event.is_set():
            try:
                data, addr = self.sock_recv.recvfrom(self.socket_buffer_size)
                logging.debug(f"Получен пакет {len(data)} байт от {addr}")

                if addr[0] == self.local_ip: continue

                if data.startswith(self.packet_type_audio):
                    opus_packet = data[len(self.packet_type_audio):]
                    packet_tuple = (addr[0], opus_packet)
                    try: self.received_opus_packets.put_nowait(packet_tuple); logging.debug(f"Аудио пакет ({len(opus_packet)} байт от {addr[0]}) добавлен в очередь.")
                    except queue.Full:
                        try: dropped_tuple = self.received_opus_packets.get_nowait(); self.received_opus_packets.put_nowait(packet_tuple); logging.warning(f"Очередь аудио пакетов полна. Отброшен пакет от {dropped_tuple[0]}.")
                        except queue.Empty: pass
                        except queue.Full: logging.warning("Очередь полна даже после удаления, новый пакет пропущен.")

                elif data.startswith(self.packet_type_ping):
                    # *** ИЗМЕНЕНИЕ: Извлекаем никнейм, обновляем структуру active_clients ***
                    nickname_bytes = data[len(self.packet_type_ping):]
                    try:
                        nickname = nickname_bytes.decode('utf-8', errors='replace').strip()
                    except Exception as e:
                        logging.warning(f"Не удалось декодировать никнейм из PING от {addr[0]}: {e}")
                        nickname = "" # Используем пустой ник при ошибке

                    with self.clients_lock:
                        # Обновляем или создаем запись клиента
                        client_info = self.active_clients.get(addr[0], {}) # Получаем существующую или пустую инфу
                        client_info['last_seen'] = time.time()
                        client_info['nickname'] = nickname # Сохраняем/обновляем ник
                        self.active_clients[addr[0]] = client_info # Записываем обратно
                    logging.info(f"Получен PING от {addr[0]} (Ник: '{nickname}'). Клиент активен.")
                    # ***********************************************************************
                else:
                    logging.warning(f"Получен неизвестный тип пакета от {addr}: {data[:10]}...")

            except socket.timeout: continue
            except socket.error as e:
                if self.shutdown_event.is_set(): logging.info("Сокет закрыт, поток приема завершается."); break
                else:
                    if not self.shutdown_event.is_set(): logging.error(f"Ошибка сокета при получении пакета: {e}")
                    time.sleep(0.1)
            except Exception as e:
                 if not self.shutdown_event.is_set(): logging.exception("Неожиданная ошибка в receive_packets")
        logging.info("Поток приема пакетов завершен.")

    # --- decode_audio, get_decoded_audio_packet (без изменений) ---
    def decode_audio(self, opus_packet):
        """Декодирование Opus пакета в PCM"""
        try:
            pcm_data = self.decoder.decode(opus_packet, self.block_size)
            logging.debug(f"Декодирован пакет {len(opus_packet)} байт -> {len(pcm_data)} байт PCM")
            return pcm_data
        except opuslib.OpusError as e: logging.error(f"Ошибка декодирования Opus пакета ({len(opus_packet)} байт): {e}"); return None
        except Exception as e: logging.exception(f"Неожиданная ошибка декодирования пакета ({len(opus_packet)} байт)"); return None

    def get_decoded_audio_packet(self):
        """Извлекает Opus пакет из очереди и декодирует его. Возвращает (sender_ip, audio_data) или None."""
        try:
            sender_ip, opus_packet = self.received_opus_packets.get_nowait()
            decoded_pcm = self.decode_audio(opus_packet)
            if decoded_pcm:
                 audio_data = np.frombuffer(decoded_pcm, dtype=self.dtype)
                 expected_size = self.block_size * self.channels
                 if audio_data.size == expected_size: return sender_ip, audio_data
                 else: logging.warning(f"Неожиданный размер декодированного пакета от {sender_ip} ({audio_data.size} вместо {expected_size})"); return None
            else: return None
        except queue.Empty: return None
        except Exception as e: logging.exception("Неожиданная ошибка в get_decoded_audio_packet"); return None

    def cleanup_inactive_clients(self):
        """Очистка неактивных клиентов"""
        current_time = time.time()
        inactive_ips = []
        client_timeout = self.net_config.get('client_timeout_sec', 5)

        with self.clients_lock:
            all_client_ips = list(self.active_clients.keys()) # Копия ключей для безопасной итерации

        for ip in all_client_ips:
            last_seen = None
            with self.clients_lock:
                # Получаем время последнего пинга для IP
                client_info = self.active_clients.get(ip)
                if client_info:
                    last_seen = client_info.get('last_seen')

            if last_seen is None: continue # Если клиент был удален в другом потоке

            if current_time - last_seen > client_timeout:
                inactive_ips.append(ip)

        if inactive_ips:
            logging.debug(f"Кандидаты на удаление по таймауту: {inactive_ips}")
            with self.clients_lock:
                for ip in inactive_ips:
                    # Перепроверяем перед удалением
                    client_info = self.active_clients.get(ip)
                    if client_info and current_time - client_info.get('last_seen', 0) > client_timeout:
                        nickname = client_info.get('nickname', '')
                        logging.info(f"Удаляем неактивного клиента: {ip} (Ник: '{nickname}', посл. раз: {current_time - client_info.get('last_seen', 0):.1f} сек назад)")
                        del self.active_clients[ip]


# --- GUI Выбора устройств ---
class AudioSelector(ctk.CTk):
    def __init__(self, gui_config):
        super().__init__()
        self.gui_config = gui_config
        self.title("Выбор аудиоустройств")
        geometry = self.gui_config.get('selector_geometry', '500x350')
        try: self.geometry(geometry)
        except Exception as e: logging.warning(f"Некорректная геометрия для AudioSelector в конфиге ('{geometry}'): {e}. Используется 500x350."); self.geometry("500x350")
        self.resizable(False, False)
        self.input_device_index = None
        self.output_device_index = None
        self.create_widgets()
        self.bind("<Escape>", lambda e: self.destroy())

    def create_widgets(self):
        ctk.CTkLabel(self, text="Выберите микрофон:", font=("Arial", 14)).pack(pady=10)
        input_devices = self.get_device_list(input=True)
        self.input_combo = ctk.CTkComboBox(self, values=input_devices, width=400)
        if input_devices: self.input_combo.set(input_devices[0])
        else: logging.warning("Не найдено ни одного устройства ввода.")
        self.input_combo.pack()
        ctk.CTkLabel(self, text="Выберите устройство вывода:", font=("Arial", 14)).pack(pady=20)
        output_devices = self.get_device_list(output=True)
        self.output_combo = ctk.CTkComboBox(self, values=output_devices, width=400)
        if output_devices: self.output_combo.set(output_devices[0])
        else: logging.warning("Не найдено ни одного устройства вывода.")
        self.output_combo.pack()
        ctk.CTkButton(self, text="Продолжить", command=self.validate_and_launch).pack(pady=30)
        self.error_label = ctk.CTkLabel(self, text="", text_color="red", font=("Arial", 12))
        self.error_label.pack(pady=(0, 10))
        self.after(100, lambda: self.focus_force())

    def get_device_list(self, input=False, output=False):
        try:
            devices = sd.query_devices()
            device_list = []
            for i, dev in enumerate(devices):
                if not dev or not isinstance(dev, dict) or not dev.get('name'): logging.warning(f"Пропущено некорректное устройство с индексом {i}: {dev}"); continue
                is_input = dev.get('max_input_channels', 0) > 0
                is_output = dev.get('max_output_channels', 0) > 0
                if (input and is_input) or (output and is_output):
                     try: device_list.append(f"{i}: {dev['name']}")
                     except Exception as enc_e: logging.warning(f"Проблема с именем устройства {i}: {dev.get('name')}. Ошибка: {enc_e}. Пропускаем.")
            logging.info(f"Найдено устройств {'ввода' if input else 'вывода'}: {len(device_list)}")
            return device_list
        except sd.PortAudioError as e: logging.exception("Ошибка PortAudio при получении списка устройств"); self._update_error_label(f"Ошибка чтения устройств: {e}"); return []
        except Exception as e: logging.exception("Неожиданная ошибка при получении списка устройств"); self._update_error_label("Критическая ошибка чтения устройств!"); return []

    def _update_error_label(self, text):
         """Безопасное обновление метки ошибки."""
         if hasattr(self, 'error_label') and self.error_label.winfo_exists():
              self.error_label.configure(text=text)

    def validate_and_launch(self):
        input_selection = self.input_combo.get()
        output_selection = self.output_combo.get()
        try:
            if not input_selection or not output_selection: raise ValueError("Не выбрано одно или оба устройства.")
            if not ":" in input_selection or not ":" in output_selection: raise ValueError("Некорректный формат выбранного устройства.")
            self.input_device_index = int(input_selection.split(":")[0])
            self.output_device_index = int(output_selection.split(":")[0])
            logging.info(f"Выбраны устройства: Ввод={self.input_device_index} ('{input_selection}'), Вывод={self.output_device_index} ('{output_selection}')")
            global config
            audio_cfg = config.get('audio', {})
            rate = audio_cfg.get('sample_rate', 48000); chans = audio_cfg.get('channels', 1); dtype = audio_cfg.get('dtype', 'int16')
            try:
                 logging.debug(f"Проверка настроек ввода: dev={self.input_device_index}, rate={rate}, chans={chans}, dtype={dtype}")
                 sd.check_input_settings(device=self.input_device_index, channels=chans, samplerate=rate, dtype=dtype)
                 logging.debug(f"Проверка настроек вывода: dev={self.output_device_index}, rate={rate}, chans={chans}, dtype={dtype}")
                 sd.check_output_settings(device=self.output_device_index, channels=chans, samplerate=rate, dtype=dtype)
                 logging.info("Настройки аудиоустройств успешно проверены.")
            except sd.PortAudioError as pa_err: logging.error(f"Ошибка проверки настроек PortAudio: {pa_err}"); raise ValueError(f"Устройство не поддерживает настройки ({rate}Hz, {chans}ch, {dtype}): {pa_err}")
            except ValueError as val_err: logging.error(f"Ошибка проверки настроек sounddevice (ValueError): {val_err}"); raise ValueError(f"Некорректный индекс устройства или ошибка: {val_err}")
            except Exception as e: logging.exception("Ошибка проверки настроек sounddevice"); raise ValueError(f"Ошибка проверки устройства: {e}")
            self._update_error_label("")
            self.destroy()
            # *** ИЗМЕНЕНИЕ: Передаем user_config в VoxShareGUI ***
            main_app = VoxShareGUI(
                input_device_index=self.input_device_index,
                output_device_index=self.output_device_index,
                user_config=config.get('user', {}), # <--- Добавлено
                gui_config=self.gui_config,
                net_config=config.get('network',{}),
                audio_config=config.get('audio',{})
                )
            # ****************************************************
            main_app.mainloop()
        except (ValueError, AttributeError, IndexError) as e: error_message = f"Ошибка выбора: {e}"; logging.warning(f"Ошибка валидации выбора устройств: {e}"); self._update_error_label(error_message)
        except Exception as e: logging.exception("Неожиданная ошибка при валидации и запуске"); self._update_error_label("Произошла критическая ошибка!")

# --- Основное GUI Приложения ---
class VoxShareGUI(ctk.CTk):
    # *** ИЗМЕНЕНИЕ: Принимает user_config ***
    def __init__(self, input_device_index, output_device_index, user_config, gui_config, net_config, audio_config):
        super().__init__()
        self.user_config = user_config # <--- Сохраняем
        self.gui_config = gui_config
        self.net_config = net_config
        self.audio_config = audio_config
        # ------------------------------------
        self.title("VoxShare")
        geometry = self.gui_config.get('main_geometry', '550x450')
        try: self.geometry(geometry)
        except Exception as e: logging.warning(f"Некорректная геометрия для VoxShareGUI в конфиге ('{geometry}'): {e}. Используется 550x450."); self.geometry("550x450")
        self.resizable(False, False)
        self.input_device_index = input_device_index
        self.output_device_index = output_device_index
        self.is_pressing = False
        self.volume = 0.0
        self.volume_lock = Lock()
        self.currently_speaking_ip = None
        self.last_packet_played_time = 0
        self.speaker_lock = Lock()
        try:
             # *** ИЗМЕНЕНИЕ: Передаем user_config в AudioTransceiver ***
            self.audio_transceiver = AudioTransceiver(
                user_config=self.user_config, # <--- Передаем
                net_config=self.net_config,
                audio_config=self.audio_config
                )
            # **********************************************************
        except RuntimeError as e: logging.exception("Критическая ошибка при инициализации AudioTransceiver"); self.destroy(); return
        except Exception as e: logging.exception("Неожиданная критическая ошибка при инициализации AudioTransceiver"); self.destroy(); return
        self.setup_gui()
        self.start_threads()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        logging.info("Основное окно VoxShareGUI инициализировано.")

    # --- setup_gui, start_threads, audio_input_thread, audio_output_thread (без изменений) ---
    def setup_gui(self):
        """Настройка графического интерфейса"""
        top_frame = ctk.CTkFrame(self, fg_color="transparent"); top_frame.pack(pady=10, padx=10, fill="x")
        ctk.CTkLabel(top_frame, text="VoxShare", font=("Arial", 24)).pack()
        middle_frame = ctk.CTkFrame(self, fg_color="transparent"); middle_frame.pack(pady=10, padx=10, fill="both", expand=True)
        try:
            logo_path = resource_path(os.path.join("images", "logo.png"))
            img = Image.open(logo_path).resize((150, 150), Image.Resampling.LANCZOS)
            self.logo_img = ctk.CTkImage(light_image=img, dark_image=img, size=(150, 150))
            logo_widget = ctk.CTkLabel(middle_frame, image=self.logo_img, text=""); logging.debug("Логотип logo.png загружен.")
        except FileNotFoundError: logging.warning("Файл logo.png не найден."); self.logo_img = None; logo_widget = ctk.CTkLabel(middle_frame, text="[Лого]", width=150, height=150, fg_color="grey")
        except Exception as e: logging.warning(f"Не удалось загрузить или обработать logo.png: {e}"); self.logo_img = None; logo_widget = ctk.CTkLabel(middle_frame, text="[Лого Ошибка]", width=150, height=150, fg_color="grey")
        logo_widget.pack(side="left", padx=(0, 20), anchor="n")
        peer_list_frame = ctk.CTkFrame(middle_frame); peer_list_frame.pack(side="left", fill="both", expand=True)
        ctk.CTkLabel(peer_list_frame, text="Участники:", font=("Arial", 14)).pack(anchor="w", padx=5)
        self.peer_list_textbox = ctk.CTkTextbox(peer_list_frame, font=("Arial", 12), wrap="none")
        self.peer_list_textbox.pack(side="top", fill="both", expand=True, padx=5, pady=(0,5)); self.peer_list_textbox.configure(state="disabled")
        bottom_frame = ctk.CTkFrame(self, fg_color="transparent"); bottom_frame.pack(side="bottom", pady=10, padx=10, fill="x")
        bottom_frame.columnconfigure(0, weight=1)
        self.led = ctk.CTkLabel(bottom_frame, text="", width=30, height=30, corner_radius=15, fg_color="#D50000"); self.led.grid(row=0, column=0, padx=10, pady=(5, 2))
        self.volume_bar = ctk.CTkProgressBar(bottom_frame, height=20); self.volume_bar.set(0); self.volume_bar.grid(row=1, column=0, padx=50, pady=2, sticky="ew")
        self.talk_btn = ctk.CTkButton(bottom_frame, text="Говорить", height=40, font=("Arial", 16)); self.talk_btn.grid(row=2, column=0, padx=50, pady=(5, 5), sticky="ew")
        self.talk_btn.bind("<ButtonPress-1>", self.on_press); self.talk_btn.bind("<ButtonRelease-1>", self.on_release)
        self.bind("<KeyPress-space>", self.on_press); self.bind("<KeyRelease-space>", self.on_release)
        self.bind("<Button-1>", lambda event: self.focus_set())
        logging.debug("Элементы GUI основного окна созданы и размещены.")
        self.after(100, lambda: self.focus_force())

    def start_threads(self):
        """Запуск рабочих потоков"""
        if not hasattr(self, 'audio_transceiver') or not self.audio_transceiver: logging.error("Ошибка: audio_transceiver не инициализирован, потоки не запускаются."); return
        logging.info("Запуск рабочих потоков...")
        self.input_thread = threading.Thread(target=self.audio_input_thread, name="AudioInputThread", daemon=True)
        self.output_thread = threading.Thread(target=self.audio_output_thread, name="AudioOutputThread", daemon=True)
        self.receive_thread = threading.Thread(target=self.receive_thread, name="ReceiveThread", daemon=True)
        self.ping_thread = threading.Thread(target=self.ping_thread, name="PingThread", daemon=True)
        self.cleanup_thread = threading.Thread(target=self.client_cleanup_thread, name="ClientCleanupThread", daemon=True)
        self.input_thread.start(); self.output_thread.start(); self.receive_thread.start(); self.ping_thread.start(); self.cleanup_thread.start()
        self.after(100, self.update_gui); logging.info("Все рабочие потоки запущены.")

    def audio_input_thread(self):
        """Поток для захвата аудио, кодирования и отправки"""
        sample_rate = self.audio_transceiver.sample_rate; channels = self.audio_transceiver.channels; blocksize = self.audio_transceiver.block_size; dtype = self.audio_transceiver.dtype
        def callback(indata: np.ndarray, frames: int, time_info, status: sd.CallbackFlags):
            if status: logging.warning(f"Статус обратного вызова ввода: {status}")
            if not self.audio_transceiver.shutdown_event.is_set() and self.is_pressing:
                try:
                    pcm_data_bytes = indata.tobytes(); self.audio_transceiver.encode_and_send_audio(pcm_data_bytes)
                    float_data = indata.astype(np.float32) / 32768.0; rms = np.sqrt(np.mean(np.square(float_data)))
                    with self.volume_lock: self.volume = float(rms) * 2.5
                except Exception as e: logging.exception(f"Ошибка в audio_input callback во время передачи")
            else:
                 if not self.is_pressing or self.audio_transceiver.shutdown_event.is_set():
                     with self.volume_lock:
                         self.volume = 0.0
        try:
            logging.info(f"Открытие InputStream: Устройство={self.input_device_index}, Rate={sample_rate}, Block={blocksize}, Dtype={dtype}")
            with sd.InputStream(samplerate=sample_rate, channels=channels, dtype=dtype, callback=callback, blocksize=blocksize, device=self.input_device_index):
                logging.info("InputStream открыт. Ожидание сигнала завершения...")
                self.audio_transceiver.shutdown_event.wait()
        except sd.PortAudioError as e: logging.exception(f"Критическая ошибка аудио входа (PortAudioError) Устройство={self.input_device_index}")
        except Exception as e: logging.exception(f"Критическая ошибка аудио входа (Другое) Устройство={self.input_device_index}")
        logging.info("Поток аудио входа завершается.")

    def audio_output_thread(self):
        """Поток для получения декодированного аудио и воспроизведения"""
        sample_rate = self.audio_transceiver.sample_rate; channels = self.audio_transceiver.channels; blocksize = self.audio_transceiver.block_size; dtype = self.audio_transceiver.dtype
        def callback(outdata: np.ndarray, frames: int, time_info, status: sd.CallbackFlags):
            if status: logging.warning(f"Статус обратного вызова вывода: {status}")
            packet_info = self.audio_transceiver.get_decoded_audio_packet(); processed_ip = None
            if packet_info is not None:
                sender_ip, audio_data = packet_info
                if audio_data is not None and audio_data.size == frames * channels: outdata[:] = audio_data.reshape(-1, channels); processed_ip = sender_ip; logging.debug(f"Воспроизведен аудио пакет {len(audio_data)} сэмплов от {sender_ip}")
                else: outdata.fill(0); logging.warning(f"Размер пакета от {sender_ip} не совпал ({audio_data.size} vs {frames * channels}), воспроизведена тишина.") if audio_data is not None else None
            else: outdata.fill(0)
            if not self.audio_transceiver.shutdown_event.is_set():
                with self.speaker_lock:
                    if processed_ip: self.currently_speaking_ip = processed_ip; self.last_packet_played_time = time.time()
        try:
            logging.info(f"Открытие OutputStream: Устройство={self.output_device_index}, Rate={sample_rate}, Block={blocksize}, Dtype={dtype}")
            with sd.OutputStream(samplerate=sample_rate, channels=channels, dtype=dtype, callback=callback, blocksize=blocksize, device=self.output_device_index):
                logging.info("OutputStream открыт. Ожидание сигнала завершения...")
                self.audio_transceiver.shutdown_event.wait()
        except sd.PortAudioError as e: logging.exception(f"Критическая ошибка аудио выхода (PortAudioError) Устройство={self.output_device_index}")
        except Exception as e: logging.exception(f"Критическая ошибка аудио выхода (Другое) Устройство={self.output_device_index}")
        logging.info("Поток аудио вывода завершается.")

    # --- receive_thread, ping_thread, client_cleanup_thread (без изменений) ---
    def receive_thread(self):
        if hasattr(self, 'audio_transceiver') and self.audio_transceiver: self.audio_transceiver.receive_packets()
        else: logging.error("ReceiveThread: audio_transceiver не существует.")

    def ping_thread(self):
        logging.info("Поток отправки пингов запущен.")
        if not hasattr(self, 'audio_transceiver') or not self.audio_transceiver: logging.error("PingThread: audio_transceiver не существует."); return
        ping_interval = self.net_config.get('ping_interval_sec', 2)
        while not self.audio_transceiver.shutdown_event.wait(timeout=ping_interval):
            self.audio_transceiver.send_ping()
        logging.info("Поток отправки пингов завершается.")

    def client_cleanup_thread(self):
        logging.info("Поток очистки клиентов запущен.")
        if not hasattr(self, 'audio_transceiver') or not self.audio_transceiver: logging.error("ClientCleanupThread: audio_transceiver не существует."); return
        cleanup_interval = 1.0
        while not self.audio_transceiver.shutdown_event.wait(timeout=cleanup_interval):
            self.audio_transceiver.cleanup_inactive_clients()
        logging.info("Поток очистки клиентов завершается.")


    def update_gui(self):
        """Обновление GUI (вызывается в основном потоке)"""
        try:
            if not self.winfo_exists() or not hasattr(self, 'audio_transceiver') or not self.audio_transceiver: return
            # Обновление громкости
            if hasattr(self, 'volume_bar') and self.volume_bar.winfo_exists():
                with self.volume_lock: current_volume = min(1.0, max(0.0, self.volume))
                self.volume_bar.set(current_volume)

            # --- ИЗМЕНЕНИЕ: Обновление списка пиров с никнеймами ---
            active_peers_data = {} # Словарь {ip: nickname}
            current_speaker = None
            now = time.time()

            try:
                # Получаем копию словаря клиентов под блокировкой
                with self.audio_transceiver.clients_lock:
                    active_peers_data = self.audio_transceiver.active_clients.copy()
            except AttributeError:
                 logging.warning("update_gui: audio_transceiver не найден при доступе к clients_lock.")
                 return

            # Определяем говорящего и проверяем таймаут/активность
            with self.speaker_lock:
                if self.currently_speaking_ip and (now - self.last_packet_played_time > SPEAKER_TIMEOUT_THRESHOLD):
                    logging.debug(f"Сброс статуса говорящего для {self.currently_speaking_ip} по таймауту.")
                    self.currently_speaking_ip = None
                # Проверяем, что говорящий еще активен (есть в словаре)
                if self.currently_speaking_ip and self.currently_speaking_ip not in active_peers_data:
                     logging.debug(f"Говорящий {self.currently_speaking_ip} больше не в списке активных пиров.")
                     self.currently_speaking_ip = None
                current_speaker = self.currently_speaking_ip

            # Обновляем текстовое поле
            if hasattr(self, 'peer_list_textbox') and self.peer_list_textbox.winfo_exists():
                try:
                     self.peer_list_textbox.configure(state="normal")
                     self.peer_list_textbox.delete("1.0", "end")

                     # Сортируем IP адреса для стабильного отображения
                     sorted_ips = sorted(active_peers_data.keys())

                     if sorted_ips:
                         for peer_ip in sorted_ips:
                             info = active_peers_data.get(peer_ip, {})
                             nickname = info.get('nickname', '')
                             display_name = nickname if nickname else peer_ip # Используем ник, если есть, иначе IP
                             prefix = "* " if peer_ip == current_speaker else "  "
                             self.peer_list_textbox.insert("end", f"{prefix}{display_name}\n")
                     else:
                         self.peer_list_textbox.insert("end", " (нет других участников)")

                     self.peer_list_textbox.configure(state="disabled")
                except tkinter.TclError as e:
                     logging.warning(f"Ошибка обновления peer_list_textbox (возможно, виджет уничтожен): {e}")
            # ------------------------------------------------------

            # Планируем следующее обновление
            if hasattr(self, 'audio_transceiver') and not self.audio_transceiver.shutdown_event.is_set():
                 self.after(100, self.update_gui)
        except Exception as e: logging.exception("Неожиданная ошибка в update_gui")

    # --- on_press, on_release, update_led, on_closing (без изменений) ---
    def on_press(self, event=None):
        if not self.is_pressing:
            logging.info("Начало передачи (кнопка/пробел нажат)")
            self.is_pressing = True
            self.update_led(True)
            if hasattr(self, 'talk_btn') and self.talk_btn.winfo_exists(): self.talk_btn.configure(fg_color="#00A853")

    def on_release(self, event=None):
        if self.is_pressing:
            logging.info("Остановка передачи (кнопка/пробел отпущен)")
            self.is_pressing = False
            self.update_led(False)
            if hasattr(self, 'talk_btn') and self.talk_btn.winfo_exists():
                try: std_color = ctk.ThemeManager.theme["CTkButton"]["fg_color"]
                except KeyError: std_color = ("#3a7ebf", "#1f538d")
                self.talk_btn.configure(fg_color=std_color)
            with self.volume_lock: self.volume = 0.0
            if hasattr(self, 'volume_bar') and self.volume_bar.winfo_exists(): self.volume_bar.set(0.0)

    def update_led(self, on):
        color = "#00C853" if on else "#D50000"
        if hasattr(self, 'led') and self.led.winfo_exists(): self.led.configure(fg_color=color); logging.debug(f"LED индикатор установлен в {'ON' if on else 'OFF'}")

    def on_closing(self):
        """Обработчик закрытия окна"""
        logging.info("Получен сигнал закрытия окна (WM_DELETE_WINDOW).")
        if hasattr(self, 'audio_transceiver') and self.audio_transceiver: self.audio_transceiver.cleanup()
        logging.info("Уничтожение окна GUI...")
        try:
             self.unbind("<KeyPress-space>"); self.unbind("<KeyRelease-space>"); self.unbind("<Button-1>")
             self.destroy()
        except Exception as e: logging.exception("Ошибка при уничтожении главного окна")
        logging.info("Приложение завершило работу.")


# --- Точка входа ---
if __name__ == "__main__":
    load_config()
    setup_logging()
    try:
        gui_conf = config.get('gui', {})
        appearance_mode = gui_conf.get('appearance_mode', 'dark').lower()
        if appearance_mode not in ['dark', 'light', 'system']: logging.warning(f"Некорректный режим темы '{appearance_mode}' в конфиге. Используется 'dark'."); appearance_mode = 'dark'
        ctk.set_appearance_mode(appearance_mode)
        logging.info(f"Установлена тема интерфейса: {appearance_mode}")
    except Exception as e: logging.exception("Ошибка при установке темы интерфейса из конфига."); ctk.set_appearance_mode("dark")
    try:
        if not hasattr(opuslib, 'Encoder'): raise ImportError("opuslib не содержит ожидаемых атрибутов.")
        logging.info(f"Библиотека opuslib найдена и импортирована.")
    except ImportError: message = "Критическая ошибка: Библиотека opuslib не найдена. Установите ее: pip install opuslib"; print(message); logging.critical(message); sys.exit(1)
    except Exception as e: message = f"Неожиданная ошибка при проверке opuslib: {e}"; print(message); logging.critical(message); sys.exit(1)
    try:
        # Передаем только gui часть конфига в селектор
        selector = AudioSelector(gui_config=config.get('gui', {}))
        # Главный цикл селектора запустит основное окно, если выбор успешен
        selector.mainloop()
    except Exception as e: logging.exception("Критическая необработанная ошибка на верхнем уровне"); sys.exit(1)
    logging.info("="*20 + " Приложение штатно завершено " + "="*20)
    print("Приложение завершено.")