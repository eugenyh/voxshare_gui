import customtkinter as ctk
import sounddevice as sd
import socket
import threading
import numpy as np
from PIL import Image, ImageTk
import struct
import time
# import os # Не используется, можно удалить
import queue
# from queue import Queue # Избыточный импорт, используем 'import queue'
from threading import Event
import opuslib # <--- Добавлено для Opus

# --- Константы ---
MCAST_GRP = "239.255.42.99"
PORT = 5005
TTL = 1
# Увеличим буфер сокета, т.к. максимальный размер Opus пакета может быть больше
SOCKET_BUFFER_SIZE = 65536 # Увеличено
# Буфер для декодированных пакетов перед воспроизведением
PLAYBACK_QUEUE_SIZE = 20 # Количество декодированных аудио пакетов в очереди воспроизведения
PING_INTERVAL = 2
CLIENT_TIMEOUT = 5

# --- Аудио настройки ---
SAMPLE_RATE = 48000
CHANNELS = 1
# Размер блока для sounddevice и Opus (Opus поддерживает: 2.5, 5, 10, 20, 40, 60 ms)
# 48000 * 0.020 = 960 - хороший выбор (20ms)
BLOCKSIZE = 960 # Количество сэмплов на канал в блоке
DTYPE = 'int16'
OPUS_APPLICATION = opuslib.APPLICATION_VOIP # Тип приложения для Opus

# --- Типы пакетов ---
PACKET_TYPE_AUDIO = b"AUD"
PACKET_TYPE_PING = b"PING"

# --- Класс для работы с сетью и Opus ---
class AudioTransceiver:
    def __init__(self):
        self.local_ip = socket.gethostbyname(socket.gethostname())
        self.active_clients = {}
        self.clients_lock = threading.Lock() # <--- Добавлена блокировка для active_clients
        # Очередь для полученных *закодированных* Opus пакетов
        self.received_opus_packets = queue.Queue(maxsize=PLAYBACK_QUEUE_SIZE * 2) # Немного больше для буферизации сети
        self.shutdown_event = Event()

        # Инициализация Opus кодера и декодера
        try:
            self.encoder = opuslib.Encoder(SAMPLE_RATE, CHANNELS, OPUS_APPLICATION)
            self.decoder = opuslib.Decoder(SAMPLE_RATE, CHANNELS)
            print("Opus кодер и декодер инициализированы.")
        except opuslib.OpusError as e:
            raise RuntimeError(f"Ошибка инициализации Opus: {e}")

        # Инициализация сокетов
        self.init_sockets()

    def init_sockets(self):
        """Инициализация multicast сокетов"""
        try:
            self.sock_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock_send.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, TTL)

            self.sock_recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock_recv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Увеличиваем буфер приема сокета
            self.sock_recv.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_BUFFER_SIZE)
            self.sock_recv.bind(("", PORT))
            mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
            self.sock_recv.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            print("Сокеты инициализированы.")
        except socket.error as e:
            raise RuntimeError(f"Ошибка инициализации сокетов: {e}")

    def cleanup(self):
        """Очистка ресурсов"""
        print("Начало очистки ресурсов...")
        self.shutdown_event.set()
        # Даем потокам немного времени на завершение
        time.sleep(0.2)
        if hasattr(self, 'sock_send'):
            self.sock_send.close()
            print("Сокет отправки закрыт.")
        if hasattr(self, 'sock_recv'):
             # Попытка покинуть группу мультикаст перед закрытием
            try:
                mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
                self.sock_recv.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
                print("Покинута multicast группа.")
            except socket.error as e:
                print(f"Предупреждение: Не удалось покинуть multicast группу: {e}")
            self.sock_recv.close()
            print("Сокет приема закрыт.")
        print("Очистка завершена.")


    def encode_and_send_audio(self, pcm_data_bytes):
        """Кодирование PCM данных в Opus и отправка"""
        try:
            # Кодируем PCM данные. BLOCKSIZE - это количество сэмплов на канал.
            encoded_data = self.encoder.encode(pcm_data_bytes, BLOCKSIZE)
            # Отправляем пакет: ТИП + ЗАКОДИРОВАННЫЕ ДАННЫЕ
            self.sock_send.sendto(PACKET_TYPE_AUDIO + encoded_data, (MCAST_GRP, PORT))
        except opuslib.OpusError as e:
            print(f"Ошибка кодирования Opus: {e}")
        except socket.error as e:
            print(f"Ошибка отправки аудио: {e}")
        except Exception as e:
            print(f"Неожиданная ошибка при кодировании/отправке: {e}")


    def send_ping(self):
        """Отправка ping-пакета"""
        try:
            self.sock_send.sendto(PACKET_TYPE_PING, (MCAST_GRP, PORT))
        except socket.error as e:
            # Не печатаем ошибку если сокет уже закрывается
            if not self.shutdown_event.is_set():
                 print(f"Ошибка отправки ping: {e}")


    def receive_packets(self):
        """Получение пакетов в цикле"""
        while not self.shutdown_event.is_set():
            try:
                # Используем увеличенный буфер сокета
                data, addr = self.sock_recv.recvfrom(SOCKET_BUFFER_SIZE)

                # Пропускаем пакеты от себя (простая проверка по IP)
                if addr[0] == self.local_ip:
                    continue

                # Обработка аудио пакета
                if data.startswith(PACKET_TYPE_AUDIO):
                    opus_packet = data[len(PACKET_TYPE_AUDIO):]
                    try:
                        # Кладем *закодированный* пакет в очередь
                        self.received_opus_packets.put_nowait(opus_packet)
                    except queue.Full:
                        # Отбрасываем самый старый пакет, чтобы освободить место
                        try:
                            self.received_opus_packets.get_nowait()
                            self.received_opus_packets.put_nowait(opus_packet)
                            # print("Предупреждение: Очередь полученных пакетов была полна, старый пакет отброшен.")
                        except queue.Empty:
                            pass # Очередь уже пуста, странно, но игнорируем
                        except queue.Full:
                            pass # Не удалось добавить даже после удаления, пропускаем

                # Обработка пинг пакета
                elif data.startswith(PACKET_TYPE_PING):
                    with self.clients_lock: # <--- Блокировка доступа
                        self.active_clients[addr[0]] = time.time()

            except socket.timeout: # Если установлен таймаут на сокете (здесь не установлен)
                 continue
            except socket.error as e:
                # Не печатаем ошибку если сокет закрывается штатно
                if not self.shutdown_event.is_set():
                    print(f"Ошибка получения пакета: {e}")
                    time.sleep(0.1) # Небольшая пауза при ошибке
            except Exception as e:
                 if not self.shutdown_event.is_set():
                    print(f"Неожиданная ошибка в receive_packets: {e}")


    def decode_audio(self, opus_packet):
        """Декодирование Opus пакета в PCM"""
        try:
            # Декодируем Opus пакет. BLOCKSIZE - ожидаемое количество сэмплов на выходе.
            pcm_data = self.decoder.decode(opus_packet, BLOCKSIZE)
            return pcm_data
        except opuslib.OpusError as e:
            print(f"Ошибка декодирования Opus: {e}")
            return None # Возвращаем None при ошибке декодирования


    def get_decoded_audio_packet(self):
        """Извлекает Opus пакет из очереди и декодирует его"""
        try:
            opus_packet = self.received_opus_packets.get_nowait()
            decoded_pcm = self.decode_audio(opus_packet)
            if decoded_pcm:
                 # Конвертируем декодированные байты в numpy массив нужного типа
                 audio_data = np.frombuffer(decoded_pcm, dtype=DTYPE)
                 # Проверяем, соответствует ли размер ожидаемому
                 if audio_data.size == BLOCKSIZE * CHANNELS:
                     return audio_data
                 else:
                     print(f"Предупреждение: Неожиданный размер декодированного пакета ({audio_data.size} вместо {BLOCKSIZE * CHANNELS})")
                     return None
            else:
                return None # Ошибка декодирования
        except queue.Empty:
            return None # Очередь пуста


    def cleanup_inactive_clients(self):
        """Очистка неактивных клиентов"""
        current_time = time.time()
        inactive = []
        # Используем блокировку при доступе к словарю
        with self.clients_lock:
            inactive = [ip for ip, last_seen in self.active_clients.items()
                        if current_time - last_seen > CLIENT_TIMEOUT]

        if inactive:
            with self.clients_lock:
                for ip in inactive:
                    # Дополнительная проверка перед удалением
                    if ip in self.active_clients and current_time - self.active_clients[ip] > CLIENT_TIMEOUT:
                        print(f"Удаляем неактивного клиента: {ip}")
                        del self.active_clients[ip]

# --- GUI Выбора устройств ---
class AudioSelector(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Выбор аудиоустройств")
        self.geometry("500x350") # Немного увеличим высоту для метки ошибки
        self.resizable(False, False)
        ctk.set_appearance_mode("dark")

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
        self.input_combo.pack()

        ctk.CTkLabel(self, text="Выберите устройство вывода:", font=("Arial", 14)).pack(pady=20)
        output_devices = self.get_device_list(output=True)
        self.output_combo = ctk.CTkComboBox(self, values=output_devices, width=400)
        if output_devices:
            self.output_combo.set(output_devices[0]) # Установить значение по умолчанию, если есть
        self.output_combo.pack()

        ctk.CTkButton(self, text="Продолжить", command=self.validate_and_launch).pack(pady=30)

        # Метка для вывода ошибок валидации
        self.error_label = ctk.CTkLabel(self, text="", text_color="red", font=("Arial", 12))
        self.error_label.pack(pady=(0, 10))


    def get_device_list(self, input=False, output=False):
        """Получение списка аудиоустройств"""
        try:
            devices = sd.query_devices()
            # Добавим проверку на None для имени устройства
            return [f"{i}: {dev['name']}" for i, dev in enumerate(devices)
                    if dev and dev['name'] and (
                        (input and dev['max_input_channels'] > 0) or
                        (output and dev['max_output_channels'] > 0)
                    )]
        except Exception as e: # Ловим более общую ошибку на всякий случай
            print(f"Ошибка получения списка устройств: {e}")
            # Попытка сообщить пользователю через GUI, если окно уже создано
            if hasattr(self, 'error_label'):
                self.error_label.configure(text=f"Ошибка чтения устройств: {e}")
            return []

    def validate_and_launch(self):
        """Проверка выбора устройств и запуск основного окна"""
        input_selection = self.input_combo.get()
        output_selection = self.output_combo.get()

        try:
            if not input_selection or not output_selection:
                 raise ValueError("Не выбрано одно из устройств.")

            self.input_device_index = int(input_selection.split(":")[0])
            self.output_device_index = int(output_selection.split(":")[0])

            # Дополнительная проверка существования устройств с выбранными индексами
            # (на случай, если список изменился с момента загрузки)
            try:
                 sd.check_input_settings(device=self.input_device_index, channels=CHANNELS, samplerate=SAMPLE_RATE)
                 sd.check_output_settings(device=self.output_device_index, channels=CHANNELS, samplerate=SAMPLE_RATE)
            except sd.PortAudioError as pa_err:
                 raise ValueError(f"Некорректные настройки устройства: {pa_err}")

            self.error_label.configure(text="") # Очистить ошибку при успехе
            self.destroy() # Закрыть окно выбора
            # Запустить основное окно
            main_app = VoxShareGUI(self.input_device_index, self.output_device_index)
            main_app.mainloop()

        except (ValueError, AttributeError, IndexError) as e:
            error_message = f"Ошибка выбора: {e}" if isinstance(e, ValueError) else "Пожалуйста, выберите оба устройства из списка!"
            self.error_label.configure(text=error_message)
        except Exception as e: # Общая ошибка
             self.error_label.configure(text=f"Произошла ошибка: {e}")


# --- Основное GUI Приложения ---
class VoxShareGUI(ctk.CTk):
    def __init__(self, input_device_index, output_device_index):
        super().__init__()
        self.title("VoxShare")
        self.geometry("400x500")
        self.resizable(False, False)
        ctk.set_appearance_mode("dark")

        self.input_device_index = input_device_index
        self.output_device_index = output_device_index
        self.is_pressing = False
        self.volume = 0.0
        self.volume_lock = threading.Lock()

        # Создаем экземпляр AudioTransceiver
        try:
            self.audio_transceiver = AudioTransceiver()
        except RuntimeError as e:
             # Показать критическую ошибку пользователю и завершить работу
             print(f"Критическая ошибка при инициализации: {e}")
             # Можно показать окно с сообщением об ошибке перед выходом
             # import tkinter.messagebox as messagebox
             # messagebox.showerror("Критическая ошибка", str(e))
             self.destroy() # Закрыть окно, если оно успело создаться
             return # Прервать инициализацию

        self.setup_gui()
        self.start_threads()

        # *** ИСПРАВЛЕНИЕ: Привязка метода очистки к закрытию окна ***
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        print("Обработчик закрытия окна установлен.")

    def setup_gui(self):
        """Настройка графического интерфейса"""
        ctk.CTkLabel(self, text="VoxShare", font=("Arial", 24)).pack(pady=20)

        # Логотип с обработкой ошибок
        try:
            # Убедитесь, что файл logo.png находится в той же директории
            # или укажите полный путь
            img = Image.open("logo.png").resize((150, 150), Image.Resampling.LANCZOS)
            # CTkImage требует light_image и dark_image, можно использовать одно и то же
            self.logo_img = ctk.CTkImage(light_image=img, dark_image=img, size=(150, 150))
            logo_label = ctk.CTkLabel(self, image=self.logo_img, text="")
        except (FileNotFoundError, IOError, Exception) as e:
            print(f"Предупреждение: Не удалось загрузить logo.png: {e}")
            self.logo_img = None # Явно указываем, что лого нет
            logo_label = ctk.CTkLabel(self, text="[Лого]", width=150, height=150) # Заглушка

        # Кнопка теперь использует logo_label как основу, если лого нет
        self.talk_btn = ctk.CTkButton(
            self, image=self.logo_img if self.logo_img else None, # Используем лого если есть
            text="" if self.logo_img else "ГОВОРИТЬ", # Текст если нет лого
            width=160, height=160,
            corner_radius=80, fg_color="#444", hover_color="#555"
        )
        self.talk_btn.pack(pady=30)
        self.talk_btn.bind("<ButtonPress-1>", self.on_press)
        self.talk_btn.bind("<ButtonRelease-1>", self.on_release)

        # LED индикатор
        self.led = ctk.CTkLabel(self, text="", width=30, height=30, corner_radius=15, fg_color="#880000")
        self.led.pack(pady=10)
        # self.update_led(False) # Начальное состояние уже установлено в fg_color

        # Индикатор громкости
        self.volume_bar = ctk.CTkProgressBar(self, width=200, height=20)
        self.volume_bar.set(0)
        self.volume_bar.pack(pady=20)


    def start_threads(self):
        """Запуск рабочих потоков"""
        # Проверяем, был ли audio_transceiver успешно создан
        if not hasattr(self, 'audio_transceiver'):
             print("Ошибка: audio_transceiver не инициализирован, потоки не запускаются.")
             return

        print("Запуск потоков...")
        # Поток захвата и кодирования аудио
        self.input_thread = threading.Thread(target=self.audio_input_thread, daemon=True)
        self.input_thread.start()

        # Поток декодирования и воспроизведения аудио
        self.output_thread = threading.Thread(target=self.audio_output_thread, daemon=True)
        self.output_thread.start()

        # Поток приема сетевых пакетов
        self.receive_thread = threading.Thread(target=self.receive_thread, daemon=True)
        self.receive_thread.start()

        # Поток отправки пингов
        self.ping_thread = threading.Thread(target=self.ping_thread, daemon=True)
        self.ping_thread.start()

        # Поток очистки неактивных клиентов
        self.cleanup_thread = threading.Thread(target=self.client_cleanup_thread, daemon=True)
        self.cleanup_thread.start()

        # Запуск обновления GUI в основном потоке
        self.after(100, self.update_gui)
        print("Потоки запущены.")


    def audio_input_thread(self):
        """Поток для захвата аудио, кодирования и отправки"""
        def callback(indata: np.ndarray, frames: int, time_info, status: sd.CallbackFlags):
            if status:
                print(f"Ошибка ввода аудио (callback): {status}")
            if self.is_pressing and not self.audio_transceiver.shutdown_event.is_set():
                try:
                    # Конвертируем numpy массив в байты
                    pcm_data_bytes = indata.tobytes()
                    # Кодируем и отправляем через transceiver
                    self.audio_transceiver.encode_and_send_audio(pcm_data_bytes)

                    # Обновляем индикатор громкости (остается локальным)
                    rms = np.sqrt(np.mean(np.square(indata.astype(np.float32) / 32768.0))) # Нормализуем перед RMS
                    with self.volume_lock:
                         # Уменьшим множитель, т.к. RMS теперь 0-1
                        self.volume = float(rms) * 2.0 # Усиление для видимости
                except Exception as e:
                    # Ловим общие ошибки здесь тоже на всякий случай
                    print(f"Ошибка в audio_input callback: {e}")
            else:
                 # Сбрасываем громкость если не говорим
                 with self.volume_lock:
                    self.volume = 0.0

        try:
            print(f"Открытие InputStream: Устройство={self.input_device_index}, Rate={SAMPLE_RATE}, Block={BLOCKSIZE}")
            with sd.InputStream(samplerate=SAMPLE_RATE, channels=CHANNELS, dtype=DTYPE,
                                callback=callback, blocksize=BLOCKSIZE,
                                device=self.input_device_index):
                print("InputStream открыт. Ожидание...")
                # Держим поток активным, пока не придет сигнал завершения
                self.audio_transceiver.shutdown_event.wait()

        except sd.PortAudioError as e:
            print(f"Критическая ошибка аудио входа (PortAudioError): {e}")
            # Можно попытаться уведомить пользователя через GUI, если это возможно
            # self.after(0, lambda: messagebox.showerror("Ошибка аудио", f"Ошибка устройства ввода: {e}"))
        except Exception as e:
            print(f"Критическая ошибка аудио входа (Другое): {e}")

        print("Поток аудио входа завершается.")


    def audio_output_thread(self):
        """Поток для получения декодированного аудио и воспроизведения"""
        def callback(outdata: np.ndarray, frames: int, time_info, status: sd.CallbackFlags):
            if status:
                print(f"Ошибка вывода аудио (callback): {status}")

            # Получаем *уже декодированный* пакет (или None)
            audio_data = self.audio_transceiver.get_decoded_audio_packet()

            if audio_data is not None and audio_data.size == frames * CHANNELS:
                 # Копируем данные в буфер вывода
                outdata[:] = audio_data.reshape(-1, CHANNELS)
            else:
                # Если данных нет или размер неверный, выводим тишину
                outdata.fill(0)

        try:
            print(f"Открытие OutputStream: Устройство={self.output_device_index}, Rate={SAMPLE_RATE}, Block={BLOCKSIZE}")
            with sd.OutputStream(samplerate=SAMPLE_RATE, channels=CHANNELS, dtype=DTYPE,
                                 callback=callback, blocksize=BLOCKSIZE,
                                 device=self.output_device_index):
                print("OutputStream открыт. Ожидание...")
                # Держим поток активным, пока не придет сигнал завершения
                self.audio_transceiver.shutdown_event.wait()

        except sd.PortAudioError as e:
            print(f"Критическая ошибка аудио выхода (PortAudioError): {e}")
            # self.after(0, lambda: messagebox.showerror("Ошибка аудио", f"Ошибка устройства вывода: {e}"))
        except Exception as e:
             print(f"Критическая ошибка аудио выхода (Другое): {e}")

        print("Поток аудио вывода завершается.")

    # --- Остальные потоки без изменений в логике, только делегирование ---
    def receive_thread(self):
        """Поток для приема пакетов"""
        print("Поток приема пакетов запущен.")
        self.audio_transceiver.receive_packets()
        print("Поток приема пакетов завершается.")

    def ping_thread(self):
        """Поток для отправки ping-пакетов"""
        print("Поток отправки пингов запущен.")
        while not self.audio_transceiver.shutdown_event.is_set():
            self.audio_transceiver.send_ping()
            # Используем wait вместо sleep для более быстрого выхода при shutdown_event
            self.audio_transceiver.shutdown_event.wait(timeout=PING_INTERVAL)
        print("Поток отправки пингов завершается.")


    def client_cleanup_thread(self):
        """Поток для очистки неактивных клиентов"""
        print("Поток очистки клиентов запущен.")
        while not self.audio_transceiver.shutdown_event.is_set():
            self.audio_transceiver.cleanup_inactive_clients()
            self.audio_transceiver.shutdown_event.wait(timeout=1.0) # Проверка каждую секунду
        print("Поток очистки клиентов завершается.")

    # --- Обновление GUI и обработчики событий ---
    def update_gui(self):
        """Обновление GUI (вызывается в основном потоке)"""
        # Обновляем индикатор громкости
        with self.volume_lock:
            # Убедимся, что громкость не превышает 1.0
            current_volume = min(1.0, max(0.0, self.volume))
        self.volume_bar.set(current_volume)

        # Планируем следующее обновление, если окно еще существует
        if self.winfo_exists() and not self.audio_transceiver.shutdown_event.is_set():
             self.after(50, self.update_gui)


    def on_press(self, event):
        if not self.is_pressing:
             print("Начало передачи...")
             self.is_pressing = True
             self.update_led(True)


    def on_release(self, event):
        if self.is_pressing:
             print("Остановка передачи.")
             self.is_pressing = False
             self.update_led(False)
             # Сразу сбросить громкость на индикаторе
             with self.volume_lock:
                 self.volume = 0.0
             self.volume_bar.set(0.0)


    def update_led(self, on):
        color = "#00ff00" if on else "#880000" # Зеленый при передаче
        # Проверяем, существует ли еще виджет LED
        if hasattr(self, 'led') and self.led.winfo_exists():
            self.led.configure(fg_color=color)


    def on_closing(self):
        """Обработчик закрытия окна"""
        print("Получен сигнал закрытия окна.")
        if hasattr(self, 'audio_transceiver') and self.audio_transceiver:
            self.audio_transceiver.cleanup() # Вызываем очистку сокетов и сигналим потокам

        # Ждем немного, чтобы дать потокам шанс завершиться (опционально, но полезно)
        # time.sleep(0.5)

        print("Уничтожение окна GUI...")
        self.destroy() # Закрываем окно Tkinter

# --- Точка входа ---
if __name__ == "__main__":
    # Важное требование: Установите библиотеку opuslib
    # pip install opuslib
    # Также убедитесь, что сама библиотека Opus установлена в вашей системе.
    # Linux (Debian/Ubuntu): sudo apt-get install libopus-dev
    # Linux (Fedora): sudo dnf install opus-devel
    # macOS (Homebrew): brew install opus
    # Windows: Скачайте с официального сайта Opus или используйте vcpkg/winget.
    #          Убедитесь, что DLL (.dll) находится там, где Python может ее найти.
    print("Запуск приложения...")
    try:
        selector = AudioSelector()
        selector.mainloop()
    except Exception as e:
        # Ловим любые необработанные исключения при запуске
        print(f"Критическая ошибка на верхнем уровне: {e}")
        import traceback
        traceback.print_exc() # Печатаем полный стектрейс для диагностики

    print("Приложение завершено.")