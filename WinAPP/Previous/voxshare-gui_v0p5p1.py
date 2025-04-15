import customtkinter as ctk
import sounddevice as sd
import socket
import threading
import numpy as np
from PIL import Image, ImageTk
import struct
import time
import os
import queue
from queue import Queue
from threading import Event

# Константы
MCAST_GRP = "239.255.42.99"
PORT = 5005
TTL = 1
BUFFER_SIZE = 100  # Максимальное количество хранимых аудиопакетов
PING_INTERVAL = 2  # Интервал отправки ping в секундах
CLIENT_TIMEOUT = 5  # Таймаут клиента в секундах

# Аудио настройки
SAMPLE_RATE = 48000
CHANNELS = 1
BLOCKSIZE = 960
DTYPE = 'int16'

# Типы пакетов
PACKET_TYPE_AUDIO = b"AUD"
PACKET_TYPE_PING = b"PING"

class AudioTransceiver:
    def __init__(self):
        self.local_ip = socket.gethostbyname(socket.gethostname())
        self.active_clients = {}
        self.received_audio = Queue(maxsize=BUFFER_SIZE)
        self.shutdown_event = Event()
        
        # Инициализация сокетов
        self.init_sockets()
        
    def init_sockets(self):
        """Инициализация multicast сокетов"""
        try:
            self.sock_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock_send.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, TTL)
            
            self.sock_recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock_recv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock_recv.bind(("", PORT))
            mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
            self.sock_recv.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except socket.error as e:
            raise RuntimeError(f"Ошибка инициализации сокетов: {e}")

    def cleanup(self):
        """Очистка ресурсов"""
        self.shutdown_event.set()
        if hasattr(self, 'sock_send'):
            self.sock_send.close()
        if hasattr(self, 'sock_recv'):
            self.sock_recv.close()

    def send_audio(self, pcm_data):
        """Отправка аудио данных"""
        try:
            self.sock_send.sendto(PACKET_TYPE_AUDIO + pcm_data, (MCAST_GRP, PORT))
        except socket.error as e:
            print(f"Ошибка отправки аудио: {e}")

    def send_ping(self):
        """Отправка ping-пакета"""
        try:
            self.sock_send.sendto(PACKET_TYPE_PING, (MCAST_GRP, PORT))
        except socket.error as e:
            print(f"Ошибка отправки ping: {e}")

    def receive_packets(self):
        """Получение пакетов в цикле"""
        while not self.shutdown_event.is_set():
            try:
                data, addr = self.sock_recv.recvfrom(4096)
                if addr[0] == self.local_ip:
                    continue  # фильтрация самих себя
                
                if data.startswith(PACKET_TYPE_AUDIO):
                    try:
                        self.received_audio.put_nowait(data[3:])
                    except queue.Full:
                        pass  # Отбрасываем пакет если очередь полна
                elif data.startswith(PACKET_TYPE_PING):
                    self.active_clients[addr[0]] = time.time()
            
            except socket.error as e:
                if not self.shutdown_event.is_set():
                    print(f"Ошибка получения пакета: {e}")

    def cleanup_inactive_clients(self):
        """Очистка неактивных клиентов"""
        current_time = time.time()
        inactive = [ip for ip, last_seen in self.active_clients.items() 
                   if current_time - last_seen > CLIENT_TIMEOUT]
        for ip in inactive:
            del self.active_clients[ip]

class AudioSelector(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Выбор аудиоустройств")
        self.geometry("500x300")
        self.resizable(False, False)
        ctk.set_appearance_mode("dark")

        self.input_device_index = None
        self.output_device_index = None

        self.create_widgets()

    def create_widgets(self):
        """Создание элементов интерфейса"""
        ctk.CTkLabel(self, text="Выберите микрофон:", font=("Arial", 14)).pack(pady=10)
        self.input_combo = ctk.CTkComboBox(self, values=self.get_device_list(input=True), width=400)
        self.input_combo.pack()

        ctk.CTkLabel(self, text="Выберите устройство вывода:", font=("Arial", 14)).pack(pady=20)
        self.output_combo = ctk.CTkComboBox(self, values=self.get_device_list(output=True), width=400)
        self.output_combo.pack()

        ctk.CTkButton(self, text="Продолжить", command=self.validate_and_launch).pack(pady=30)

    def get_device_list(self, input=False, output=False):
        """Получение списка аудиоустройств"""
        try:
            devices = sd.query_devices()
            return [f"{i}: {dev['name']}" for i, dev in enumerate(devices)
                   if (input and dev['max_input_channels'] > 0) or 
                      (output and dev['max_output_channels'] > 0)]
        except sd.PortAudioError as e:
            print(f"Ошибка получения списка устройств: {e}")
            return []

    def validate_and_launch(self):
        """Проверка выбора устройств и запуск основного окна"""
        try:
            self.input_device_index = int(self.input_combo.get().split(":")[0])
            self.output_device_index = int(self.output_combo.get().split(":")[0])
            self.destroy()
            VoxShareGUI(self.input_device_index, self.output_device_index).mainloop()
        except (ValueError, AttributeError):
            ctk.CTkLabel(self, text="Пожалуйста, выберите оба устройства!", text_color="red").pack()

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
        self.audio_transceiver = AudioTransceiver()

        self.setup_gui()
        self.start_threads()

    def setup_gui(self):
        """Настройка графического интерфейса"""
        ctk.CTkLabel(self, text="VoxShare", font=("Arial", 24)).pack(pady=20)

        # Логотип с обработкой ошибок
        try:
            img = Image.open("logo.png").resize((150, 150), Image.Resampling.LANCZOS)
            self.logo_img = ctk.CTkImage(light_image=img, size=(150, 150))
        except (FileNotFoundError, IOError):
            # Запасной вариант без логотипа
            self.logo_img = None

        self.talk_btn = ctk.CTkButton(
            self, image=self.logo_img, text="", width=160, height=160,
            corner_radius=80, fg_color="#444"
        )
        self.talk_btn.pack(pady=30)
        self.talk_btn.bind("<ButtonPress-1>", self.on_press)
        self.talk_btn.bind("<ButtonRelease-1>", self.on_release)

        self.led = ctk.CTkLabel(self, text="", width=30, height=30, corner_radius=15)
        self.led.pack(pady=10)
        self.update_led(False)

        self.volume_bar = ctk.CTkProgressBar(self, width=200, height=20)
        self.volume_bar.set(0)
        self.volume_bar.pack(pady=20)

    def start_threads(self):
        """Запуск рабочих потоков"""
        threading.Thread(target=self.audio_input_thread, daemon=True).start()
        threading.Thread(target=self.audio_output_thread, daemon=True).start()
        threading.Thread(target=self.ping_thread, daemon=True).start()
        threading.Thread(target=self.client_cleanup_thread, daemon=True).start()
        threading.Thread(target=self.receive_thread, daemon=True).start()
        self.after(50, self.update_gui)  # Запуск обновления GUI в основном потоке

    def audio_input_thread(self):
        """Поток для захвата аудио"""
        def callback(indata, frames, time_info, status):
            if status:
                print(f"Ошибка ввода аудио: {status}")
            
            if self.is_pressing:
                try:
                    self.audio_transceiver.send_audio(indata.tobytes())
                    rms = np.sqrt(np.mean(np.square(indata)))
                    with self.volume_lock:
                        self.volume = float(rms) * 5.0
                except Exception as e:
                    print(f"Ошибка обработки аудио: {e}")
            else:
                with self.volume_lock:
                    self.volume = 0.0

        try:
            with sd.InputStream(samplerate=SAMPLE_RATE, channels=CHANNELS, dtype=DTYPE,
                               callback=callback, blocksize=BLOCKSIZE, 
                               device=self.input_device_index):
                while not self.audio_transceiver.shutdown_event.is_set():
                    sd.sleep(50)
        except sd.PortAudioError as e:
            print(f"Ошибка аудио входа: {e}")

    def audio_output_thread(self):
        """Поток для воспроизведения аудио"""
        def callback(outdata, frames, time_info, status):
            if status:
                print(f"Ошибка вывода аудио: {status}")
            
            try:
                packet = self.audio_transceiver.received_audio.get_nowait()
                audio_data = np.frombuffer(packet, dtype=DTYPE)
                if len(audio_data) == frames * CHANNELS:
                    outdata[:] = audio_data.reshape(-1, CHANNELS)
                else:
                    outdata[:] = np.zeros((frames, CHANNELS), dtype=DTYPE)
            except queue.Empty:
                outdata[:] = np.zeros((frames, CHANNELS), dtype=DTYPE)
            except Exception as e:
                print(f"Ошибка обработки аудио: {e}")
                outdata[:] = np.zeros((frames, CHANNELS), dtype=DTYPE)

        try:
            with sd.OutputStream(samplerate=SAMPLE_RATE, channels=CHANNELS, dtype=DTYPE,
                              callback=callback, blocksize=BLOCKSIZE,
                              device=self.output_device_index):
                while not self.audio_transceiver.shutdown_event.is_set():
                    sd.sleep(100)
        except sd.PortAudioError as e:
            print(f"Ошибка аудио выхода: {e}")

    def receive_thread(self):
        """Поток для приема пакетов"""
        self.audio_transceiver.receive_packets()

    def ping_thread(self):
        """Поток для отправки ping-пакетов"""
        while not self.audio_transceiver.shutdown_event.is_set():
            self.audio_transceiver.send_ping()
            time.sleep(PING_INTERVAL)

    def client_cleanup_thread(self):
        """Поток для очистки неактивных клиентов"""
        while not self.audio_transceiver.shutdown_event.is_set():
            self.audio_transceiver.cleanup_inactive_clients()
            time.sleep(1)

    def update_gui(self):
        """Обновление GUI (вызывается в основном потоке)"""
        with self.volume_lock:
            self.volume_bar.set(min(1.0, self.volume))
        self.after(50, self.update_gui)  # Планируем следующее обновление

    def on_press(self, event):
        self.is_pressing = True
        self.update_led(True)

    def on_release(self, event):
        self.is_pressing = False
        self.update_led(False)

    def update_led(self, on):
        color = "#ff0000" if on else "#880000"  # Более видимый выключенный цвет
        self.led.configure(fg_color=color)

    def on_closing(self):
        """Обработчик закрытия окна"""
        self.audio_transceiver.cleanup()
        self.destroy()

if __name__ == "__main__":
    try:
        selector = AudioSelector()
        selector.mainloop()
    except Exception as e:
        print(f"Критическая ошибка: {e}")