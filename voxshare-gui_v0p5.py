import customtkinter as ctk
import sounddevice as sd
import socket
import threading
import numpy as np
from PIL import Image, ImageTk
import struct
import time
import os

# Настройки Multicast
MCAST_GRP = "239.255.42.99"
PORT = 5005
TTL = 1

# Аудио
SAMPLE_RATE = 48000
CHANNELS = 1
BLOCKSIZE = 960
DTYPE = 'int16'

# Список активных клиентов
active_clients = set()
local_ip = socket.gethostbyname(socket.gethostname())

# Сокеты
sock_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock_send.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, TTL)

sock_recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock_recv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock_recv.bind(("", PORT))
mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
sock_recv.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

received_packets = []

gui = None


class AudioSelector(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Выбор аудиоустройств")
        self.geometry("500x300")

        ctk.set_appearance_mode("dark")

        ctk.CTkLabel(self, text="Выберите микрофон:", font=("Arial", 14)).pack(pady=10)
        self.input_combo = ctk.CTkComboBox(self, values=self.get_device_list(input=True), width=400)
        self.input_combo.pack()

        ctk.CTkLabel(self, text="Выберите устройство вывода:", font=("Arial", 14)).pack(pady=20)
        self.output_combo = ctk.CTkComboBox(self, values=self.get_device_list(output=True), width=400)
        self.output_combo.pack()

        ctk.CTkButton(self, text="Продолжить", command=self.launch_main).pack(pady=30)

    def get_device_list(self, input=False, output=False):
        devices = sd.query_devices()
        result = []
        for i, dev in enumerate(devices):
            if (input and dev['max_input_channels'] > 0) or (output and dev['max_output_channels'] > 0):
                result.append(f"{i}: {dev['name']}")
        return result

    def launch_main(self):
        global input_device_index, output_device_index, gui
        input_device_index = int(self.input_combo.get().split(":")[0])
        output_device_index = int(self.output_combo.get().split(":")[0])
        self.destroy()
        gui = VoxShareGUI()
        gui.mainloop()


class VoxShareGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("VoxShare")
        self.geometry("400x500")
        ctk.set_appearance_mode("dark")

        self.is_pressing = False
        self.volume = 0.0

        ctk.CTkLabel(self, text="VoxShare", font=("Arial", 24)).pack(pady=20)

        # Загрузка изображения с учетом Pillow >=10
        image_path = "logo.png"
        try:
            resample = Image.Resampling.LANCZOS
        except AttributeError:
            resample = Image.ANTIALIAS

        img = Image.open(image_path).resize((150, 150), resample)
        self.logo_img = ctk.CTkImage(light_image=img, size=(150, 150))

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

        # Запуск потоков
        threading.Thread(target=send_audio, daemon=True).start()
        threading.Thread(target=receive_audio, daemon=True).start()
        threading.Thread(target=play_audio, daemon=True).start()
        threading.Thread(target=send_ping, daemon=True).start()
        threading.Thread(target=self.update_gui_loop, daemon=True).start()

    def on_press(self, event):
        self.is_pressing = True
        self.update_led(True)

    def on_release(self, event):
        self.is_pressing = False
        self.update_led(False)

    def update_led(self, on):
        color = "#ff0000" if on else "#330000"
        self.led.configure(fg_color=color)

    def update_volume(self, level):
        self.volume_bar.set(min(1.0, level))

    def update_gui_loop(self):
        while True:
            self.update_volume(self.volume)
            time.sleep(0.05)


def send_audio():
    def callback(indata, frames, time_info, status):
        if gui.is_pressing:
            pcm_bytes = indata.tobytes()
            sock_send.sendto(b"AUD" + pcm_bytes, (MCAST_GRP, PORT))
            rms = np.sqrt(np.mean(np.square(indata)))
            gui.volume = float(rms) * 5.0
        else:
            gui.volume = 0.0

    with sd.InputStream(samplerate=SAMPLE_RATE, channels=CHANNELS, dtype=DTYPE,
                        callback=callback, blocksize=BLOCKSIZE, device=input_device_index):
        while True:
            sd.sleep(50)


def receive_audio():
    while True:
        data, addr = sock_recv.recvfrom(4096)
        if addr[0] == local_ip:
            continue  # фильтрация самих себя
        if data.startswith(b"AUD"):
            received_packets.append(data[3:])
        elif data.startswith(b"PING"):
            active_clients.add(addr[0])


def play_audio():
    def callback(outdata, frames, time_info, status):
        if received_packets:
            try:
                packet = received_packets.pop(0)
                outdata[:] = np.frombuffer(packet, dtype=DTYPE).reshape(-1, CHANNELS)
            except:
                outdata[:] = np.zeros((frames, CHANNELS), dtype=DTYPE)
        else:
            outdata[:] = np.zeros((frames, CHANNELS), dtype=DTYPE)

    with sd.OutputStream(samplerate=SAMPLE_RATE, channels=CHANNELS, dtype=DTYPE,
                         callback=callback, blocksize=BLOCKSIZE, device=output_device_index):
        while True:
            sd.sleep(100)


def send_ping():
    while True:
        sock_send.sendto(b"PING", (MCAST_GRP, PORT))
        time.sleep(2)


if __name__ == "__main__":
    selector = AudioSelector()
    selector.mainloop()
