import customtkinter as ctk
import sounddevice as sd
import socket
import threading
import numpy as np
from PIL import Image, ImageTk
import struct
import time

# Настройки Multicast
MCAST_GRP = "239.255.42.99"
PORT = 5005
TTL = 1

# Аудио
SAMPLE_RATE = 48000
CHANNELS = 1
BLOCKSIZE = 960
DTYPE = 'int16'

# Список активных клиентов (обнаружение)
active_clients = set()
received_packets = []

# Определить свой IP
local_ip = socket.gethostbyname(socket.gethostname())

# Сокеты
sock_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock_send.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, TTL)

sock_recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock_recv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock_recv.bind(("", PORT))
mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
sock_recv.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

# GUI
class VoxShareGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("VoxShare")
        self.geometry("400x500")
        self.resizable(False, False)
        ctk.set_appearance_mode("dark")

        self.is_pressing = False
        self.volume = 0.0

        ctk.CTkLabel(self, text="VoxShare", font=("Arial", 24)).pack(pady=20)

        img = Image.open("logo.png").resize((150, 150))
        self.logo_img = ImageTk.PhotoImage(img)

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


def send_audio():
    def callback(indata, frames, time, status):
        if gui.is_pressing:
            pcm_bytes = indata.tobytes()
            sock_send.sendto(b"AUD" + pcm_bytes, (MCAST_GRP, PORT))
            rms = np.sqrt(np.mean(np.square(indata)))
            gui.volume = float(rms) * 5.0
        else:
            gui.volume = 0.0

    with sd.InputStream(samplerate=SAMPLE_RATE, channels=CHANNELS, dtype=DTYPE,
                        callback=callback, blocksize=BLOCKSIZE):
        while True:
            sd.sleep(50)


def receive_audio():
    while True:
        data, addr = sock_recv.recvfrom(4096)

        # Фильтрация своих пакетов
        if addr[0] == local_ip:
            continue

        if data.startswith(b"AUD"):
            received_packets.append(data[3:])
        elif data.startswith(b"PING"):
            active_clients.add(addr[0])


def play_audio():
    def callback(outdata, frames, time, status):
        if received_packets:
            try:
                packet = received_packets.pop(0)
                outdata[:] = np.frombuffer(packet, dtype=DTYPE).reshape(-1, CHANNELS)
            except:
                outdata[:] = np.zeros((frames, CHANNELS), dtype=DTYPE)
        else:
            outdata[:] = np.zeros((frames, CHANNELS), dtype=DTYPE)

    with sd.OutputStream(samplerate=SAMPLE_RATE, channels=CHANNELS, dtype=DTYPE,
                         callback=callback, blocksize=BLOCKSIZE):
        while True:
            sd.sleep(100)


def send_ping():
    while True:
        sock_send.sendto(b"PING", (MCAST_GRP, PORT))
        time.sleep(2)


def update_gui_loop():
    while True:
        gui.update_volume(gui.volume)
        time.sleep(0.05)


if __name__ == "__main__":
    gui = VoxShareGUI()

    threading.Thread(target=send_audio, daemon=True).start()
    threading.Thread(target=receive_audio, daemon=True).start()
    threading.Thread(target=play_audio, daemon=True).start()
    threading.Thread(target=send_ping, daemon=True).start()
    threading.Thread(target=update_gui_loop, daemon=True).start()

    gui.mainloop()
