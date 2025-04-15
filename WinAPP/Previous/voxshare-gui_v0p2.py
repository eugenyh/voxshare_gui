import socket
import threading
import customtkinter as ctk
import sounddevice as sd
import numpy as np
import struct
import time
from PIL import Image

# === Настройки ===
MULTICAST_GROUP = "239.255.0.1"
PORT = 5005
SAMPLE_RATE = 48000
CHANNELS = 1
SAMPLE_WIDTH = 2  # bytes (16 bit)
FRAME_DURATION = 20  # milliseconds
FRAME_SIZE = int(SAMPLE_RATE * FRAME_DURATION / 1000)
MUTE_AFTER = 5  # секунд без активности

discovered_peers = set()
peer_lock = threading.Lock()

# === GUI ===
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class VoxShareApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("VoxShare")
        self.geometry("400x500")

        self.label = ctk.CTkLabel(self, text="VoxShare", font=("Arial", 24))
        self.label.pack(pady=10)

        self.logo_image = ctk.CTkImage(Image.open("logo.png"), size=(150,150))
        self.talk_button = ctk.CTkButton(self, image=self.logo_image, text="", width=150, height=150,
                                         command=None)
        self.talk_button.bind("<ButtonPress>", self.start_transmit)
        self.talk_button.bind("<ButtonRelease>", self.stop_transmit)
        self.talk_button.pack(pady=20)

        self.led = ctk.CTkLabel(self, text="●", text_color="darkred", font=("Arial", 36))
        self.led.pack(pady=10)

        self.volume_bar = ctk.CTkProgressBar(self, width=300)
        self.volume_bar.set(0)
        self.volume_bar.pack(pady=10)

        self.is_transmitting = False
        self.running = True

        self.audio_stream_out = sd.OutputStream(samplerate=SAMPLE_RATE, channels=CHANNELS, dtype='int16')
        self.audio_stream_out.start()

        threading.Thread(target=self.receive_loop, daemon=True).start()
        threading.Thread(target=self.peer_cleanup_loop, daemon=True).start()

    def calculate_rms_level(self, pcm_data):
        audio_array = np.frombuffer(pcm_data, dtype=np.int16).astype(np.float32)
        audio_array = audio_array / 32768.0
        rms = np.sqrt(np.mean(np.square(audio_array)))
        return min(rms, 1.0)

    def start_transmit(self, event=None):
        self.is_transmitting = True
        self.led.configure(text_color="red")
        threading.Thread(target=self.transmit_loop, daemon=True).start()

    def stop_transmit(self, event=None):
        self.is_transmitting = False
        self.led.configure(text_color="darkred")

    def transmit_loop(self):
        with sd.InputStream(samplerate=SAMPLE_RATE, channels=CHANNELS, dtype='int16', blocksize=FRAME_SIZE) as stream:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            ttl = struct.pack('b', 1)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

            while self.is_transmitting:
                pcm_data, _ = stream.read(FRAME_SIZE)
                pcm_bytes = pcm_data.tobytes()

                # Визуализация громкости
                rms = self.calculate_rms_level(pcm_bytes)
                self.volume_bar.set(rms)

                sock.sendto(pcm_bytes, (MULTICAST_GROUP, PORT))
                time.sleep(FRAME_DURATION / 1000)

    def receive_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", PORT))
        mreq = struct.pack("4sl", socket.inet_aton(MULTICAST_GROUP), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        last_seen = {}

        while self.running:
            try:
                data, addr = sock.recvfrom(4096)
                with peer_lock:
                    discovered_peers.add(addr[0])
                    last_seen[addr[0]] = time.time()
                self.audio_stream_out.write(np.frombuffer(data, dtype=np.int16))
            except Exception as e:
                print("Recv error:", e)

    def peer_cleanup_loop(self):
        while self.running:
            with peer_lock:
                now = time.time()
                to_remove = [ip for ip, t in list(discovered_peers) if now - t > MUTE_AFTER]
                for ip in to_remove:
                    discovered_peers.discard(ip)
            time.sleep(1)

    def on_closing(self):
        self.running = False
        self.destroy()

if __name__ == "__main__":
    app = VoxShareApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
