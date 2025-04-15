import customtkinter as ctk
import sounddevice as sd
import socket
import threading
import numpy as np
from PIL import Image, ImageTk

# Конфигурация
PORT = 5555
DEST_IPS = ["127.0.0.1", "192.168.1.10", "192.168.1.11"]
SAMPLE_RATE = 48000
CHANNELS = 1
BLOCKSIZE = 960  # Примерно 20мс аудио (48000 / 1000 * 20)
DTYPE = 'int16'

# UDP сокет
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", PORT))

received_packets = []

def send_audio():
    def callback(indata, frames, time, status):
        if gui.is_speaking:
            pcm_bytes = indata.tobytes()
            for ip in DEST_IPS:
                sock.sendto(pcm_bytes, (ip, PORT))

    with sd.InputStream(samplerate=SAMPLE_RATE, channels=CHANNELS, dtype=DTYPE, callback=callback, blocksize=BLOCKSIZE):
        while gui.is_speaking:
            sd.sleep(100)

def receive_audio():
    while True:
        try:
            data, _ = sock.recvfrom(4096)
            received_packets.append(data)
        except:
            continue

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

    with sd.OutputStream(samplerate=SAMPLE_RATE, channels=CHANNELS, dtype=DTYPE, callback=callback, blocksize=BLOCKSIZE):
        while True:
            sd.sleep(100)

# GUI
class VoxShareGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("VoxShare")
        self.geometry("400x500")
        ctk.set_appearance_mode("dark")

        self.is_speaking = False

        ctk.CTkLabel(self, text="VoxShare", font=("Arial", 24)).pack(pady=20)

        img = Image.open("logo.png").resize((150, 150))
        self.logo_img = ImageTk.PhotoImage(img)

        self.talk_btn = ctk.CTkButton(
            self, image=self.logo_img, text="", width=160, height=160,
            command=self.toggle_speech, corner_radius=80, fg_color="#444"
        )
        self.talk_btn.pack(pady=30)

        self.led = ctk.CTkLabel(self, text="", width=30, height=30, corner_radius=15)
        self.led.pack(pady=40)
        self.update_led(False)

    def toggle_speech(self):
        self.is_speaking = not self.is_speaking
        self.update_led(self.is_speaking)
        if self.is_speaking:
            threading.Thread(target=send_audio, daemon=True).start()

    def update_led(self, on):
        color = "#ff0000" if on else "#330000"
        self.led.configure(fg_color=color)

if __name__ == "__main__":
    threading.Thread(target=receive_audio, daemon=True).start()
    threading.Thread(target=play_audio, daemon=True).start()

    gui = VoxShareGUI()
    gui.mainloop()
