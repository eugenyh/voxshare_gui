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
import tkinter # For checking the type of event
import os

# --- Global dictionary for settings ---
config = {}

# --- Global definitions of packet type constants ---
PACKET_TYPE_AUDIO = b"AUD"
PACKET_TYPE_PING = b"PING" # Prefix remains 4 bytes

# --- Additional constants ---
SPEAKER_TIMEOUT_THRESHOLD = 0.3 # Seconds after which the "speaking" status is reset

def resource_path(relative_path):
    """ Gets the correct path for resources in EXE and in development """
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

# --- Functions for working with settings and logging ---

def get_default_config():
    """Returns a dictionary with default settings."""
    return {
        "user": { # <--- Added user section
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

# --- load_config, setup_logging functions (no changes) ---
def load_config(filename="config.json"):
    """Loads settings from a JSON file or creates a file with default settings."""
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
            print(f"Settings loaded from {filename}")
    except FileNotFoundError:
        print(f"Settings file {filename} not found. Creating a file with default settings.")
        config = defaults
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            print(f"Settings file {filename} created.")
        except IOError as e:
            print(f"Error: Could not create settings file {filename}: {e}")
    except json.JSONDecodeError as e:
        print(f"Error: Could not decode JSON in file {filename}: {e}")
        print("Using default settings.")
        config = defaults
    except Exception as e:
        print(f"Unexpected error while loading settings: {e}")
        print("Using default settings.")
        config = defaults

def setup_logging():
    """Configures the logging system based on the configuration."""
    log_config = config.get('logging', {})
    enabled = log_config.get('enabled', False)
    if not enabled:
        logging.disable(logging.CRITICAL)
        print("Logging disabled in settings.")
        return
    log_level_str = log_config.get('log_level', 'INFO').upper()
    log_file = log_config.get('log_file', 'voxshare.log')
    log_format = log_config.get('log_format', '%(asctime)s - %(levelname)s - %(threadName)s - %(message)s')
    log_level_map = {'DEBUG': logging.DEBUG, 'INFO': logging.INFO, 'WARNING': logging.WARNING, 'ERROR': logging.ERROR, 'CRITICAL': logging.CRITICAL}
    log_level = log_level_map.get(log_level_str, logging.INFO)
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    try:
        logging.basicConfig(level=log_level, format=log_format, filename=log_file, filemode='w', encoding='utf-8', force=True)
        logging.info("="*20 + " Application Start " + "="*20)
        logging.info(f"Logging configured. Level: {log_level_str}, Файл: {log_file}")
        print(f"Logging configured. Level: {log_level_str}, Файл: {log_file}")
    except IOError as e:
         print(f"Error configuring logging to file {log_file}: {e}. Logging will be disabled.")
         logging.disable(logging.CRITICAL)
    except Exception as e:
        print(f"Unexpected error configuring logging: {e}. Logging will be disabled.")
        logging.disable(logging.CRITICAL)

# --- Mapping strings from config to Opus constants ---
OPUS_APPLICATION_MAP = { "voip": opuslib.APPLICATION_VOIP, "audio": opuslib.APPLICATION_AUDIO, "restricted_lowdelay": opuslib.APPLICATION_RESTRICTED_LOWDELAY }

# --- Class for working with network and Opus ---
class AudioTransceiver:
    # *** CHANGE: Accepts user_config ***
    def __init__(self, user_config, net_config, audio_config):
        self.user_config = user_config
        self.net_config = net_config
        self.audio_config = audio_config

        # *** NEW: Saving nickname ***
        self.nickname = self.user_config.get('nickname', '').strip()
        # ---------------------------------

        try:
            self.local_ip = socket.gethostbyname(socket.gethostname())
        except socket.gaierror:
             logging.warning("Failed to determine local IP by hostname, using '127.0.0.1'")
             self.local_ip = "127.0.0.1"

        # *** CHANGE: Structure of active_clients ***
        # Now stores {ip: {'nickname': str, 'last_seen': float}}
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
            logging.info(f"Opus initialized: Rate={self.sample_rate}, Channels={self.channels}, App={opus_app_str}")
        except opuslib.OpusError as e:
            logging.exception("Critical Opus initialization error")
            raise RuntimeError(f"Opus initialization error: {e}")
        except Exception as e:
             logging.exception("Unexpected critical Opus initialization error")
             raise RuntimeError(f"Unexpected Opus initialization error: {e}")
        self.init_sockets()

    # --- init_sockets, cleanup, encode_and_send_audio (no changes) ---
    def init_sockets(self):
        """Initialization of multicast sockets"""
        try:
            self.sock_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock_send.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.ttl)
            self.sock_recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.sock_recv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                 self.sock_recv.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.socket_buffer_size)
                 logging.info(f"Set socket receive buffer size: {self.socket_buffer_size}")
            except socket.error as e:
                 logging.warning(f"Failed to set socket receive buffer size: {e}")
            self.sock_recv.bind(("", self.port))
            mreq = struct.pack("4sl", socket.inet_aton(self.mcast_grp), socket.INADDR_ANY)
            self.sock_recv.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            logging.info(f"Sockets initialized. Receiving on port {self.port}, group {self.mcast_grp}")
        except socket.error as e:
            logging.exception("Critical socket initialization error")
            raise RuntimeError(f"Socket initialization error: {e}")
        except Exception as e:
             logging.exception("Unexpected critical socket initialization error")
             raise RuntimeError(f"Unexpected socket initialization error: {e}")

    def cleanup(self):
        """Cleanup resources"""
        logging.info("Starting AudioTransceiver resource cleanup...")
        self.shutdown_event.set()
        time.sleep(0.2)
        if hasattr(self, 'sock_send'):
            try: self.sock_send.close(); logging.info("Send socket closed.")
            except Exception as e: logging.error(f"Error closing send socket: {e}")
        if hasattr(self, 'sock_recv'):
            try:
                mreq = struct.pack("4sl", socket.inet_aton(self.mcast_grp), socket.INADDR_ANY)
                self.sock_recv.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
                logging.info(f"Left multicast group {self.mcast_grp}.")
            except socket.error as e: logging.warning(f"Failed to leave multicast group (socket may already be closed): {e}")
            except Exception as e: logging.error(f"Error attempting to leave multicast group: {e}")
            try: self.sock_recv.close(); logging.info("Receive socket closed.")
            except Exception as e: logging.error(f"Error closing receive socket: {e}")
        logging.info("AudioTransceiver cleanup complete.")

    def encode_and_send_audio(self, pcm_data_bytes):
        """Encoding PCM data to Opus and sending"""
        if self.shutdown_event.is_set(): return
        try:
            encoded_data = self.encoder.encode(pcm_data_bytes, self.block_size)
            self.sock_send.sendto(self.packet_type_audio + encoded_data, (self.mcast_grp, self.port))
        except opuslib.OpusError as e: logging.error(f"Opus encoding error: {e}")
        except socket.error as e: logging.error(f"Audio sending error: {e}")
        except Exception as e: logging.exception(f"Unexpected error during audio encoding/sending")

    def send_ping(self):
        """Sending a ping packet with the nickname"""
        if self.shutdown_event.is_set(): return
        try:
            # *** CHANGE: Adding nickname to the packet ***
            nickname_bytes = self.nickname.encode('utf-8')
            ping_packet = self.packet_type_ping + nickname_bytes
            # **********************************************
            self.sock_send.sendto(ping_packet, (self.mcast_grp, self.port))
            logging.debug(f"Sent PING packet (nick: '{self.nickname}')")
        except socket.error as e:
            if not self.shutdown_event.is_set(): logging.error(f"Ping sending error: {e}")
        except Exception as e:
             if not self.shutdown_event.is_set(): logging.exception("Unexpected error during ping sending")

    def receive_packets(self):
        """Receiving packets in a loop"""
        logging.info("Packet receiving thread started.")
        while not self.shutdown_event.is_set():
            try:
                data, addr = self.sock_recv.recvfrom(self.socket_buffer_size)
                logging.debug(f"Received packet {len(data)} bytes from {addr}")

                if addr[0] == self.local_ip: continue

                if data.startswith(self.packet_type_audio):
                    opus_packet = data[len(self.packet_type_audio):]
                    packet_tuple = (addr[0], opus_packet)
                    try: self.received_opus_packets.put_nowait(packet_tuple); logging.debug(f"Audio packet ({len(opus_packet)} bytes from {addr[0]}) added to queue.")
                    except queue.Full:
                        try: dropped_tuple = self.received_opus_packets.get_nowait(); self.received_opus_packets.put_nowait(packet_tuple); logging.warning(f"Audio packet queue full. Dropped packet from {dropped_tuple[0]}.")
                        except queue.Empty: pass
                        except queue.Full: logging.warning("Queue is full even after removal, new packet skipped.")

                elif data.startswith(self.packet_type_ping):
                    # *** CHANGE: Extracting nickname, updating active_clients structure ***
                    nickname_bytes = data[len(self.packet_type_ping):]
                    try:
                        nickname = nickname_bytes.decode('utf-8', errors='replace').strip()
                    except Exception as e:
                        logging.warning(f"Failed to decode nickname from PING from {addr[0]}: {e}")
                        nickname = "" # Use empty nick on error

                    with self.clients_lock:
                        # Update or create client record
                        client_info = self.active_clients.get(addr[0], {}) # Get existing or empty info
                        client_info['last_seen'] = time.time()
                        client_info['nickname'] = nickname # Save/update nick
                        self.active_clients[addr[0]] = client_info # Write back
                    logging.info(f"Received PING from {addr[0]} (Nick: '{nickname}'). Client active.")
                    # ***********************************************************************
                else:
                    logging.warning(f"Received unknown packet type from {addr}: {data[:10]}...")

            except socket.timeout: continue
            except socket.error as e:
                if self.shutdown_event.is_set(): logging.info("Socket closed, receiving thread is terminating."); break
                else:
                    if not self.shutdown_event.is_set(): logging.error(f"Socket error while receiving packet: {e}")
                    time.sleep(0.1)
            except Exception as e:
                 if not self.shutdown_event.is_set(): logging.exception("Unexpected error in receive_packets")
        logging.info("Packet reception thread finished.")

    # --- decode_audio, get_decoded_audio_packet ---
    def decode_audio(self, opus_packet):
        """Decodes an Opus packet into PCM"""
        try:
            pcm_data = self.decoder.decode(opus_packet, self.block_size)
            logging.debug(f"Декодирован пакет {len(opus_packet)} байт -> {len(pcm_data)} байт PCM")
            return pcm_data
        except opuslib.OpusError as e: logging.error(f"Error decoding Opus packet ({len(opus_packet)} bytes): {e}"); return None
        except Exception as e: logging.exception(f"Unexpected error decoding packet ({len(opus_packet)} bytes)"); return None

    def get_decoded_audio_packet(self):
        """Retrieves an Opus packet from the queue and decodes it. Returns (sender_ip, audio_data) or None."""
        try:
            sender_ip, opus_packet = self.received_opus_packets.get_nowait()
            decoded_pcm = self.decode_audio(opus_packet)
            if decoded_pcm:
                 audio_data = np.frombuffer(decoded_pcm, dtype=self.dtype)
                 expected_size = self.block_size * self.channels
                 if audio_data.size == expected_size: return sender_ip, audio_data
                 else: logging.warning(f"Unexpected size of decoded packet from {sender_ip} ({audio_data.size} instead of {expected_size})"); return None
            else: return None
        except queue.Empty: return None
        except Exception as e: logging.exception("Unexpected error in get_decoded_audio_packet"); return None

    def cleanup_inactive_clients(self):
        """Cleanup of inactive clients"""
        current_time = time.time()
        inactive_ips = []
        client_timeout = self.net_config.get('client_timeout_sec', 5)

        with self.clients_lock:
            all_client_ips = list(self.active_clients.keys()) # Copy of keys for safe iteration

        for ip in all_client_ips:
            last_seen = None
            with self.clients_lock:
                # Get the last ping time for the IP
                client_info = self.active_clients.get(ip)
                if client_info:
                    last_seen = client_info.get('last_seen')

            if last_seen is None: continue # If the client was removed in another thread

            if current_time - last_seen > client_timeout:
                inactive_ips.append(ip)

        if inactive_ips:
            logging.debug(f"Candidates for removal due to timeout: {inactive_ips}")
            with self.clients_lock:
                for ip in inactive_ips:
                    # Double-check before removing
                    client_info = self.active_clients.get(ip)
                    if client_info and current_time - client_info.get('last_seen', 0) > client_timeout:
                        nickname = client_info.get('nickname', '')
                        logging.info(f"Removing inactive client: {ip} (Nickname: '{nickname}', last seen: {current_time - client_info.get('last_seen', 0):.1f} seconds ago)")
                        del self.active_clients[ip]


# --- GUI Device Selection ---
class AudioSelector(ctk.CTk):
    def __init__(self, gui_config):
        super().__init__()
        self.gui_config = gui_config
        self.title("Select audio devices")
        geometry = self.gui_config.get('selector_geometry', '500x350')
        try: self.geometry(geometry)
        except Exception as e: logging.warning(f"Incorrect geometry for AudioSelector in config ('{geometry}'): {e}. Using 500x350."); self.geometry("500x350")
        self.resizable(False, False)
        self.input_device_index = None
        self.output_device_index = None
        self.create_widgets()
        self.bind("<Escape>", lambda e: self.destroy())

    def create_widgets(self):
        ctk.CTkLabel(self, text="Select microphone:", font=("Arial", 14)).pack(pady=10)
        input_devices = self.get_device_list(input=True)
        self.input_combo = ctk.CTkComboBox(self, values=input_devices, width=400)
        if input_devices: self.input_combo.set(input_devices[0])
        else: logging.warning("No input devices found.")
        self.input_combo.pack()
        ctk.CTkLabel(self, text="Select output device:", font=("Arial", 14)).pack(pady=20)
        output_devices = self.get_device_list(output=True)
        self.output_combo = ctk.CTkComboBox(self, values=output_devices, width=400)
        if output_devices: self.output_combo.set(output_devices[0])
        else: logging.warning("No output devices found.")
        self.output_combo.pack()
        ctk.CTkButton(self, text="Continue", command=self.validate_and_launch).pack(pady=30)
        self.error_label = ctk.CTkLabel(self, text="", text_color="red", font=("Arial", 12))
        self.error_label.pack(pady=(0, 10))
        self.after(100, lambda: self.focus_force())

    def get_device_list(self, input=False, output=False):
        try:
            devices = sd.query_devices()
            device_list = []
            for i, dev in enumerate(devices):
                if not dev or not isinstance(dev, dict) or not dev.get('name'): logging.warning(f"Skipping invalid device with index {i}: {dev}"); continue
                is_input = dev.get('max_input_channels', 0) > 0
                is_output = dev.get('max_output_channels', 0) > 0
                if (input and is_input) or (output and is_output):
                     try: device_list.append(f"{i}: {dev['name']}")
                     except Exception as enc_e: logging.warning(f"Problem with device name {i}: {dev.get('name')}. Error: {enc_e}. Skipping.")
            logging.info(f"Found {'input' if input else 'output'} devices: {len(device_list)}")
            return device_list
        except sd.PortAudioError as e: logging.exception("PortAudio error while getting device list"); self._update_error_label(f"Error reading devices: {e}"); return []
        except Exception as e: logging.exception("Unexpected error while getting device list"); self._update_error_label("Critical error reading devices!"); return []

    def _update_error_label(self, text):
         """Safely updates the error label."""
         if hasattr(self, 'error_label') and self.error_label.winfo_exists():
              self.error_label.configure(text=text)

    def validate_and_launch(self):
        input_selection = self.input_combo.get()
        output_selection = self.output_combo.get()
        try:
            if not input_selection or not output_selection: raise ValueError("One or both devices not selected.")
            if not ":" in input_selection or not ":" in output_selection: raise ValueError("Incorrect format of the selected device.")
            self.input_device_index = int(input_selection.split(":")[0])
            self.output_device_index = int(output_selection.split(":")[0])
            logging.info(f"Selected devices: Input={self.input_device_index} ('{input_selection}'), Output={self.output_device_index} ('{output_selection}')")
            global config
            audio_cfg = config.get('audio', {})
            rate = audio_cfg.get('sample_rate', 48000); chans = audio_cfg.get('channels', 1); dtype = audio_cfg.get('dtype', 'int16')
            try:
                 logging.debug(f"Checking input settings: dev={self.input_device_index}, rate={rate}, chans={chans}, dtype={dtype}")
                 sd.check_input_settings(device=self.input_device_index, channels=chans, samplerate=rate, dtype=dtype)
                 logging.debug(f"Checking output settings: dev={self.output_device_index}, rate={rate}, chans={chans}, dtype={dtype}")
                 sd.check_output_settings(device=self.output_device_index, channels=chans, samplerate=rate, dtype=dtype)
                 logging.info("Audio device settings checked successfully.")
            except sd.PortAudioError as pa_err: logging.error(f"PortAudio settings check error: {pa_err}"); raise ValueError(f"Device does not support settings ({rate}Hz, {chans}ch, {dtype}): {pa_err}")
            except ValueError as val_err: logging.error(f"sounddevice settings check error (ValueError): {val_err}"); raise ValueError(f"Incorrect device index or error: {val_err}")
            except Exception as e: logging.exception("sounddevice settings check error"); raise ValueError(f"Device check error: {e}")
            self._update_error_label("")
            self.destroy()
            # *** CHANGE: Passing user_config to VoxShareGUI ***
            main_app = VoxShareGUI(
                input_device_index=self.input_device_index,
                output_device_index=self.output_device_index,
                user_config=config.get('user', {}), 
                gui_config=self.gui_config,
                net_config=config.get('network',{}),
                audio_config=config.get('audio',{})
                )
            # ****************************************************
            main_app.mainloop()
        except (ValueError, AttributeError, IndexError) as e: error_message = f"Selection error: {e}"; logging.warning(f"Device selection validation error: {e}"); self._update_error_label(error_message)
        except Exception as e: logging.exception("Unexpected error during validation and launch"); self._update_error_label("A critical error occurred!")

# --- Main Application GUI ---
class VoxShareGUI(ctk.CTk):
    # *** CHANGE: Accepts user_config ***
    def __init__(self, input_device_index, output_device_index, user_config, gui_config, net_config, audio_config):
        super().__init__()
        self.user_config = user_config 
        self.gui_config = gui_config
        self.net_config = net_config
        self.audio_config = audio_config
        # ------------------------------------
        self.title("VoxShare")
        geometry = self.gui_config.get('main_geometry', '550x450')
        try: self.geometry(geometry)
        except Exception as e: logging.warning(f"Incorrect geometry for VoxShareGUI in config ('{geometry}'): {e}. Using 550x450."); self.geometry("550x450")
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
            # *** CHANGE: Passing user_config to AudioTransceiver ***
            self.audio_transceiver = AudioTransceiver(
                user_config=self.user_config, 
                net_config=self.net_config,
                audio_config=self.audio_config
                )
            # **********************************************************
        except RuntimeError as e: logging.exception("Critical error during AudioTransceiver initialization"); self.destroy(); return
        except Exception as e: logging.exception("Unexpected critical error during AudioTransceiver initialization"); self.destroy(); return
        self.setup_gui()
        self.start_threads()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        logging.info("Main VoxShareGUI window initialized.")

    # --- setup_gui, start_threads, audio_input_thread, audio_output_thread ---
    def setup_gui(self):
        """GUI configuration"""
        top_frame = ctk.CTkFrame(self, fg_color="transparent"); top_frame.pack(pady=10, padx=10, fill="x")
        ctk.CTkLabel(top_frame, text="VoxShare", font=("Arial", 24)).pack()
        middle_frame = ctk.CTkFrame(self, fg_color="transparent"); middle_frame.pack(pady=10, padx=10, fill="both", expand=True)
        try:
            logo_path = resource_path(os.path.join("Icons", "logo.png"))
            img = Image.open(logo_path).resize((150, 150), Image.Resampling.LANCZOS)
            self.logo_img = ctk.CTkImage(light_image=img, dark_image=img, size=(150, 150))
            logo_widget = ctk.CTkLabel(middle_frame, image=self.logo_img, text=""); logging.debug("Logo logo.png loaded.")
        except FileNotFoundError: logging.warning("File logo.png not found."); self.logo_img = None; logo_widget = ctk.CTkLabel(middle_frame, text="[Logo]", width=150, height=150, fg_color="grey")
        except Exception as e: logging.warning(f"Failed to load or process logo.png: {e}"); self.logo_img = None; logo_widget = ctk.CTkLabel(middle_frame, text="[Logo error]", width=150, height=150, fg_color="grey")
        logo_widget.pack(side="left", padx=(0, 20), anchor="n")
        peer_list_frame = ctk.CTkFrame(middle_frame); peer_list_frame.pack(side="left", fill="both", expand=True)
        ctk.CTkLabel(peer_list_frame, text="Peers:", font=("Arial", 14)).pack(anchor="w", padx=5)
        self.peer_list_textbox = ctk.CTkTextbox(peer_list_frame, font=("Arial", 12), wrap="none")
        self.peer_list_textbox.pack(side="top", fill="both", expand=True, padx=5, pady=(0,5)); self.peer_list_textbox.configure(state="disabled")
        bottom_frame = ctk.CTkFrame(self, fg_color="transparent"); bottom_frame.pack(side="bottom", pady=10, padx=10, fill="x")
        bottom_frame.columnconfigure(0, weight=1)
        self.led = ctk.CTkLabel(bottom_frame, text="", width=30, height=30, corner_radius=15, fg_color="#D50000"); self.led.grid(row=0, column=0, padx=10, pady=(5, 2))
        self.volume_bar = ctk.CTkProgressBar(bottom_frame, height=20); self.volume_bar.set(0); self.volume_bar.grid(row=1, column=0, padx=50, pady=2, sticky="ew")
        self.talk_btn = ctk.CTkButton(bottom_frame, text="Speak", height=40, font=("Arial", 16)); self.talk_btn.grid(row=2, column=0, padx=50, pady=(5, 5), sticky="ew")
        self.talk_btn.bind("<ButtonPress-1>", self.on_press); self.talk_btn.bind("<ButtonRelease-1>", self.on_release)
        self.bind("<KeyPress-space>", self.on_press); self.bind("<KeyRelease-space>", self.on_release)
        self.bind("<Button-1>", lambda event: self.focus_set())
        logging.debug("GUI elements of the main window created and placed.")
        self.after(100, lambda: self.focus_force())

    def start_threads(self):
        """Starting worker threads"""
        if not hasattr(self, 'audio_transceiver') or not self.audio_transceiver: logging.error("Error: audio_transceiver not initialized, threads not started."); return
        logging.info("Starting worker threads...")
        self.input_thread = threading.Thread(target=self.audio_input_thread, name="AudioInputThread", daemon=True)
        self.output_thread = threading.Thread(target=self.audio_output_thread, name="AudioOutputThread", daemon=True)
        self.receive_thread = threading.Thread(target=self.receive_thread, name="ReceiveThread", daemon=True)
        self.ping_thread = threading.Thread(target=self.ping_thread, name="PingThread", daemon=True)
        self.cleanup_thread = threading.Thread(target=self.client_cleanup_thread, name="ClientCleanupThread", daemon=True)
        self.input_thread.start(); self.output_thread.start(); self.receive_thread.start(); self.ping_thread.start(); self.cleanup_thread.start()
        self.after(100, self.update_gui); logging.info("All worker threads started.")

    def audio_input_thread(self):
        """Thread for capturing audio, encoding, and sending"""
        sample_rate = self.audio_transceiver.sample_rate; channels = self.audio_transceiver.channels; blocksize = self.audio_transceiver.block_size; dtype = self.audio_transceiver.dtype
        def callback(indata: np.ndarray, frames: int, time_info, status: sd.CallbackFlags):
            if status: logging.warning(f"Input callback status: {status}")
            if not self.audio_transceiver.shutdown_event.is_set() and self.is_pressing:
                try:
                    pcm_data_bytes = indata.tobytes(); self.audio_transceiver.encode_and_send_audio(pcm_data_bytes)
                    float_data = indata.astype(np.float32) / 32768.0; rms = np.sqrt(np.mean(np.square(float_data)))
                    with self.volume_lock: self.volume = float(rms) * 2.5
                except Exception as e: logging.exception(f"Error in audio_input callback during transmission")
            else:
                 if not self.is_pressing or self.audio_transceiver.shutdown_event.is_set():
                     with self.volume_lock:
                         self.volume = 0.0
        try:
            logging.info(f"Opening InputStream: Device={self.input_device_index}, Rate={sample_rate}, Block={blocksize}, Dtype={dtype}")
            with sd.InputStream(samplerate=sample_rate, channels=channels, dtype=dtype, callback=callback, blocksize=blocksize, device=self.input_device_index):
                logging.info("InputStream opened. Waiting for shutdown signal...")
                self.audio_transceiver.shutdown_event.wait()
        except sd.PortAudioError as e: logging.exception(f"Critical audio input error (PortAudioError) Device={self.input_device_index}")
        except Exception as e: logging.exception(f"Critical audio input error (Other) Device={self.input_device_index}")
        logging.info("Audio input thread is shutting down.")

    def audio_output_thread(self):
        """Thread for receiving decoded audio and playing it"""
        sample_rate = self.audio_transceiver.sample_rate; channels = self.audio_transceiver.channels; blocksize = self.audio_transceiver.block_size; dtype = self.audio_transceiver.dtype
        def callback(outdata: np.ndarray, frames: int, time_info, status: sd.CallbackFlags):
            if status: logging.warning(f"Output callback status: {status}")
            packet_info = self.audio_transceiver.get_decoded_audio_packet(); processed_ip = None
            if packet_info is not None:
                sender_ip, audio_data = packet_info
                if audio_data is not None and audio_data.size == frames * channels: outdata[:] = audio_data.reshape(-1, channels); processed_ip = sender_ip; logging.debug(f"Played audio packet {len(audio_data)} samples from {sender_ip}")
                else: outdata.fill(0); logging.warning(f"Packet size from {sender_ip} did not match ({audio_data.size} vs {frames * channels}), played silence.") if audio_data is not None else None
            else: outdata.fill(0)
            if not self.audio_transceiver.shutdown_event.is_set():
                with self.speaker_lock:
                    if processed_ip: self.currently_speaking_ip = processed_ip; self.last_packet_played_time = time.time()
        try:
            logging.info(f"Opening OutputStream: Device={self.output_device_index}, Rate={sample_rate}, Block={blocksize}, Dtype={dtype}")
            with sd.OutputStream(samplerate=sample_rate, channels=channels, dtype=dtype, callback=callback, blocksize=blocksize, device=self.output_device_index):
                logging.info("OutputStream opened. Waiting for shutdown signal...")
                self.audio_transceiver.shutdown_event.wait()
        except sd.PortAudioError as e: logging.exception(f"Critical audio output error (PortAudioError) Device={self.output_device_index}")
        except Exception as e: logging.exception(f"Critical audio output error (Other) Device={self.output_device_index}")
        logging.info("Audio output thread is shutting down.")

    # --- receive_thread, ping_thread, client_cleanup_thread ---
    def receive_thread(self):
        if hasattr(self, 'audio_transceiver') and self.audio_transceiver: self.audio_transceiver.receive_packets()
        else: logging.error("ReceiveThread: audio_transceiver does not exist.")

    def ping_thread(self):
        logging.info("Ping sending thread started.")
        if not hasattr(self, 'audio_transceiver') or not self.audio_transceiver: logging.error("PingThread: audio_transceiver does not exist."); return
        ping_interval = self.net_config.get('ping_interval_sec', 2)
        while not self.audio_transceiver.shutdown_event.wait(timeout=ping_interval):
            self.audio_transceiver.send_ping()
        logging.info("Ping sending thread is shutting down.")

    def client_cleanup_thread(self):
        logging.info("Ping sending thread started.")
        if not hasattr(self, 'audio_transceiver') or not self.audio_transceiver: logging.error("ClientCleanupThread: audio_transceiver не существует."); return
        cleanup_interval = 1.0
        while not self.audio_transceiver.shutdown_event.wait(timeout=cleanup_interval):
            self.audio_transceiver.cleanup_inactive_clients()
        logging.info("Ping sending thread is shutting down.")

    def update_gui(self):
        """GUI update (called in the main thread)"""
        try:
            if not self.winfo_exists() or not hasattr(self, 'audio_transceiver') or not self.audio_transceiver: return
            # Volume update
            if hasattr(self, 'volume_bar') and self.volume_bar.winfo_exists():
                with self.volume_lock: current_volume = min(1.0, max(0.0, self.volume))
                self.volume_bar.set(current_volume)

            # --- CHANGE: Updating the peer list with nicknames ---
            active_peers_data = {} # Dictionary {ip: nickname}
            current_speaker = None
            now = time.time()

            try:
                # Get a copy of the clients dictionary under lock
                with self.audio_transceiver.clients_lock:
                    active_peers_data = self.audio_transceiver.active_clients.copy()
            except AttributeError:
                 logging.warning("update_gui: audio_transceiver not found while accessing clients_lock.")
                 return

            # Determine the speaker and check for timeout/activity
            with self.speaker_lock:
                if self.currently_speaking_ip and (now - self.last_packet_played_time > SPEAKER_TIMEOUT_THRESHOLD):
                    logging.debug(f"Resetting speaker status for {self.currently_speaking_ip} due to timeout.")
                    self.currently_speaking_ip = None
                # Check if the speaker is still active (present in the dictionary)
                if self.currently_speaking_ip and self.currently_speaking_ip not in active_peers_data:
                     logging.debug(f"Speaker {self.currently_speaking_ip} is no longer in the list of active peers.")
                     self.currently_speaking_ip = None
                current_speaker = self.currently_speaking_ip

            # Update the text box
            if hasattr(self, 'peer_list_textbox') and self.peer_list_textbox.winfo_exists():
                try:
                     self.peer_list_textbox.configure(state="normal")
                     self.peer_list_textbox.delete("1.0", "end")

                     # Sort IP addresses for stable display
                     sorted_ips = sorted(active_peers_data.keys())

                     if sorted_ips:
                         for peer_ip in sorted_ips:
                             info = active_peers_data.get(peer_ip, {})
                             nickname = info.get('nickname', '')
                             display_name = nickname if nickname else peer_ip # Use nickname if available, otherwise IP
                             prefix = "* " if peer_ip == current_speaker else "  "
                             self.peer_list_textbox.insert("end", f"{prefix}{display_name}\n")
                     else:
                         self.peer_list_textbox.insert("end", " (no other peers)")

                     self.peer_list_textbox.configure(state="disabled")
                except tkinter.TclError as e:
                     logging.warning(f"Error updating peer_list_textbox (widget might be destroyed): {e}")
            # ------------------------------------------------------

            # Schedule the next update
            if hasattr(self, 'audio_transceiver') and not self.audio_transceiver.shutdown_event.is_set():
                 self.after(100, self.update_gui)
        except Exception as e: logging.exception("Unexpected error in update_gui")

    # --- on_press, on_release, update_led, on_closing ---
    def on_press(self, event=None):
        if not self.is_pressing:
            logging.info("Transmission started (button/space pressed)")
            self.is_pressing = True
            self.update_led(True)
            if hasattr(self, 'talk_btn') and self.talk_btn.winfo_exists(): self.talk_btn.configure(fg_color="#00A853")

    def on_release(self, event=None):
        if self.is_pressing:
            logging.info("Transmission stopped (button/space released)")
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
        """Window closing handler"""
        logging.info("Received window closing signal (WM_DELETE_WINDOW).")
        if hasattr(self, 'audio_transceiver') and self.audio_transceiver: self.audio_transceiver.cleanup()
        logging.info("Destroying GUI window...")
        try:
             self.unbind("<KeyPress-space>"); self.unbind("<KeyRelease-space>"); self.unbind("<Button-1>")
             self.destroy()
        except Exception as e: logging.exception("Error during main window destruction")
        logging.info("Application finished.")

# --- Entry point ---
if __name__ == "__main__":
    load_config()
    setup_logging()
    try:
        gui_conf = config.get('gui', {})
        appearance_mode = gui_conf.get('appearance_mode', 'dark').lower()
        if appearance_mode not in ['dark', 'light', 'system']: logging.warning(f"Incorrect theme mode '{appearance_mode}' in config. Using 'dark'."); appearance_mode = 'dark'
        ctk.set_appearance_mode(appearance_mode)
        logging.info(f"Interface theme set to: {appearance_mode}")
    except Exception as e: logging.exception("Error setting interface theme from config."); ctk.set_appearance_mode("dark")
    try:
        if not hasattr(opuslib, 'Encoder'): raise ImportError("opuslib does not contain expected attributes.")
        logging.info(f"opuslib library found and imported.")
    except ImportError: message = "Critical error: opuslib library not found. Install it: pip install opuslib"; print(message); logging.critical(message); sys.exit(1)
    except Exception as e: message = f"Unexpected error while checking opuslib: {e}"; print(message); logging.critical(message); sys.exit(1)
    try:
        # Passing only the gui part of the config to the selector
        selector = AudioSelector(gui_config=config.get('gui', {}))
        # The main loop of the selector will launch the main window if selection is successful
        selector.mainloop()
    except Exception as e: logging.exception("Critical unhandled error at the top level"); sys.exit(1)
    logging.info("="*20 + " Application finished normally " + "="*20)
    print("Application finished.")        
    