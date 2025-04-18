# -*- coding: utf-8 -*-
import customtkinter as ctk
import sounddevice as sd
import socket
import threading
import numpy as np
from PIL import Image, ImageTk
import struct
import time
import queue # <-- Needed for volume queue
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
        "user": {
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

# --- load_config, setup_logging functions (no changes from original) ---
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
    def __init__(self, user_config, net_config, audio_config):
        self.user_config = user_config
        self.net_config = net_config
        self.audio_config = audio_config
        self.nickname = self.user_config.get('nickname', '').strip()

        try:
            self.local_ip = socket.gethostbyname(socket.gethostname())
        except socket.gaierror:
             logging.warning("Failed to determine local IP by hostname, using '127.0.0.1'")
             self.local_ip = "127.0.0.1"

        # Stores {ip: {'nickname': str, 'last_seen': float}}
        self.active_clients = {}
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
        time.sleep(0.2) # Give threads a moment to notice the event
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
            nickname_bytes = self.nickname.encode('utf-8')
            ping_packet = self.packet_type_ping + nickname_bytes
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

                # Ignore packets from self
                if addr[0] == self.local_ip: continue

                # Audio packet
                if data.startswith(self.packet_type_audio):
                    opus_packet = data[len(self.packet_type_audio):]
                    packet_tuple = (addr[0], opus_packet)
                    try:
                        self.received_opus_packets.put_nowait(packet_tuple)
                        logging.debug(f"Audio packet ({len(opus_packet)} bytes from {addr[0]}) added to queue.")
                    except queue.Full:
                        try:
                            # Drop oldest packet if queue is full
                            dropped_tuple = self.received_opus_packets.get_nowait()
                            self.received_opus_packets.put_nowait(packet_tuple)
                            logging.warning(f"Audio packet queue full. Dropped packet from {dropped_tuple[0]}. Added new from {addr[0]}.")
                        except queue.Empty: pass # Should not happen here
                        except queue.Full: logging.warning("Queue is full even after removal, new audio packet skipped.")

                # Ping packet
                elif data.startswith(self.packet_type_ping):
                    nickname_bytes = data[len(self.packet_type_ping):]
                    try:
                        nickname = nickname_bytes.decode('utf-8', errors='replace').strip()
                    except Exception as e:
                        logging.warning(f"Failed to decode nickname from PING from {addr[0]}: {e}")
                        nickname = "" # Use empty nick on error

                    with self.clients_lock:
                        # Update or create client record
                        client_info = self.active_clients.get(addr[0], {})
                        client_info['last_seen'] = time.time()
                        client_info['nickname'] = nickname # Save/update nick
                        self.active_clients[addr[0]] = client_info
                    logging.info(f"Received PING from {addr[0]} (Nick: '{nickname}'). Client active.")

                # Unknown packet
                else:
                    logging.warning(f"Received unknown packet type from {addr}: {data[:10]}...")

            except socket.timeout:
                 continue # Normal if no data received
            except socket.error as e:
                 if self.shutdown_event.is_set():
                     logging.info("Socket closed, receiving thread is terminating.")
                     break
                 else:
                     if not self.shutdown_event.is_set(): logging.error(f"Socket error while receiving packet: {e}")
                     time.sleep(0.1) # Avoid busy-looping on persistent errors
            except Exception as e:
                  if not self.shutdown_event.is_set(): logging.exception("Unexpected error in receive_packets")

        logging.info("Packet reception thread finished.")

    def decode_audio(self, opus_packet):
        """Decodes an Opus packet into PCM"""
        try:
            pcm_data = self.decoder.decode(opus_packet, self.block_size)
            logging.debug(f"Decoded packet {len(opus_packet)} bytes -> {len(pcm_data)} bytes PCM")
            return pcm_data
        except opuslib.OpusError as e:
            logging.error(f"Error decoding Opus packet ({len(opus_packet)} bytes): {e}")
            return None
        except Exception as e:
            logging.exception(f"Unexpected error decoding packet ({len(opus_packet)} bytes)")
            return None

    def get_decoded_audio_packet(self):
        """Retrieves an Opus packet from the queue and decodes it. Returns (sender_ip, audio_data) or None."""
        try:
            sender_ip, opus_packet = self.received_opus_packets.get_nowait()
            decoded_pcm = self.decode_audio(opus_packet)
            if decoded_pcm:
                 audio_data = np.frombuffer(decoded_pcm, dtype=self.dtype)
                 expected_size = self.block_size * self.channels
                 if audio_data.size == expected_size:
                     return sender_ip, audio_data
                 else:
                     logging.warning(f"Unexpected size of decoded packet from {sender_ip} ({audio_data.size} instead of {expected_size})")
                     return None # Or maybe return (sender_ip, None) ? Returning None seems safer.
            else:
                 return None # Decoding failed
        except queue.Empty:
            return None # No packets available
        except Exception as e:
            logging.exception("Unexpected error in get_decoded_audio_packet")
            return None

    def cleanup_inactive_clients(self):
        """Cleanup of inactive clients"""
        current_time = time.time()
        inactive_ips = []
        client_timeout = self.net_config.get('client_timeout_sec', 5)

        # Use a copy of keys for safe iteration while checking
        with self.clients_lock:
            all_client_ips = list(self.active_clients.keys())

        for ip in all_client_ips:
            last_seen = None
            with self.clients_lock:
                # Re-check if client still exists before getting last_seen
                client_info = self.active_clients.get(ip)
                if client_info:
                    last_seen = client_info.get('last_seen')

            if last_seen is None: continue # Client might have been removed by another thread/check

            if current_time - last_seen > client_timeout:
                inactive_ips.append(ip)

        if inactive_ips:
            logging.debug(f"Candidates for removal due to timeout: {inactive_ips}")
            with self.clients_lock:
                for ip in inactive_ips:
                    # Double-check timeout condition before removing inside the lock
                    client_info = self.active_clients.get(ip)
                    if client_info and current_time - client_info.get('last_seen', 0) > client_timeout:
                        nickname = client_info.get('nickname', '')
                        logging.info(f"Removing inactive client: {ip} (Nickname: '{nickname}', last seen: {current_time - client_info.get('last_seen', 0):.1f} seconds ago)")
                        del self.active_clients[ip]
                    else:
                        # Log if the client was either removed already or became active again between checks
                        logging.debug(f"Client {ip} no longer candidate for removal or already removed.")


# --- GUI Device Selection ---
class AudioSelector(ctk.CTk):
    def __init__(self, gui_config):
        super().__init__()
        self.gui_config = gui_config
        self.title("Select audio devices")
        geometry = self.gui_config.get('selector_geometry', '500x350')
        try:
            self.geometry(geometry)
        except Exception as e:
            logging.warning(f"Incorrect geometry for AudioSelector in config ('{geometry}'): {e}. Using 500x350.")
            self.geometry("500x350")
        self.resizable(False, False)
        self.input_device_index = None
        self.output_device_index = None
        self.create_widgets()
        self.bind("<Escape>", lambda e: self.destroy())

    def create_widgets(self):
        ctk.CTkLabel(self, text="Select microphone:", font=("Arial", 14)).pack(pady=10)
        input_devices = self.get_device_list(input=True)
        self.input_combo = ctk.CTkComboBox(self, values=input_devices, width=400)
        if input_devices:
            self.input_combo.set(input_devices[0])
        else:
            logging.warning("No input devices found.")
            self.input_combo.set("No input devices found")
            self.input_combo.configure(state="disabled")
        self.input_combo.pack()

        ctk.CTkLabel(self, text="Select output device:", font=("Arial", 14)).pack(pady=20)
        output_devices = self.get_device_list(output=True)
        self.output_combo = ctk.CTkComboBox(self, values=output_devices, width=400)
        if output_devices:
            self.output_combo.set(output_devices[0])
        else:
            logging.warning("No output devices found.")
            self.output_combo.set("No output devices found")
            self.output_combo.configure(state="disabled")
        self.output_combo.pack()

        self.continue_button = ctk.CTkButton(self, text="Continue", command=self.validate_and_launch)
        if not input_devices or not output_devices:
            self.continue_button.configure(state="disabled")
        self.continue_button.pack(pady=30)

        self.error_label = ctk.CTkLabel(self, text="", text_color="red", font=("Arial", 12))
        self.error_label.pack(pady=(0, 10))

        self.after(100, lambda: self.focus_force()) # Try to grab focus

    def get_device_list(self, input=False, output=False):
        try:
            devices = sd.query_devices()
            device_list = []
            default_device_index = sd.query_hostapis()[0]['default_input_device'] if input else sd.query_hostapis()[0]['default_output_device']
            default_device_name = ""

            for i, dev in enumerate(devices):
                if not dev or not isinstance(dev, dict) or not dev.get('name'):
                    logging.warning(f"Skipping invalid device with index {i}: {dev}")
                    continue

                is_input = dev.get('max_input_channels', 0) > 0
                is_output = dev.get('max_output_channels', 0) > 0

                if (input and is_input) or (output and is_output):
                     try:
                         device_name = f"{i}: {dev['name']}"
                         device_list.append(device_name)
                         if i == default_device_index:
                             default_device_name = device_name
                     except Exception as enc_e:
                         logging.warning(f"Problem processing device name {i}: {dev.get('name')}. Error: {enc_e}. Skipping.")

            logging.info(f"Found {'input' if input else 'output'} devices: {len(device_list)}")

            # Try to set the default device if found
            if default_device_name and default_device_name in device_list:
                 if input and hasattr(self, 'input_combo'):
                     self.input_combo.set(default_device_name)
                 elif output and hasattr(self, 'output_combo'):
                     self.output_combo.set(default_device_name)

            return device_list
        except sd.PortAudioError as e:
            logging.exception("PortAudio error while getting device list")
            self._update_error_label(f"Error reading devices: {e}")
            return []
        except Exception as e:
            logging.exception("Unexpected error while getting device list")
            self._update_error_label("Critical error reading devices!")
            return []

    def _update_error_label(self, text):
         """Safely updates the error label."""
         if hasattr(self, 'error_label') and self.error_label.winfo_exists():
              self.error_label.configure(text=text)

    def validate_and_launch(self):
        input_selection = self.input_combo.get()
        output_selection = self.output_combo.get()
        try:
            if not input_selection or not output_selection or "No devices found" in input_selection or "No devices found" in output_selection:
                 raise ValueError("Input or output device not selected or not available.")
            if ":" not in input_selection or ":" not in output_selection:
                 raise ValueError("Incorrect format of the selected device.")

            self.input_device_index = int(input_selection.split(":")[0])
            self.output_device_index = int(output_selection.split(":")[0])
            logging.info(f"Selected devices: Input={self.input_device_index} ('{input_selection}'), Output={self.output_device_index} ('{output_selection}')")

            global config
            audio_cfg = config.get('audio', {})
            rate = audio_cfg.get('sample_rate', 48000)
            chans = audio_cfg.get('channels', 1)
            dtype = audio_cfg.get('dtype', 'int16')

            # Check if devices support the required settings
            try:
                 logging.debug(f"Checking input settings: dev={self.input_device_index}, rate={rate}, chans={chans}, dtype={dtype}")
                 sd.check_input_settings(device=self.input_device_index, channels=chans, samplerate=rate, dtype=dtype)
                 logging.debug(f"Checking output settings: dev={self.output_device_index}, rate={rate}, chans={chans}, dtype={dtype}")
                 sd.check_output_settings(device=self.output_device_index, channels=chans, samplerate=rate, dtype=dtype)
                 logging.info("Audio device settings checked successfully.")
            except sd.PortAudioError as pa_err:
                 logging.error(f"PortAudio settings check error: {pa_err}")
                 raise ValueError(f"Device does not support required settings ({rate}Hz, {chans}ch, {dtype}): {pa_err}")
            except ValueError as val_err: # Catches invalid device indices etc.
                 logging.error(f"sounddevice settings check error (ValueError): {val_err}")
                 raise ValueError(f"Incorrect device index or configuration error: {val_err}")
            except Exception as e:
                 logging.exception("Unexpected error during sounddevice settings check")
                 raise ValueError(f"Unexpected device check error: {e}")

            self._update_error_label("") # Clear errors if check passed
            self.destroy() # Close selector window

            # Launch the main application window
            main_app = VoxShareGUI(
                input_device_index=self.input_device_index,
                output_device_index=self.output_device_index,
                user_config=config.get('user', {}),
                gui_config=self.gui_config,
                net_config=config.get('network',{}),
                audio_config=config.get('audio',{})
                )
            main_app.mainloop()

        except (ValueError, AttributeError, IndexError, TypeError) as e: # Catch more potential issues
            error_message = f"Selection or validation error: {e}"
            logging.warning(f"Device selection validation error: {e}")
            self._update_error_label(error_message)
        except Exception as e:
            logging.exception("Unexpected error during validation and launch")
            self._update_error_label("A critical error occurred!")


# --- Main Application GUI ---
class VoxShareGUI(ctk.CTk):
    def __init__(self, input_device_index, output_device_index, user_config, gui_config, net_config, audio_config):
        super().__init__()
        self.user_config = user_config
        self.gui_config = gui_config
        self.net_config = net_config
        self.audio_config = audio_config

        self.title("VoxShare")
        geometry = self.gui_config.get('main_geometry', '550x450')
        try:
            self.geometry(geometry)
        except Exception as e:
            logging.warning(f"Incorrect geometry for VoxShareGUI in config ('{geometry}'): {e}. Using 550x450.")
            self.geometry("550x450")
        self.resizable(False, False)

        self.input_device_index = input_device_index
        self.output_device_index = output_device_index
        self.is_pressing = False

        # --- MODIFIED: Removed self.volume and self.volume_lock ---
        # self.volume = 0.0
        # self.volume_lock = Lock()
        self.volume_queue = queue.Queue(maxsize=5) # Queue for volume updates from audio thread

        self.currently_speaking_ip = None
        self.last_packet_played_time = 0
        self.speaker_lock = Lock() # Lock for currently_speaking_ip and last_packet_played_time

        try:
            # Initialize the network/audio handler
            self.audio_transceiver = AudioTransceiver(
                user_config=self.user_config,
                net_config=self.net_config,
                audio_config=self.audio_config
                )
        except RuntimeError as e:
            logging.exception("Critical error during AudioTransceiver initialization")
            # Optionally show an error message box before destroying
            # messagebox.showerror("Initialization Error", f"Failed to initialize audio/network: {e}")
            self.destroy()
            return # Prevent further initialization if transceiver fails
        except Exception as e:
            logging.exception("Unexpected critical error during AudioTransceiver initialization")
            # messagebox.showerror("Initialization Error", f"An unexpected error occurred: {e}")
            self.destroy()
            return

        self.setup_gui()
        self.start_threads()
        self.protocol("WM_DELETE_WINDOW", self.on_closing) # Handle window close button
        logging.info("Main VoxShareGUI window initialized.")
        self.after(100, lambda: self.focus_force()) # Try to grab focus

    def setup_gui(self):
        """GUI configuration"""
        top_frame = ctk.CTkFrame(self, fg_color="transparent")
        top_frame.pack(pady=10, padx=10, fill="x")
        ctk.CTkLabel(top_frame, text="VoxShare", font=("Arial", 24)).pack()

        middle_frame = ctk.CTkFrame(self, fg_color="transparent")
        middle_frame.pack(pady=10, padx=10, fill="both", expand=True)

        # Logo
        logo_widget = None
        try:
            logo_path = resource_path(os.path.join("Icons", "logo.png"))
            img = Image.open(logo_path).resize((150, 150), Image.Resampling.LANCZOS)
            self.logo_img = ctk.CTkImage(light_image=img, dark_image=img, size=(150, 150))
            logo_widget = ctk.CTkLabel(middle_frame, image=self.logo_img, text="")
            logging.debug(f"Logo loaded from {logo_path}")
        except FileNotFoundError:
            logging.warning("File logo.png not found.")
            logo_widget = ctk.CTkLabel(middle_frame, text="[Logo Not Found]", width=150, height=150, fg_color="grey")
        except Exception as e:
            logging.warning(f"Failed to load or process logo.png: {e}. Path attempted: {logo_path if 'logo_path' in locals() else 'Unknown'}")
            logo_widget = ctk.CTkLabel(middle_frame, text="[Logo Load Error]", width=150, height=150, fg_color="grey")
        if logo_widget:
            logo_widget.pack(side="left", padx=(0, 20), anchor="n")

        # Peer List
        peer_list_frame = ctk.CTkFrame(middle_frame)
        peer_list_frame.pack(side="left", fill="both", expand=True)
        ctk.CTkLabel(peer_list_frame, text="Peers:", font=("Arial", 14)).pack(anchor="w", padx=5)
        self.peer_list_textbox = ctk.CTkTextbox(peer_list_frame, font=("Arial", 12), wrap="none")
        self.peer_list_textbox.pack(side="top", fill="both", expand=True, padx=5, pady=(0,5))
        self.peer_list_textbox.configure(state="disabled") # Make it read-only

        # Bottom controls
        bottom_frame = ctk.CTkFrame(self, fg_color="transparent")
        bottom_frame.pack(side="bottom", pady=10, padx=10, fill="x")
        bottom_frame.columnconfigure(0, weight=1) # Make the central column expandable

        # LED indicator (aligned center)
        self.led = ctk.CTkLabel(bottom_frame, text="", width=30, height=30, corner_radius=15, fg_color="#D50000")
        self.led.grid(row=0, column=0, padx=10, pady=(5, 2), sticky="") # Aligned center

        # Volume bar (centered below LED)
        self.volume_bar = ctk.CTkProgressBar(bottom_frame, height=20, width=200) # Added width
        self.volume_bar.set(0)
        self.volume_bar.grid(row=1, column=0, padx=50, pady=2, sticky="ew") # Span centrally

        # Talk button (centered below volume bar)
        self.talk_btn = ctk.CTkButton(bottom_frame, text="Speak (Hold Space)", height=40, font=("Arial", 16))
        self.talk_btn.grid(row=2, column=0, padx=50, pady=(5, 5), sticky="ew") # Span centrally

        # Bindings
        self.talk_btn.bind("<ButtonPress-1>", self.on_press)
        self.talk_btn.bind("<ButtonRelease-1>", self.on_release)
        # Bind spacebar globally to the window
        self.bind("<KeyPress-space>", self.on_press)
        self.bind("<KeyRelease-space>", self.on_release)
        # Set focus to the main window on click to ensure keybindings work
        self.bind("<Button-1>", lambda event: self.focus_set())

        logging.debug("GUI elements of the main window created and placed.")


    def start_threads(self):
        """Starting worker threads"""
        if not hasattr(self, 'audio_transceiver') or not self.audio_transceiver:
            logging.error("Error: audio_transceiver not initialized, threads not started.")
            return

        logging.info("Starting worker threads...")
        self.input_thread = threading.Thread(target=self.audio_input_thread, name="AudioInputThread", daemon=True)
        self.output_thread = threading.Thread(target=self.audio_output_thread, name="AudioOutputThread", daemon=True)
        self.receive_thread = threading.Thread(target=self.receive_thread, name="ReceiveThread", daemon=True)
        self.ping_thread = threading.Thread(target=self.ping_thread, name="PingThread", daemon=True)
        self.cleanup_thread = threading.Thread(target=self.client_cleanup_thread, name="ClientCleanupThread", daemon=True)

        self.input_thread.start()
        self.output_thread.start()
        self.receive_thread.start()
        self.ping_thread.start()
        self.cleanup_thread.start()

        # Start the GUI update loop
        self.after(100, self.update_gui)
        logging.info("All worker threads started.")

    def audio_input_thread(self):
        """Thread for capturing audio, encoding, and sending"""
        if not hasattr(self, 'audio_transceiver'): return # Should not happen if start_threads checks

        sample_rate = self.audio_transceiver.sample_rate
        channels = self.audio_transceiver.channels
        blocksize = self.audio_transceiver.block_size
        dtype = self.audio_transceiver.dtype

        def callback(indata: np.ndarray, frames: int, time_info, status: sd.CallbackFlags):
            """Callback function for the input stream."""
            if status:
                logging.warning(f"Input callback status: {status}")

            # Check if we should process audio (not shutting down and button pressed)
            if not self.audio_transceiver.shutdown_event.is_set() and self.is_pressing:
                try:
                    # 1. Send audio data
                    pcm_data_bytes = indata.tobytes()
                    self.audio_transceiver.encode_and_send_audio(pcm_data_bytes)

                    # 2. Calculate volume
                    # Convert to float for RMS calculation, normalize to [-1.0, 1.0]
                    float_data = indata.astype(np.float32) / 32768.0
                    rms = np.sqrt(np.mean(np.square(float_data)))
                    # Amplify RMS for better visibility on the bar, needs tuning
                    calculated_volume = float(rms) * 2.5 # Adjust multiplier as needed

                    # --- MODIFIED: Put volume into queue ---
                    try:
                        # Clear old values if queue is full to keep the latest
                        while self.volume_queue.full():
                            try: self.volume_queue.get_nowait()
                            except queue.Empty: break # Just in case
                        self.volume_queue.put_nowait(calculated_volume)
                    except queue.Full: # Should be rare after the clearing loop
                         pass
                    except Exception as q_err:
                         logging.warning(f"Error putting volume in queue: {q_err}")
                    # --- END MODIFICATION ---

                except Exception as e:
                    # Log exceptions occurring within the callback processing
                    logging.exception(f"Error in audio_input callback during transmission")
            else:
                # --- MODIFIED: Put zero volume when not pressing ---
                # If not pressing or shutting down, ensure volume bar shows zero
                if not self.is_pressing or self.audio_transceiver.shutdown_event.is_set():
                    try:
                        while self.volume_queue.full():
                           try: self.volume_queue.get_nowait()
                           except queue.Empty: break
                        self.volume_queue.put_nowait(0.0) # Put zero volume
                    except queue.Full:
                        pass
                    except Exception as q_err:
                        logging.warning(f"Error putting zero volume in queue: {q_err}")
                # --- END MODIFICATION ---

        # Main part of the input thread: Open and manage the stream
        try:
            logging.info(f"Opening InputStream: Device={self.input_device_index}, Rate={sample_rate}, Block={blocksize}, Dtype={dtype}, Channels={channels}")
            # Use InputStream as a context manager
            with sd.InputStream(samplerate=sample_rate,
                                channels=channels,
                                dtype=dtype,
                                callback=callback,
                                blocksize=blocksize,
                                device=self.input_device_index):
                logging.info("InputStream opened. Waiting for shutdown signal...")
                # Wait until the shutdown event is set
                self.audio_transceiver.shutdown_event.wait()
        except sd.PortAudioError as e:
            logging.exception(f"Critical audio input error (PortAudioError) Device={self.input_device_index}")
            # Consider notifying the user or attempting recovery if possible
        except Exception as e:
            logging.exception(f"Critical audio input error (Other) Device={self.input_device_index}")
            # General catch-all for unexpected errors during stream setup or operation

        logging.info("Audio input thread is shutting down.")


    def audio_output_thread(self):
        """Thread for receiving decoded audio and playing it"""
        if not hasattr(self, 'audio_transceiver'): return

        sample_rate = self.audio_transceiver.sample_rate
        channels = self.audio_transceiver.channels
        blocksize = self.audio_transceiver.block_size
        dtype = self.audio_transceiver.dtype

        def callback(outdata: np.ndarray, frames: int, time_info, status: sd.CallbackFlags):
            """Callback function for the output stream."""
            if status:
                logging.warning(f"Output callback status: {status}")

            processed_ip = None # Track which IP's packet was played
            if not self.audio_transceiver.shutdown_event.is_set():
                # Attempt to get a decoded audio packet
                packet_info = self.audio_transceiver.get_decoded_audio_packet()

                if packet_info is not None:
                    sender_ip, audio_data = packet_info
                    # Check if data is valid and size matches expected frames
                    if audio_data is not None and audio_data.size == frames * channels:
                        # Reshape and copy data to output buffer
                        outdata[:] = audio_data.reshape(-1, channels)
                        processed_ip = sender_ip # Mark this IP as the one whose packet was played
                        logging.debug(f"Played audio packet {len(audio_data)} samples from {sender_ip}")
                    else:
                        # If data size mismatch or decoding failed previously
                        outdata.fill(0) # Play silence
                        if audio_data is not None: # Log only if size was wrong
                           logging.warning(f"Packet size mismatch from {sender_ip} ({audio_data.size} vs {frames * channels}), played silence.")
                else:
                    # No packet available in the queue, play silence
                    outdata.fill(0)

                # Update speaker status based on the packet just processed
                with self.speaker_lock:
                    if processed_ip: # If we played a valid packet
                        self.currently_speaking_ip = processed_ip
                        self.last_packet_played_time = time.time()
                    # No need for an else here, timeout check happens in update_gui
            else:
                 # If shutting down, fill with silence
                 outdata.fill(0)

        # Main part of the output thread
        try:
            logging.info(f"Opening OutputStream: Device={self.output_device_index}, Rate={sample_rate}, Block={blocksize}, Dtype={dtype}, Channels={channels}")
            with sd.OutputStream(samplerate=sample_rate,
                                 channels=channels,
                                 dtype=dtype,
                                 callback=callback,
                                 blocksize=blocksize,
                                 device=self.output_device_index):
                logging.info("OutputStream opened. Waiting for shutdown signal...")
                self.audio_transceiver.shutdown_event.wait()
        except sd.PortAudioError as e:
            logging.exception(f"Critical audio output error (PortAudioError) Device={self.output_device_index}")
        except Exception as e:
            logging.exception(f"Critical audio output error (Other) Device={self.output_device_index}")

        logging.info("Audio output thread is shutting down.")

    def receive_thread(self):
        """Wrapper for packet receiving"""
        if hasattr(self, 'audio_transceiver') and self.audio_transceiver:
            self.audio_transceiver.receive_packets()
        else:
            logging.error("ReceiveThread: audio_transceiver does not exist.")

    def ping_thread(self):
        """Periodically sends ping packets"""
        logging.info("Ping sending thread started.")
        if not hasattr(self, 'audio_transceiver') or not self.audio_transceiver:
            logging.error("PingThread: audio_transceiver does not exist.")
            return

        ping_interval = self.net_config.get('ping_interval_sec', 2)
        if ping_interval <= 0:
            logging.warning(f"Ping interval ({ping_interval}s) is zero or negative. Pinging disabled.")
            return

        while not self.audio_transceiver.shutdown_event.wait(timeout=ping_interval):
            self.audio_transceiver.send_ping()

        logging.info("Ping sending thread finished.") # MODIFIED Log Message

    def client_cleanup_thread(self):
        """Periodically cleans up inactive clients"""
        # --- MODIFIED Log Message ---
        logging.info("Client cleanup thread started.")
        if not hasattr(self, 'audio_transceiver') or not self.audio_transceiver:
            logging.error("ClientCleanupThread: audio_transceiver does not exist.")
            return

        # Use a slightly longer interval than pings to avoid race conditions
        cleanup_interval = max(1.0, self.net_config.get('ping_interval_sec', 2) * 1.5)
        logging.info(f"Client cleanup interval set to {cleanup_interval:.1f} seconds.")

        while not self.audio_transceiver.shutdown_event.wait(timeout=cleanup_interval):
             try:
                 self.audio_transceiver.cleanup_inactive_clients()
             except Exception as e:
                 logging.exception("Error during client cleanup") # Catch errors within the loop

        # --- MODIFIED Log Message ---
        logging.info("Client cleanup thread finished.")

    def update_gui(self):
        """GUI update loop (called via self.after in the main thread)"""
        try:
            # Check if window and transceiver still exist
            if not self.winfo_exists() or not hasattr(self, 'audio_transceiver') or not self.audio_transceiver:
                logging.info("update_gui: Window or audio_transceiver gone, stopping updates.")
                return

            # --- MODIFIED: Update volume bar from queue ---
            last_volume_update = None
            while not self.volume_queue.empty():
                try:
                    # Get the latest value from the queue
                    last_volume_update = self.volume_queue.get_nowait()
                except queue.Empty:
                    break # Should not happen with check, but safe practice
                except Exception as e:
                    logging.warning(f"Error getting volume from queue: {e}")

            # Update the progress bar only if a new value was received
            if last_volume_update is not None and hasattr(self, 'volume_bar') and self.volume_bar.winfo_exists():
                # Clamp the volume value to the range [0.0, 1.0]
                display_volume = min(1.0, max(0.0, last_volume_update))
                self.volume_bar.set(display_volume)
            # --- END MODIFICATION ---


            # --- Update peer list and speaker status ---
            active_peers_data = {} # {ip: {'nickname': str, 'last_seen': float}}
            current_speaker_ip = None
            now = time.time()

            # Get a safe copy of client data
            try:
                with self.audio_transceiver.clients_lock:
                    active_peers_data = self.audio_transceiver.active_clients.copy()
            except AttributeError: # Should not happen if initial check passed
                 logging.warning("update_gui: audio_transceiver lost while accessing clients_lock.")
                 return # Stop update if transceiver disappeared unexpectedly

            # Check speaker timeout and activity under lock
            with self.speaker_lock:
                # Reset speaker if timeout threshold exceeded
                if self.currently_speaking_ip and (now - self.last_packet_played_time > SPEAKER_TIMEOUT_THRESHOLD):
                    logging.debug(f"Resetting speaker status for {self.currently_speaking_ip} due to timeout.")
                    self.currently_speaking_ip = None

                # Reset speaker if they are no longer in the active client list
                if self.currently_speaking_ip and self.currently_speaking_ip not in active_peers_data:
                     logging.debug(f"Speaker {self.currently_speaking_ip} is no longer in the list of active peers, resetting.")
                     self.currently_speaking_ip = None

                current_speaker_ip = self.currently_speaking_ip # Get the current speaker after checks

            # Update the peer list text box
            if hasattr(self, 'peer_list_textbox') and self.peer_list_textbox.winfo_exists():
                try:
                     # Store current scroll position
                     # scroll_pos = self.peer_list_textbox.yview() # TODO: Check if CTkTextbox supports this easily

                     self.peer_list_textbox.configure(state="normal") # Enable writing
                     self.peer_list_textbox.delete("1.0", "end") # Clear content

                     # Sort IPs for consistent display order
                     sorted_ips = sorted(active_peers_data.keys())

                     if sorted_ips:
                         for peer_ip in sorted_ips:
                             info = active_peers_data.get(peer_ip, {}) # Default to empty dict if somehow missing
                             nickname = info.get('nickname', '')
                             # Use nickname if available, otherwise IP
                             display_name = nickname if nickname else peer_ip
                             # Add indicator for the current speaker
                             prefix = "* " if peer_ip == current_speaker_ip else "  "
                             self.peer_list_textbox.insert("end", f"{prefix}{display_name}\n")
                     else:
                         self.peer_list_textbox.insert("end", " (no other peers)")

                     self.peer_list_textbox.configure(state="disabled") # Disable writing

                     # Restore scroll position if possible
                     # self.peer_list_textbox.yview_moveto(scroll_pos[0]) # TODO: Check CTkTextbox scrolling API

                except tkinter.TclError as e:
                     # Handle cases where the widget might be destroyed during the update
                     logging.warning(f"Error updating peer_list_textbox (widget might be destroyed): {e}")
                except Exception as e:
                    logging.exception("Unexpected error updating peer list textbox")


            # --- Schedule the next GUI update ---
            # Check shutdown_event again before scheduling next update
            if hasattr(self, 'audio_transceiver') and not self.audio_transceiver.shutdown_event.is_set():
                 self.after(100, self.update_gui) # Reschedule

        except Exception as e:
            # Catch-all for unexpected errors in the update loop
            logging.exception("Unexpected error in update_gui loop")
            # Consider stopping the loop if errors persist
            # self.after(5000, self.update_gui) # Maybe retry after a delay?


    def on_press(self, event=None):
        """Handler for Speak button press or Spacebar press"""
        # Check if the event source is the button or the key (optional, for debugging)
        # source = "Button" if isinstance(event, tkinter.Event) and event.widget == self.talk_btn else "Key"
        # logging.debug(f"on_press triggered by {source}")

        if not self.is_pressing:
            logging.info("Transmission started (button/space pressed)")
            self.is_pressing = True
            self.update_led(True) # Turn LED green
            # Change button appearance
            if hasattr(self, 'talk_btn') and self.talk_btn.winfo_exists():
                 # Use a distinct color to show it's active
                 self.talk_btn.configure(fg_color="#00A853") # Example green color

    def on_release(self, event=None):
        """Handler for Speak button release or Spacebar release"""
        # source = "Button" if isinstance(event, tkinter.Event) and event.widget == self.talk_btn else "Key"
        # logging.debug(f"on_release triggered by {source}")

        if self.is_pressing:
            logging.info("Transmission stopped (button/space released)")
            self.is_pressing = False
            self.update_led(False) # Turn LED red

            # Restore button appearance
            if hasattr(self, 'talk_btn') and self.talk_btn.winfo_exists():
                try:
                    # Get the default theme color for the button
                    std_color = ctk.ThemeManager.theme["CTkButton"]["fg_color"]
                except (KeyError, AttributeError):
                    # Fallback colors if theme access fails
                    std_color = ("#3a7ebf", "#1f538d") # Default light/dark mode colors
                self.talk_btn.configure(fg_color=std_color)

            # --- MODIFIED: Remove direct volume update, keep progress bar reset ---
            # with self.volume_lock: self.volume = 0.0 # REMOVED

            # Reset volume bar directly (safe in GUI thread event handler)
            if hasattr(self, 'volume_bar') and self.volume_bar.winfo_exists():
                self.volume_bar.set(0.0)
            # --- END MODIFICATION ---


    def update_led(self, on):
        """Updates the color of the LED indicator."""
        color = "#00C853" if on else "#D50000" # Green for on, Red for off
        if hasattr(self, 'led') and self.led.winfo_exists():
            try:
                 self.led.configure(fg_color=color)
                 logging.debug(f"LED indicator set to {'ON' if on else 'OFF'} (Color: {color})")
            except Exception as e:
                 logging.error(f"Failed to update LED color: {e}")


    def on_closing(self):
        """Handler for window closing event (WM_DELETE_WINDOW)."""
        logging.info("Received window closing signal (WM_DELETE_WINDOW). Starting shutdown...")

        # 1. Signal all threads to stop by setting the event
        if hasattr(self, 'audio_transceiver') and self.audio_transceiver:
            logging.info("Signaling threads to stop via shutdown_event...")
            self.audio_transceiver.shutdown_event.set() # Signal threads first
            logging.info("Calling AudioTransceiver cleanup...")
            self.audio_transceiver.cleanup() # Close sockets etc.
        else:
            logging.warning("on_closing: audio_transceiver not found or already cleaned up.")

        # 2. Wait briefly for threads to potentially finish processing the event
        #    This is optional and might not guarantee threads fully exit,
        #    but gives them a chance before forceful exit.
        # time.sleep(0.3) # Adjust delay as needed

        # 3. Destroy the GUI window
        logging.info("Destroying GUI window...")
        try:
             # Unbind global keys if necessary, though destroying window should handle this
             # self.unbind("<KeyPress-space>")
             # self.unbind("<KeyRelease-space>")
             # self.unbind("<Button-1>")
             self.destroy()
        except Exception as e:
             logging.exception("Error during main window destruction")

        logging.info("Application shutdown process completed.")
        # Note: Daemon threads will exit automatically when the main thread exits.


# --- Entry point ---
if __name__ == "__main__":
    # 1. Load Configuration
    load_config()

    # 2. Setup Logging
    setup_logging()

    # 3. Set GUI Appearance
    try:
        gui_conf = config.get('gui', {})
        appearance_mode = gui_conf.get('appearance_mode', 'dark').lower()
        if appearance_mode not in ['dark', 'light', 'system']:
            logging.warning(f"Incorrect theme mode '{appearance_mode}' in config. Using 'dark'.")
            appearance_mode = 'dark'
        ctk.set_appearance_mode(appearance_mode)
        logging.info(f"Interface theme set to: {appearance_mode}")
    except Exception as e:
        logging.exception("Error setting interface theme from config. Using 'dark'.")
        ctk.set_appearance_mode("dark") # Fallback

    # 4. Check Critical Dependencies (Opus)
    try:
        # Basic check if opuslib and its core components seem available
        if not hasattr(opuslib, 'Encoder') or not hasattr(opuslib, 'Decoder'):
            raise ImportError("opuslib does not contain expected attributes (Encoder/Decoder).")
        logging.info(f"opuslib library found and seems functional.")
    except ImportError as e:
        message = f"Critical error: opuslib library missing or incomplete ({e}). Install it: pip install opuslib"
        print(message)
        logging.critical(message)
        sys.exit(1) # Exit if critical dependency is missing
    except Exception as e:
        message = f"Unexpected error while checking opuslib: {e}"
        print(message)
        logging.critical(message)
        sys.exit(1)

    # 5. Start the Application via the Audio Selector GUI
    try:
        # Pass only the 'gui' part of the config to the selector
        selector = AudioSelector(gui_config=config.get('gui', {}))
        # The main loop of the selector will handle device selection
        # and launch the main VoxShareGUI if successful.
        selector.mainloop()
        # Execution continues here only after selector AND main app window are closed
        logging.info("GUI main loops finished.")

    except Exception as e:
        logging.exception("Critical unhandled error at the top level")
        # Optionally show a final error message to the user
        # messagebox.showerror("Fatal Error", f"An unexpected critical error occurred:\n{e}")
        sys.exit(1) # Exit on critical failure

    logging.info("="*20 + " Application finished normally " + "="*20)
    print("Application finished.")