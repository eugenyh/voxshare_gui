# -*- coding: utf-8 -*-

"""
GUI components for the VoxShare application.
Includes the main application window (VoxShareGUI) and the audio device
selection dialog (AudioSelector).
"""

import customtkinter as ctk
import sounddevice as sd
from PIL import Image
import queue
from threading import Lock
import logging
import sys
import tkinter
from tkinter import messagebox
import os
import threading
import time
import numpy as np

from constants import INVALID_DEVICE_INDEX, SPEAKER_TIMEOUT_THRESHOLD
from utils import resource_path
import config_manager
from audio_core import AudioTransceiver

class AudioSelector(ctk.CTkToplevel):
    """
    A dialog window for selecting audio input and output devices.
    """
    def __init__(self, current_config, master=None):
        super().__init__(master)
        self.config = current_config
        self.audio_config = self.config.get('audio', {})
        self.gui_config = self.config.get('gui', {})

        self.title("Select Audio Devices")
        geometry = self.gui_config.get('selector_geometry', '500x350')
        try:
            self.geometry(geometry)
        except Exception as e:
            logging.warning(f"Incorrect geometry for AudioSelector ('{geometry}'): {e}. Using 500x350.")
            self.geometry("500x350")

        self.resizable(False, False)
        self.grab_set()
        self.focus_set()
        self.protocol("WM_DELETE_WINDOW", self._on_closing)

        self.selected_input_index = INVALID_DEVICE_INDEX
        self.selected_output_index = INVALID_DEVICE_INDEX
        self.selection_successful = False

        self.create_widgets()
        self.populate_devices()

    def _on_closing(self):
        """Handle window close button press."""
        logging.warning("AudioSelector closed without selection.")
        self.selection_successful = False
        self.destroy()

    def create_widgets(self):
        """Creates and places the widgets in the window."""
        ctk.CTkLabel(self, text="Select Microphone:", font=("Arial", 14)).pack(pady=10)
        self.input_combo = ctk.CTkComboBox(self, values=["Loading..."], width=400, state="readonly")
        self.input_combo.pack()

        ctk.CTkLabel(self, text="Select Output Device:", font=("Arial", 14)).pack(pady=20)
        self.output_combo = ctk.CTkComboBox(self, values=["Loading..."], width=400, state="readonly")
        self.output_combo.pack()

        self.continue_button = ctk.CTkButton(self, text="Confirm Selection", command=self.validate_save_and_close)
        self.continue_button.pack(pady=30)
        self.continue_button.configure(state="disabled")

        self.error_label = ctk.CTkLabel(self, text="", text_color="red", font=("Arial", 12))
        self.error_label.pack(pady=(0, 10))

    def populate_devices(self):
        """Get device lists and update comboboxes."""
        input_devices = self.get_device_list(input=True)
        output_devices = self.get_device_list(output=True)

        if input_devices:
            self.input_combo.configure(values=input_devices, state="readonly")
            saved_input_idx = self.audio_config.get('input_device_index', INVALID_DEVICE_INDEX)
            preselect_input = self.find_device_name_by_index(input_devices, saved_input_idx)
            if preselect_input:
                self.input_combo.set(preselect_input)
            else:
                 self.input_combo.set(input_devices[0])
        else:
            self.input_combo.configure(values=["No input devices found"], state="disabled")
            self.input_combo.set("No input devices found")

        if output_devices:
            self.output_combo.configure(values=output_devices, state="readonly")
            saved_output_idx = self.audio_config.get('output_device_index', INVALID_DEVICE_INDEX)
            preselect_output = self.find_device_name_by_index(output_devices, saved_output_idx)
            if preselect_output:
                 self.output_combo.set(preselect_output)
            else:
                 self.output_combo.set(output_devices[0])
        else:
             self.output_combo.configure(values=["No output devices found"], state="disabled")
             self.output_combo.set("No output devices found")

        if input_devices and output_devices:
            self.continue_button.configure(state="normal")
        else:
            self._update_error_label("Cannot continue: Missing input or output devices.")

    def find_device_name_by_index(self, device_list, index_to_find):
        """Helper to find the device string like 'index: name'."""
        if index_to_find == INVALID_DEVICE_INDEX:
            return None
        prefix = f"{index_to_find}: "
        for device_name in device_list:
            if device_name.startswith(prefix):
                return device_name
        return None

    def get_device_list(self, input=False, output=False):
        """Queries sounddevice and returns a list of 'index: name' strings."""
        devices_found = []
        try:
            devices = sd.query_devices()
            for i, dev in enumerate(devices):
                if not dev or not isinstance(dev, dict) or not dev.get('name'):
                    logging.warning(f"Skipping invalid device with index {i}: {dev}")
                    continue
                is_input = dev.get('max_input_channels', 0) > 0
                is_output = dev.get('max_output_channels', 0) > 0
                if (input and is_input) or (output and is_output):
                     try:
                         device_name_str = f"{i}: {dev['name']}"
                         devices_found.append(device_name_str)
                     except Exception as enc_e:
                         logging.warning(f"Problem processing device name {i}: {dev.get('name')}. Error: {enc_e}. Skipping.")
            logging.info(f"Found {'input' if input else 'output'} devices: {devices_found}")
            return devices_found
        except sd.PortAudioError as e:
            logging.exception("PortAudio error while getting device list")
            self._update_error_label(f"Error reading devices: {e}")
            return []
        except Exception as e:
            logging.exception("Unexpected error while getting device list")
            self._update_error_label("Critical error reading devices!")
            return []

    def _update_error_label(self, text):
         """Safely updates the error label text."""
         if hasattr(self, 'error_label') and self.error_label.winfo_exists():
              self.error_label.configure(text=text)

    def validate_save_and_close(self):
        """Validate selection, check compatibility, save to config, and close."""
        input_selection = self.input_combo.get()
        output_selection = self.output_combo.get()
        try:
            if not input_selection or not output_selection or "No devices found" in input_selection or "No devices found" in output_selection:
                 raise ValueError("Input or output device not selected or not available.")
            if ":" not in input_selection or ":" not in output_selection:
                 raise ValueError("Incorrect format of the selected device.")

            current_input_index = int(input_selection.split(":")[0])
            current_output_index = int(output_selection.split(":")[0])
            logging.info(f"Selected devices: Input={current_input_index} ('{input_selection}'), Output={current_output_index} ('{output_selection}')")

            rate = self.audio_config.get('sample_rate', 16000)
            chans = self.audio_config.get('channels', 1)
            dtype = self.audio_config.get('dtype', 'int16')
            try:
                 logging.debug(f"Checking input settings: dev={current_input_index}, rate={rate}, chans={chans}, dtype={dtype}")
                 sd.check_input_settings(device=current_input_index, channels=chans, samplerate=rate, dtype=dtype)
                 logging.debug(f"Checking output settings: dev={current_output_index}, rate={rate}, chans={chans}, dtype={dtype}")
                 sd.check_output_settings(device=current_output_index, channels=chans, samplerate=rate, dtype=dtype)
                 logging.info("Audio device settings checked successfully.")
            except sd.PortAudioError as pa_err:
                 logging.error(f"PortAudio settings check error: {pa_err}")
                 raise ValueError(f"Device does not support settings ({rate}Hz, {chans}ch, {dtype}): {pa_err}")
            except ValueError as val_err:
                 logging.error(f"sounddevice settings check error (ValueError): {val_err}")
                 raise ValueError(f"Incorrect device index or configuration error: {val_err}")
            except Exception as e:
                 logging.exception("Unexpected sounddevice settings check error")
                 raise ValueError(f"Device check error: {e}")

            self.config['audio']['input_device_index'] = current_input_index
            self.config['audio']['output_device_index'] = current_output_index
            if config_manager.save_config(self.config):
                logging.info("Selected device indices saved to configuration.")
                self.selected_input_index = current_input_index
                self.selected_output_index = current_output_index
                self.selection_successful = True
                self.destroy()
            else:
                 raise ValueError("Failed to save the configuration file.")

        except (ValueError, AttributeError, IndexError, TypeError) as e:
            error_message = f"Selection error: {e}"
            logging.warning(f"Device selection validation error: {e}")
            self._update_error_label(error_message)
            self.selection_successful = False
        except Exception as e:
            logging.exception("Unexpected error during validation and save")
            self._update_error_label("A critical error occurred!")
            self.selection_successful = False


class VoxShareGUI(ctk.CTk):
    """
    The main application window.
    """
    is_closing = False

    def __init__(self, app_config):
        super().__init__()
        self.config = app_config
        self.user_config = self.config.get('user', {})
        self.gui_config = self.config.get('gui', {})
        self.net_config = self.config.get('network', {})
        self.audio_config = self.config.get('audio', {})

        self.input_device_index = self.audio_config.get('input_device_index', INVALID_DEVICE_INDEX)
        self.output_device_index = self.audio_config.get('output_device_index', INVALID_DEVICE_INDEX)
        if self.input_device_index == INVALID_DEVICE_INDEX or self.output_device_index == INVALID_DEVICE_INDEX:
             logging.critical("VoxShareGUI launched with invalid device indices in config!")
             messagebox.showerror("Configuration Error", "Application started with invalid audio device settings.")
             self.destroy()
             return

        self.title("VoxShare")
        geometry = self.gui_config.get('main_geometry', '550x450')
        try: self.geometry(geometry)
        except Exception as e: logging.warning(f"Incorrect geometry ('{geometry}'): {e}. Using 550x450."); self.geometry("550x450")
        self.resizable(False, False)

        self.is_pressing = False
        self.volume_queue = queue.Queue(maxsize=5)
        self.currently_speaking_ip = None
        self.last_packet_played_time = 0
        self.speaker_lock = Lock()
        self.audio_transceiver = None
        self.input_thread = None
        self.output_thread = None
        self.receive_thread = None
        self.ping_thread = None
        self.cleanup_thread = None

        self.setup_gui()
        if not self.setup_audio_subsystem():
             messagebox.showerror("Audio Error", "Failed to initialize audio system. Check logs.")
             logging.critical("Failed to setup audio subsystem during GUI init.")

        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        logging.info("Main VoxShareGUI window initialized.")
        self.after(100, lambda: self.focus_force())

    def setup_gui(self):
        """GUI configuration"""
        top_frame = ctk.CTkFrame(self, fg_color="transparent")
        top_frame.pack(pady=10, padx=10, fill="x")

        try:
            settings_icon_path = resource_path(os.path.join("Icons", "settings_icon.png"))
            img = Image.open(settings_icon_path).resize((24, 24), Image.Resampling.LANCZOS)
            self.settings_icon = ctk.CTkImage(light_image=img, dark_image=img, size=(24, 24))
            settings_button = ctk.CTkButton(top_frame, image=self.settings_icon, text="", width=30, command=self.open_audio_settings)
            logging.debug(f"Settings icon loaded from {settings_icon_path}")
        except FileNotFoundError:
            logging.warning("File settings_icon.png not found. Using text button.")
            settings_button = ctk.CTkButton(top_frame, text="Settings", width=60, command=self.open_audio_settings)
        except Exception as e:
            logging.warning(f"Failed to load settings_icon.png: {e}. Using text button.")
            settings_button = ctk.CTkButton(top_frame, text="Settings", width=60, command=self.open_audio_settings)
        settings_button.pack(side="right", padx=(0, 10))

        middle_frame = ctk.CTkFrame(self, fg_color="transparent")
        middle_frame.pack(pady=10, padx=10, fill="both", expand=True)

        logo_text_frame = ctk.CTkFrame(middle_frame, fg_color="transparent")
        logo_text_frame.pack(side="left", padx=(0, 20), anchor="n")

        logo_widget = None
        try:
            logo_path = resource_path(os.path.join("Icons", "logo.png"))
            img = Image.open(logo_path).resize((150, 150), Image.Resampling.LANCZOS)
            self.logo_img = ctk.CTkImage(light_image=img, dark_image=img, size=(150, 150))
            logo_widget = ctk.CTkLabel(logo_text_frame, image=self.logo_img, text="")
            logging.debug(f"Logo loaded from {logo_path}")
        except FileNotFoundError:
            logging.warning("File logo.png not found.")
            logo_widget = ctk.CTkLabel(logo_text_frame, text="[Logo]", width=150, height=150, fg_color="grey")
        except Exception as e:
            logging.warning(f"Failed to load or process logo.png: {e}.")
            logo_widget = ctk.CTkLabel(logo_text_frame, text="[Logo Error]", width=150, height=150, fg_color="grey")
        if logo_widget:
            logo_widget.pack()

        ctk.CTkLabel(logo_text_frame, text="VoxShare", font=("Arial", 24)).pack(pady=(10, 0))

        peer_list_frame = ctk.CTkFrame(middle_frame)
        peer_list_frame.pack(side="left", fill="both", expand=True)
        ctk.CTkLabel(peer_list_frame, text="Peers:", font=("Arial", 14)).pack(anchor="w", padx=5)
        self.peer_list_textbox = ctk.CTkTextbox(peer_list_frame, font=("Arial", 12), wrap="none")
        self.peer_list_textbox.pack(side="top", fill="both", expand=True, padx=5, pady=(0,5))
        self.peer_list_textbox.configure(state="disabled")

        bottom_frame = ctk.CTkFrame(self, fg_color="transparent")
        bottom_frame.pack(side="bottom", pady=10, padx=10, fill="x")
        bottom_frame.columnconfigure(0, weight=1)
        self.led = ctk.CTkLabel(bottom_frame, text="", width=30, height=30, corner_radius=15, fg_color="#D50000")
        self.led.grid(row=0, column=0, padx=10, pady=(5, 2), sticky="w")
        self.volume_bar = ctk.CTkProgressBar(bottom_frame, height=20, width=200)
        self.volume_bar.set(0)
        self.volume_bar.grid(row=1, column=0, padx=50, pady=2, sticky="ew")
        self.talk_btn = ctk.CTkButton(bottom_frame, text="Speak (Hold Space)", height=40, font=("Arial", 16))
        self.talk_btn.grid(row=2, column=0, padx=50, pady=(5, 5), sticky="ew")

        self.talk_btn.bind("<ButtonPress-1>", self.on_press)
        self.talk_btn.bind("<ButtonRelease-1>", self.on_release)
        self.bind("<KeyPress-space>", self.on_press)
        self.bind("<KeyRelease-space>", self.on_release)
        self.bind("<Button-1>", lambda event: self.focus_set())
        logging.debug("GUI elements created and placed.")

    def setup_audio_subsystem(self):
        """Initializes AudioTransceiver and starts all related threads."""
        logging.info("Setting up audio subsystem...")
        if self.input_device_index == INVALID_DEVICE_INDEX or self.output_device_index == INVALID_DEVICE_INDEX:
             logging.error("Cannot setup audio subsystem: Invalid device indices.")
             return False
        try:
            self.audio_transceiver = AudioTransceiver(
                user_config=self.user_config,
                net_config=self.net_config,
                audio_config=self.audio_config
            )
            logging.info("Starting worker threads...")
            self.input_thread = threading.Thread(target=self.audio_input_thread_func, name="AudioInputThread", daemon=True)
            self.output_thread = threading.Thread(target=self.audio_output_thread_func, name="AudioOutputThread", daemon=True)
            self.receive_thread = threading.Thread(target=self.receive_thread_func, name="ReceiveThread", daemon=True)
            self.ping_thread = threading.Thread(target=self.ping_thread_func, name="PingThread", daemon=True)
            self.cleanup_thread = threading.Thread(target=self.client_cleanup_thread_func, name="ClientCleanupThread", daemon=True)

            self.input_thread.start()
            self.output_thread.start()
            self.receive_thread.start()
            self.ping_thread.start()
            self.cleanup_thread.start()

            self.after(100, self.update_gui)
            logging.info("Audio subsystem and threads started successfully.")
            return True

        except RuntimeError as e:
            logging.exception("Critical error during AudioTransceiver initialization")
            messagebox.showerror("Initialization Error", f"Failed to initialize audio/network: {e}")
            return False
        except Exception as e:
            logging.exception("Unexpected critical error during audio subsystem setup")
            messagebox.showerror("Initialization Error", f"An unexpected error occurred during audio setup: {e}")
            return False

    def shutdown_audio_subsystem(self):
        """Stops all audio and network threads and cleans up resources."""
        logging.info("Shutting down audio subsystem...")
        if hasattr(self, 'audio_transceiver') and self.audio_transceiver:
            logging.info("Signaling threads via shutdown_event...")
            self.audio_transceiver.shutdown_event.set()
            logging.info("Cleaning up AudioTransceiver...")
            self.audio_transceiver.cleanup()
        else:
            logging.warning("Shutdown request but audio_transceiver not found.")

        threads_to_join = [
            self.input_thread, self.output_thread, self.receive_thread,
            self.ping_thread, self.cleanup_thread
        ]
        join_timeout = 2.0
        for t in threads_to_join:
            if t and t.is_alive():
                logging.debug(f"Waiting for thread {t.name} to join...")
                t.join(timeout=join_timeout)
                if t.is_alive():
                    logging.warning(f"Thread {t.name} did not finish within timeout.")
            if t == self.input_thread: self.input_thread = None
            elif t == self.output_thread: self.output_thread = None
            elif t == self.receive_thread: self.receive_thread = None
            elif t == self.ping_thread: self.ping_thread = None
            elif t == self.cleanup_thread: self.cleanup_thread = None

        self.audio_transceiver = None
        logging.info("Audio subsystem shutdown complete.")

    def open_audio_settings(self):
        """Opens the AudioSelector window to reconfigure devices."""
        logging.info("Opening audio settings selector...")
        selector = AudioSelector(self.config, master=self)
        self.wait_window(selector)

        logging.debug(f"AudioSelector closed. Selection successful: {getattr(selector, 'selection_successful', False)}")

        if hasattr(selector, 'selection_successful') and selector.selection_successful:
            logging.info("Audio settings changed and saved. Restarting audio subsystem...")
            config_manager.load_config()
            self.config = config_manager.get_config()
            self.audio_config = self.config.get('audio', {})
            new_input_idx = self.audio_config.get('input_device_index', INVALID_DEVICE_INDEX)
            new_output_idx = self.audio_config.get('output_device_index', INVALID_DEVICE_INDEX)

            if new_input_idx == INVALID_DEVICE_INDEX or new_output_idx == INVALID_DEVICE_INDEX:
                 logging.error("Audio selector closed successfully but saved invalid indices. Aborting restart.")
                 messagebox.showerror("Settings Error", "Failed to save valid audio device settings.")
                 return

            self.shutdown_audio_subsystem()
            self.input_device_index = new_input_idx
            self.output_device_index = new_output_idx

            if not self.setup_audio_subsystem():
                logging.error("Failed to restart audio subsystem after settings change.")
                messagebox.showerror("Restart Error", "Failed to restart audio with new settings. Check logs.")
            else:
                logging.info("Audio subsystem restarted successfully with new settings.")
        else:
            logging.info("Audio settings window closed without saving changes.")

    def audio_input_thread_func(self):
        """Thread for capturing audio, encoding, and sending"""
        if not hasattr(self, 'audio_transceiver') or not self.audio_transceiver or not hasattr(self.audio_transceiver, 'shutdown_event'):
            logging.error("AudioInputThread cannot start: audio_transceiver not ready.")
            return

        sample_rate = self.audio_transceiver.sample_rate
        channels = self.audio_transceiver.channels
        blocksize = self.audio_transceiver.block_size
        dtype = self.audio_transceiver.dtype
        current_input_device = self.input_device_index

        def callback(indata: np.ndarray, frames: int, time_info, status: sd.CallbackFlags):
            """Callback function for the input stream."""
            if status: logging.warning(f"Input callback status: {status}")
            if not self.audio_transceiver.shutdown_event.is_set() and self.is_pressing:
                try:
                    pcm_data_bytes = indata.tobytes()
                    self.audio_transceiver.encode_and_send_audio(pcm_data_bytes)
                    float_data = indata.astype(np.float32) / 32768.0
                    rms = np.sqrt(np.mean(np.square(float_data)))
                    calculated_volume = float(rms) * 2.5
                    try:
                        while self.volume_queue.full(): self.volume_queue.get_nowait()
                        self.volume_queue.put_nowait(calculated_volume)
                    except queue.Full: pass
                    except queue.Empty: pass
                    except Exception as q_err: logging.warning(f"Error managing volume queue: {q_err}")
                except Exception as e: logging.exception(f"Error in audio_input callback")
            else:
                if not self.is_pressing or self.audio_transceiver.shutdown_event.is_set():
                    try:
                        while self.volume_queue.full(): self.volume_queue.get_nowait()
                        self.volume_queue.put_nowait(0.0)
                    except queue.Full: pass
                    except queue.Empty: pass
                    except Exception as q_err: logging.warning(f"Error managing zero volume queue: {q_err}")

        try:
            logging.info(f"Opening InputStream: Device={current_input_device}, Rate={sample_rate}, Block={blocksize}, Dtype={dtype}, Channels={channels}")
            with sd.InputStream(samplerate=sample_rate, channels=channels, dtype=dtype, callback=callback, blocksize=blocksize, device=current_input_device):
                logging.info("InputStream opened. Waiting for shutdown signal...")
                self.audio_transceiver.shutdown_event.wait()
        except sd.PortAudioError as e: logging.exception(f"Critical audio input error (PortAudioError) Device={current_input_device}")
        except ValueError as e: logging.exception(f"Critical audio input error (ValueError - likely invalid device index?) Device={current_input_device}")
        except Exception as e: logging.exception(f"Critical audio input error (Other) Device={current_input_device}")
        logging.info("Audio input thread finished.")

    def audio_output_thread_func(self):
        """Thread for receiving decoded audio and playing it"""
        if not hasattr(self, 'audio_transceiver') or not self.audio_transceiver or not hasattr(self.audio_transceiver, 'shutdown_event'):
            logging.error("AudioOutputThread cannot start: audio_transceiver not ready.")
            return

        sample_rate = self.audio_transceiver.sample_rate
        channels = self.audio_transceiver.channels
        blocksize = self.audio_transceiver.block_size
        dtype = self.audio_transceiver.dtype
        current_output_device = self.output_device_index

        def callback(outdata: np.ndarray, frames: int, time_info, status: sd.CallbackFlags):
            """Callback function for the output stream."""
            if status:
                logging.warning(f"Output callback status: {status}")

            if not self.audio_transceiver.shutdown_event.is_set():
                # Get and add all available packets to the mixer
                while True:
                    packet_info = self.audio_transceiver.get_decoded_audio_packet()
                    if packet_info is None:
                        break

                    sender_ip, audio_data = packet_info
                    if audio_data is not None and audio_data.size == frames * channels:
                        self.audio_transceiver.mixer.add_audio(sender_ip, audio_data)
                        with self.speaker_lock:
                            self.currently_speaking_ip = sender_ip
                            self.last_packet_played_time = time.time()

                # Get the mixed audio stream
                mixed_audio = self.audio_transceiver.mixer.mix_audio()

                # Play the mixed sound or silence
                if len(mixed_audio) == frames * channels:
                    outdata[:] = mixed_audio.reshape(-1, channels)
                else:
                    outdata.fill(0)
            else:
                outdata.fill(0)

        try:
            logging.info(f"Opening OutputStream: Device={current_output_device}, Rate={sample_rate}, Block={blocksize}, Dtype={dtype}, Channels={channels}")
            with sd.OutputStream(samplerate=sample_rate, channels=channels, dtype=dtype, callback=callback, blocksize=blocksize, device=current_output_device):
                logging.info("OutputStream opened. Waiting for shutdown signal...")
                self.audio_transceiver.shutdown_event.wait()
        except sd.PortAudioError as e:
            logging.exception(f"Critical audio output error (PortAudioError) Device={current_output_device}")
        except ValueError as e:
            logging.exception(f"Critical audio output error (ValueError - likely invalid device index?) Device={current_output_device}")
        except Exception as e:
            logging.exception(f"Critical audio output error (Other) Device={current_output_device}")
        logging.info("Audio output thread finished.")

    def receive_thread_func(self):
        """Wrapper for packet receiving"""
        if hasattr(self, 'audio_transceiver') and self.audio_transceiver:
            self.audio_transceiver.receive_packets()
        else: logging.error("ReceiveThread: audio_transceiver does not exist or already cleaned up.")

    def ping_thread_func(self):
        """Periodically sends ping packets"""
        logging.info("Ping sending thread starting.")
        while not hasattr(self, 'audio_transceiver') or not self.audio_transceiver:
             if self.is_closing: return
             time.sleep(0.5)
             logging.debug("PingThread waiting for audio_transceiver...")

        ping_interval = self.net_config.get('ping_interval_sec', 2)
        if ping_interval <= 0: logging.warning("Pinging disabled."); return

        while not self.audio_transceiver.shutdown_event.wait(timeout=ping_interval):
            if hasattr(self, 'audio_transceiver') and self.audio_transceiver:
                 self.audio_transceiver.send_ping()
            else:
                 logging.warning("PingThread: audio_transceiver disappeared mid-run.")
                 break
        logging.info("Ping sending thread finished.")

    def client_cleanup_thread_func(self):
        """Periodically cleans up inactive clients"""
        logging.info("Client cleanup thread starting.")
        while not hasattr(self, 'audio_transceiver') or not self.audio_transceiver:
             if self.is_closing: return
             time.sleep(0.5)
             logging.debug("ClientCleanupThread waiting for audio_transceiver...")

        cleanup_interval = max(1.0, self.net_config.get('ping_interval_sec', 2) * 1.5)
        logging.info(f"Client cleanup interval: {cleanup_interval:.1f}s.")

        while not self.audio_transceiver.shutdown_event.wait(timeout=cleanup_interval):
            try:
                if hasattr(self, 'audio_transceiver') and self.audio_transceiver:
                     self.audio_transceiver.cleanup_inactive_clients()
                else:
                     logging.warning("ClientCleanupThread: audio_transceiver disappeared mid-run.")
                     break
            except Exception as e: logging.exception("Error during client cleanup")
        logging.info("Client cleanup thread finished.")

    def update_gui(self):
        """GUI update loop"""
        try:
            if not self.winfo_exists(): return
            transceiver_ready = hasattr(self, 'audio_transceiver') and self.audio_transceiver and not self.audio_transceiver.shutdown_event.is_set()

            last_volume_update = None
            while not self.volume_queue.empty():
                try: last_volume_update = self.volume_queue.get_nowait()
                except queue.Empty: break
                except Exception as e: logging.warning(f"Error getting volume from queue: {e}")
            if last_volume_update is not None and hasattr(self, 'volume_bar') and self.volume_bar.winfo_exists():
                display_volume = min(1.0, max(0.0, last_volume_update))
                self.volume_bar.set(display_volume)

            if transceiver_ready:
                active_peers_data = {}
                current_speaker_ip = None
                now = time.time()
                try:
                    with self.audio_transceiver.clients_lock:
                        active_peers_data = self.audio_transceiver.active_clients.copy()
                except AttributeError: logging.warning("update_gui: clients_lock not found."); return
                with self.speaker_lock:
                    if self.currently_speaking_ip and (now - self.last_packet_played_time > SPEAKER_TIMEOUT_THRESHOLD):
                        self.currently_speaking_ip = None
                    if self.currently_speaking_ip and self.currently_speaking_ip not in active_peers_data:
                        self.currently_speaking_ip = None
                    current_speaker_ip = self.currently_speaking_ip
                if hasattr(self, 'peer_list_textbox') and self.peer_list_textbox.winfo_exists():
                    try:
                        self.peer_list_textbox.configure(state="normal")
                        self.peer_list_textbox.delete("1.0", "end")
                        sorted_ips = sorted(active_peers_data.keys())
                        if sorted_ips:
                            for peer_ip in sorted_ips:
                                info = active_peers_data.get(peer_ip, {})
                                nickname = info.get('nickname', '')
                                display_name = nickname if nickname else peer_ip
                                prefix = "* " if peer_ip == current_speaker_ip else "  "
                                self.peer_list_textbox.insert("end", f"{prefix}{display_name}\n")
                        else: self.peer_list_textbox.insert("end", " (no other peers)")
                        self.peer_list_textbox.configure(state="disabled")
                    except tkinter.TclError as e: logging.warning(f"Error updating peer list: {e}")
                    except Exception as e: logging.exception("Unexpected error updating peer list")
            else:
                 if hasattr(self, 'peer_list_textbox') and self.peer_list_textbox.winfo_exists():
                    try:
                         self.peer_list_textbox.configure(state="normal")
                         self.peer_list_textbox.delete("1.0", "end")
                         self.peer_list_textbox.insert("end", "(Audio system inactive)")
                         self.peer_list_textbox.configure(state="disabled")
                    except: pass

            if self.winfo_exists():
                self.after(100, self.update_gui)
        except Exception as e:
             logging.exception("Unexpected error in update_gui")
             if self.winfo_exists():
                 self.after(500, self.update_gui)

    def on_press(self, event=None):
        """Handler for Speak button press or Spacebar press"""
        if not self.is_pressing:
            logging.info("Transmission started (button/space pressed)")
            self.is_pressing = True
            self.update_led(True)
            if hasattr(self, 'talk_btn') and self.talk_btn.winfo_exists():
                 self.talk_btn.configure(fg_color="#00A853")

    def on_release(self, event=None):
        """Handler for Speak button release or Spacebar release"""
        if self.is_pressing:
            logging.info("Transmission stopped (button/space released)")
            self.is_pressing = False
            self.update_led(False)
            if hasattr(self, 'talk_btn') and self.talk_btn.winfo_exists():
                try: std_color = ctk.ThemeManager.theme["CTkButton"]["fg_color"]
                except (KeyError, AttributeError): std_color = ("#3a7ebf", "#1f538d")
                self.talk_btn.configure(fg_color=std_color)
            if hasattr(self, 'volume_bar') and self.volume_bar.winfo_exists():
                self.volume_bar.set(0.0)

    def update_led(self, on):
        """Updates the color of the LED indicator"""
        color = "#00C853" if on else "#D50000"
        if hasattr(self, 'led') and self.led.winfo_exists():
            try: self.led.configure(fg_color=color)
            except Exception as e: logging.error(f"Failed to update LED color: {e}")

    def on_closing(self):
        """Handler for window closing event (WM_DELETE_WINDOW)."""
        logging.info("Received window closing signal (WM_DELETE_WINDOW).")
        self.is_closing = True
        self.shutdown_audio_subsystem()
        logging.info("Destroying GUI window...")
        try: self.destroy()
        except Exception as e: logging.exception("Error during main window destruction")
        logging.info("Application shutdown process completed.")