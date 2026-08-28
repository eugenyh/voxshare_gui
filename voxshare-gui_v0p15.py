# -*- coding: utf-8 -*-

"""
Main entry point for the VoxShare application.
This script initializes the application, handles configuration,
validates dependencies, and launches the GUI.
"""

import customtkinter as ctk
import sounddevice as sd
import sys
import logging
from tkinter import messagebox
import opuslib

import config_manager
from gui import AudioSelector, VoxShareGUI
from constants import INVALID_DEVICE_INDEX

def setup_logging():
    """Configures the logging system based on the configuration."""
    log_config = config_manager.get_config().get('logging', {})
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
    # Clear any existing handlers
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    try:
        logging.basicConfig(level=log_level, format=log_format, filename=log_file, filemode='w', encoding='utf-8', force=True)
        logging.info("="*20 + " Application Start " + "="*20)
        logging.info(f"Logging configured. Level: {log_level_str}, File: {log_file}")
        print(f"Logging configured. Level: {log_level_str}, File: {log_file}")
    except IOError as e:
         print(f"Error configuring logging to file {log_file}: {e}. Logging will be disabled.")
         logging.disable(logging.CRITICAL)
    except Exception as e:
        print(f"Unexpected error configuring logging: {e}. Logging will be disabled.")
        logging.disable(logging.CRITICAL)

def main():
    """Main application logic."""
    # 1. Load Configuration
    config_manager.load_config()
    config = config_manager.get_config()

    # 2. Setup Logging
    setup_logging()

    # 3. Set GUI Appearance
    try:
        gui_conf = config.get('gui', {})
        appearance_mode = gui_conf.get('appearance_mode', 'dark').lower()
        if appearance_mode not in ['dark', 'light', 'system']:
            logging.warning(f"Invalid theme '{appearance_mode}'. Using 'dark'.")
            appearance_mode = 'dark'
        ctk.set_appearance_mode(appearance_mode)
        logging.info(f"Interface theme: {appearance_mode}")
    except Exception as e:
        logging.exception("Error setting theme. Using 'dark'.")
        ctk.set_appearance_mode("dark")

    # 4. Check Critical Dependencies (Opus)
    try:
        if not hasattr(opuslib, 'Encoder') or not hasattr(opuslib, 'Decoder'):
            raise ImportError("opuslib missing Encoder/Decoder.")
        logging.info("opuslib library check passed.")
    except ImportError as e:
        message = f"Critical error: opuslib library missing/incomplete ({e}). Install: pip install opuslib"
        print(message); logging.critical(message)
        messagebox.showerror("Dependency Error", message)
        sys.exit(1)
    except Exception as e:
        message = f"Unexpected error checking opuslib: {e}"
        print(message); logging.critical(message)
        messagebox.showerror("Dependency Error", message)
        sys.exit(1)

    # 5. Determine and Validate Audio Devices
    audio_config = config.get('audio', {})
    input_idx = audio_config.get('input_device_index', INVALID_DEVICE_INDEX)
    output_idx = audio_config.get('output_device_index', INVALID_DEVICE_INDEX)
    valid_devices_configured = False

    if input_idx != INVALID_DEVICE_INDEX and output_idx != INVALID_DEVICE_INDEX:
        logging.info(f"Found saved device indices: Input={input_idx}, Output={output_idx}. Validating...")
        try:
            rate = audio_config.get('sample_rate', 16000)
            chans = audio_config.get('channels', 1)
            dtype = audio_config.get('dtype', 'int16')
            sd.check_input_settings(device=input_idx, channels=chans, samplerate=rate, dtype=dtype)
            sd.check_output_settings(device=output_idx, channels=chans, samplerate=rate, dtype=dtype)
            logging.info("Saved audio devices validated successfully.")
            valid_devices_configured = True
        except (sd.PortAudioError, ValueError, TypeError) as e:
            logging.warning(f"Validation failed for saved devices (In={input_idx}, Out={output_idx}): {e}")
            logging.info("Resetting saved device configuration.")
            config['audio']['input_device_index'] = INVALID_DEVICE_INDEX
            config['audio']['output_device_index'] = INVALID_DEVICE_INDEX
            config_manager.save_config(config)
            valid_devices_configured = False
        except Exception as e:
             logging.exception("Unexpected error validating saved devices. Resetting config.")
             config['audio']['input_device_index'] = INVALID_DEVICE_INDEX
             config['audio']['output_device_index'] = INVALID_DEVICE_INDEX
             config_manager.save_config(config)
             valid_devices_configured = False

    # 6. Run AudioSelector if devices are not configured/validated
    if not valid_devices_configured:
        logging.info("Valid audio devices not configured. Launching AudioSelector...")
        try:
            temp_root = ctk.CTk()
            temp_root.withdraw()

            selector = AudioSelector(config, master=temp_root)
            temp_root.wait_window(selector)

            temp_root.destroy()

            if hasattr(selector, 'selection_successful') and selector.selection_successful:
                 logging.info("AudioSelector finished successfully.")
                 config_manager.load_config() # Reload config after selection
                 config = config_manager.get_config()
                 valid_devices_configured = True
            else:
                 logging.error("Audio device selection was cancelled or failed.")
                 messagebox.showerror("Configuration Needed", "Audio devices were not configured. Application cannot start.")
                 sys.exit(1)
        except Exception as e:
            logging.exception("Error running AudioSelector during startup.")
            messagebox.showerror("Startup Error", f"Failed to configure audio devices: {e}")
            sys.exit(1)

    # 7. Launch Main Application if devices are ready
    if valid_devices_configured:
        logging.info("Launching main application window...")
        try:
            app = VoxShareGUI(config)
            app.mainloop()
        except Exception as e:
            logging.exception("Critical unhandled error in main application")
            messagebox.showerror("Fatal Error", f"An unexpected error occurred: {e}")
            sys.exit(1)
    else:
        logging.critical("Reached end of startup without valid devices configured.")
        sys.exit(1)

    logging.info("="*20 + " Application finished normally " + "="*20)
    print("Application finished.")

if __name__ == "__main__":
    main()