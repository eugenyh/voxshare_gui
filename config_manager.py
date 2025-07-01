# -*- coding: utf-8 -*-

"""
Configuration management for the VoxShare application.
Handles loading, saving, and providing default settings.
"""

import json
import logging
from constants import CONFIG_FILENAME, INVALID_DEVICE_INDEX

# --- Global dictionary for settings ---
config = {}

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
            "sample_rate": 16000,
            "channels": 1,
            "block_size": 320,
            "dtype": "int16",
            "opus_application": "voip",
            "playback_queue_size": 20,
            "input_device_index": INVALID_DEVICE_INDEX,
            "output_device_index": INVALID_DEVICE_INDEX
        },
        "logging": {
            "enabled": True,
            "log_file": "voxshare.log",
            "log_level": "INFO",
            "log_format": "%(asctime)s - %(levelname)s - %(threadName)s - %(message)s"
        }
    }

def load_config(filename=CONFIG_FILENAME):
    """Loads settings from a JSON file or creates a file with default settings."""
    global config
    defaults = get_default_config()
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            loaded_config = json.load(f)
            # Recursively update the defaults with the loaded config
            def update_recursive(d, u):
                for k, v in u.items():
                    if isinstance(v, dict):
                        r = d.get(k, {})
                        if isinstance(r, dict):
                           d[k] = update_recursive(r, v)
                        else:
                            d[k] = v
                    else:
                        d[k] = v
                return d
            config = update_recursive(defaults, loaded_config)
            logging.info(f"Settings loaded and merged with defaults from {filename}")
            print(f"Settings loaded from {filename}")

    except FileNotFoundError:
        print(f"Settings file {filename} not found. Creating a file with default settings.")
        logging.warning(f"Settings file {filename} not found. Creating default config.")
        config = defaults
        save_config(config, filename)
    except json.JSONDecodeError as e:
        print(f"Error: Could not decode JSON in file {filename}: {e}. Using default settings.")
        logging.error(f"Error decoding JSON in {filename}: {e}. Using defaults.")
        config = defaults
    except Exception as e:
        print(f"Unexpected error while loading settings: {e}. Using default settings.")
        logging.exception(f"Unexpected error loading settings from {filename}. Using defaults.")
        config = defaults
    # Ensure audio device indices exist to prevent KeyErrors later
    if 'audio' not in config: config['audio'] = defaults['audio']
    if 'input_device_index' not in config['audio']: config['audio']['input_device_index'] = defaults['audio']['input_device_index']
    if 'output_device_index' not in config['audio']: config['audio']['output_device_index'] = defaults['audio']['output_device_index']

def save_config(config_to_save, filename=CONFIG_FILENAME):
    """Saves the current configuration dictionary to a JSON file."""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(config_to_save, f, indent=2, ensure_ascii=False)
        logging.info(f"Configuration saved to {filename}")
        return True
    except IOError as e:
        print(f"Error: Could not save settings file {filename}: {e}")
        logging.error(f"Could not save settings to {filename}: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error while saving settings: {e}")
        logging.exception(f"Unexpected error saving settings to {filename}")
        return False

def get_config():
    """Returns the current global configuration dictionary."""
    return config