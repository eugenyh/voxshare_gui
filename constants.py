# -*- coding: utf-8 -*-

"""
Global constants for the VoxShare application.
"""

# --- Configuration ---
CONFIG_FILENAME = "config.json"

# --- Network Packet Types ---
PACKET_TYPE_AUDIO = b"AUD"
PACKET_TYPE_PING = b"PING"

# --- Audio Processing ---
SPEAKER_TIMEOUT_THRESHOLD = 0.3
INVALID_DEVICE_INDEX = -1 # Indicates unset/invalid device index

# --- Opus Application Mapping ---
# This maps string representations from the config to the actual opuslib constants.
# Moved here to avoid circular dependencies if other modules need it.
import opuslib
OPUS_APPLICATION_MAP = {
    "voip": opuslib.APPLICATION_VOIP,
    "audio": opuslib.APPLICATION_AUDIO,
    "restricted_lowdelay": opuslib.APPLICATION_RESTRICTED_LOWDELAY
}