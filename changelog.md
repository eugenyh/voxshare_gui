# Changelog

All notable changes to this project will be documented in this file.

## [v0.10] - 2025-04-21

### Added

- **Audio Device Settings Persistence:**
    - New fields, `"input_device_index"` and `"output_device_index"`, have been added to the `"audio"` section of the `config.json` configuration file.
    - On the first run or if the configuration file is missing, these fields are initialized with the value `-1` (meaning "not selected").
    - Implemented the `save_config()` function to save the current configuration state (including selected device indices) back to `config.json`.
    - Now, when the user successfully selects devices in the `AudioSelector` window, their numerical indices are saved in `config.json`, allowing them to be used on subsequent launches.

- **Audio Settings Button in Main Window:**
    - A button (using a gear icon `Icons/settings_icon.png` if available, otherwise displaying the text "Settings") has been added to the top panel of the main `VoxShareGUI` window.
    - Clicking this button calls the `open_audio_settings()` method, allowing the user to change the previously selected input and output audio devices while the application is running.

- **Validation of Saved Devices on Startup:**
    - Before launching the main interface, if saved device indices (different from `-1`) are found in `config.json`, the program now performs a validity check.
    - It uses `sounddevice.check_input_settings` and `sounddevice.check_output_settings` functions to verify if devices with these indices exist and support the parameters (sample rate, channels, data type) specified in `config.json`.

### Changed

- **Conditional Launch of Device Selection Window (`AudioSelector`):**
    - The application no longer shows the `AudioSelector` window every time it starts.
    - It now launches only under the following conditions:
        1.  On the first application run (when indices in `config.json` are `-1`).
        2.  If the saved device indices in `config.json` are found to be invalid during the startup check (e.g., the device was disconnected, or its index changed).
    - If the validation of saved devices is successful, `AudioSelector` is skipped, and the main `VoxShareGUI` window launches directly.

- **Dynamic "On-the-Fly" Audio Device Switching:**
    - When new devices are selected via the "Settings" button and successfully validated/saved in `AudioSelector`, the program now performs the following steps without a full restart:
        1.  Calls `shutdown_audio_subsystem()`: Properly stops all current audio and network threads (`input`, `output`, `receive`, `ping`, `cleanup`) and releases `AudioTransceiver` resources (closes sockets, Opus encoder/decoder).
        2.  Reloads the configuration from `config.json` to get the newly saved indices.
        3.  Calls `setup_audio_subsystem()`: Initializes a new instance of `AudioTransceiver` and starts all necessary threads using the new device indices.
    - This allows the user to smoothly switch between, for example, a headset and speakers/webcam microphone.

- **`AudioSelector` Refactoring:**
    - The `AudioSelector` class now inherits from `customtkinter.CTkToplevel`, making it a modal window (blocks interaction with the parent window until closed).
    - It is no longer responsible for launching `VoxShareGUI`. Its task is to get the user's selection, validate it, save it to `config.json`, set an internal `selection_successful` flag, and then close itself.
    - It now accepts the entire `config` object during initialization to access and update audio settings.
    - When opened, it attempts to automatically select devices in the dropdown lists corresponding to the indices saved in `config`.

- **`VoxShareGUI` Refactoring (Audio Subsystem Management):**
    - The logic for initializing `AudioTransceiver` and starting all related threads has been encapsulated in a new method `setup_audio_subsystem()`.
    - The logic for stopping threads and cleaning up `AudioTransceiver` resources has been encapsulated in a new method `shutdown_audio_subsystem()`.
    - This simplifies the `__init__` and `on_closing` methods and enables the restarting of the audio subsystem within the `open_audio_settings` method.

- **Error Handling and Logging:**
    - Improved logging for the device validation steps during startup.
    - Added more explicit error messages (in logs and via `messagebox`) if validation of saved devices fails or if the user cancels the selection in `AudioSelector`.
    - Improved error handling during loading/saving of `config.json`. The `load_config` function now more reliably handles incomplete or corrupted configuration files by applying default values for missing keys.

### Fixed

- **Handling of Incomplete Config File:** Improved the logic in `load_config` for merging loaded settings with defaults. This prevents `KeyError` exceptions if a user manually deleted sections or keys from `config.json` (e.g., `"audio"` or `"input_device_index"`). It now ensures essential keys are always present in the `config` dictionary after loading.

- **Fixed thread startup issue** where methods `ping_thread`, `receive_thread`, and `client_cleanup_thread` were unintentionally shadowed by `Thread` objects with the same names. This prevented pings, peer updates, and cleanup tasks from working properly.  
    - Renamed these methods to `ping_thread_func`, `receive_thread_func`, and `client_cleanup_thread_func` to avoid name collisions and ensure correct thread behavior.

---

## [0.9 Unreleased] - 2025-04-18

### Fixed
- Fixed incorrect log messages in the client cleanup thread (`ClientCleanupThread`) that mistakenly referenced "Ping sending thread".

### Changed
- **Volume indicator update refactoring:**
    - Eliminated direct GUI state access (`self.volume`) from background thread (`audio_input_thread`)
    - Implemented thread-safe queue (`queue.Queue`) for passing volume values from audio thread to main GUI thread
    - `update_gui` method (main thread) now pulls values from queue to update `volume_bar` widget
    - Removed related variables `self.volume` and `self.volume_lock`
    - This change improves interface update stability and thread safety
- Improved volume queue cleanup logic to prevent stale data during indicator updates
- Enhanced inactive client check/removal logic in `cleanup_inactive_clients`
- Improved shutdown sequence in `on_closing` for proper thread termination and resource cleanup

### Added
- Added handling for missing input/output audio devices in `AudioSelector` window
- Added fallback colors for "Speak" button when theme colors are unavailable

---

## [0.8] – 2025-04-16

### Fixed
- Fixed resource loading race condition during startup
- Fixed memory leak in peer list update handler
- Fixed config.json corruption when saving under high load

### Added
- Added embedded resource system using PyInstaller:
  - Logo.png now included in EXE via `--add-data`

### Changed
- Rewrote config handler to use atomic writes:
  - Temporary file creation → write → rename pattern
  - Added config backup system
- Improved network thread shutdown sequence
- Optimized GUI refresh rate during voice activity

### Removed
- Removed external logo.png dependency

---

## [0.7] – 2025-04-15

### Fixed
- Fixed socket resource cleanup during program exit
- Fixed nickname display corruption in peer list
- Fixed race condition in config.json writes

### Added
- Implemented comprehensive peer management:
  - New Peer class with properties:
    ```python
    class Peer:
        ip: str
        nickname: str
        last_seen: float
        is_active: bool
    ```
  - Peer list sorting by activity status
- Added persistent configuration:
  - New config.json structure:
    ```json
    {
        "version": 1,
        "peers": {
            "192.168.1.2": {"nickname": "Alice"},
            "192.168.1.3": {"nickname": "Bob"}
        },
        "audio": {
            "input_device": "default",
            "volume": 0.8
        }
    }
    ```
- New UI features:
  - Spacebar hotkey binding for push-to-talk
  - Dynamic peer list with scrollbar

### Changed
- Refactored network code into NetworkManager class
- Improved audio thread synchronization:
  - Added double-buffering for received packets
  - Implemented proper thread locks for audio streams
- Updated GUI layout engine for better scaling

---

## [0.6] – 2025-04-14

### Fixed
- Fixed window close behavior: `on_closing` is now properly called when the window is closed. It signals all threads to stop, closes sockets, and destroys the window.

### Added
- Integrated Opus codec using the `opuslib` Python package.
- New method `AudioTransceiver.encode_and_send_audio()` — encodes PCM data using Opus and sends it.
- New method `AudioTransceiver.decode_audio()` — decodes received Opus packets to PCM.
- New method `AudioTransceiver.get_decoded_audio_packet()` — fetches and decodes Opus packets, returns a NumPy array.
- Added thread locks (`clients_lock`, `volume_lock`) to ensure safe access to shared data structures.
- Added a note in `__main__` reminding users to install `opuslib` and the system-level Opus library.

### Changed
- Renamed `received_audio` to `received_opus_packets`, increased its maximum size.
- `audio_input_thread` and `audio_output_thread` now use Opus codec for encoding/decoding audio.
- Background threads (`ping_thread`, `client_cleanup_thread`, `receive_thread`) now use `audio_transceiver` methods for logic.
- Replaced `time.sleep()` with `shutdown_event.wait()` for faster response to shutdown signals.
- Increased socket receive buffer size to handle larger Opus packets.
- Normalized RMS calculation for volume meter to range [0, 1].

### Removed
- Removed unused and redundant imports.

### Notes
- ⚠️ You must install the `opuslib` Python package:
  ```bash
  pip install opuslib

---

## [0.5] – 2025-04-10 (Initial Release)

### Core Implementation

```python
class AudioTransceiver:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.received_audio = []  # Uncompressed PCM
        self.running = True
```

### Technical Specifications

- **Audio**: 16-bit PCM @ 48kHz (no compression)

- **Network**:
  ```python
  DEFAULT_PORT = 49500
  PACKET_RATE = 50
  TIMEOUT = 2.0
  ```

- **Threads**:
  - `audio_input_thread` – Microphone capture  
  - `audio_output_thread` – Playback  
  - `receive_thread` – Network processing  

### Limitations

- No peer discovery (manual IP required)  
- No audio compression (~768kbps bandwidth)  
- No thread synchronization  
- Basic error handling  
- Hardcoded configuration  

### Known Issues

- Memory leaks in audio buffers  
- UI freezes during network ops  
- No proper shutdown sequence  
- Audio artifacts under load  

> **Note**: Proof-of-concept version. Upgrade to v0.6+ for production use.
