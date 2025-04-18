# Changelog

All notable changes to this project will be documented in this file.


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
