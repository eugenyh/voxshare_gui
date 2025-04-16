# Changelog

All notable changes to this project will be documented in this file.

---

## [0.8) – 2025-04-16

### Fixed
- Fixed some minor bugs

### Added
- Now Logo.png inside EXE file. No need to download it.

---

## [0.7) – 2025-04-15

### Fixed
- Fixed some minor bugs

### Added
- Peer list and peer activity (marked in the list)
- Now confiog stored in config.json
- Each peer now have nikname (ip address if not defined) defined in config.json

### Changed
- User interface: peer list, press "space bar" to press speak button

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
