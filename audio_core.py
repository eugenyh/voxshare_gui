# -*- coding: utf-8 -*-

"""
Core audio and network processing for the VoxShare application.
Includes the AudioMixer for combining audio streams and the
AudioTransceiver for handling network communication and audio encoding/decoding.
"""

import socket
import threading
import numpy as np
import struct
import time
import queue
from threading import Event, Lock
import opuslib
import logging

from constants import (
    PACKET_TYPE_AUDIO, PACKET_TYPE_PING, OPUS_APPLICATION_MAP
)

class AudioMixer:
    """
    Mixes audio from multiple sources.
    This class is responsible for combining audio data from different clients
    into a single stream to be played out.
    """
    def __init__(self, sample_rate, channels, block_size, dtype):
        self.sample_rate = sample_rate
        self.channels = channels
        self.block_size = block_size
        self.dtype = dtype
        self.audio_buffers = {}  # {ip: np.array}
        self.last_activity = {}  # {ip: timestamp}
        self.lock = threading.Lock()
        self.silence_threshold = 0.01  # Threshold to detect silence
        self.max_inactive_time = 0.5  # Max inactivity time before cleanup (sec)

    def add_audio(self, ip, audio_data):
        """Add audio data from a specific IP to the mixer."""
        with self.lock:
            # Check if the packet is not silence
            if np.max(np.abs(audio_data)) > self.silence_threshold:
                self.audio_buffers[ip] = audio_data
                self.last_activity[ip] = time.time()
            else:
                # If it's silence, remove the buffer for this IP
                if ip in self.audio_buffers:
                    del self.audio_buffers[ip]

    def mix_audio(self):
        """Mix all audio buffers with normalization."""
        with self.lock:
            current_time = time.time()

            # First, clean up inactive buffers
            to_remove = [ip for ip, ts in self.last_activity.items()
                         if current_time - ts > self.max_inactive_time]
            for ip in to_remove:
                if ip in self.audio_buffers:
                    del self.audio_buffers[ip]
                if ip in self.last_activity:
                    del self.last_activity[ip]

            if not self.audio_buffers:
                return np.zeros(self.block_size * self.channels, dtype=self.dtype)

            mixed = np.zeros(self.block_size * self.channels, dtype=self.dtype)
            active_sources = 0

            for data in self.audio_buffers.values():
                if len(data) == len(mixed):
                    mixed += data
                    active_sources += 1

            # Normalize only if there are active sources
            if active_sources > 0:
                if active_sources > 1:
                    mixed = mixed / active_sources
                return mixed
            else:
                return np.zeros(self.block_size * self.channels, dtype=self.dtype)

    def cleanup_inactive(self, active_ips):
        """Remove buffers for inactive IPs."""
        with self.lock:
            inactive_ips = set(self.audio_buffers.keys()) - set(active_ips)
            for ip in inactive_ips:
                if ip in self.audio_buffers:
                    del self.audio_buffers[ip]


class AudioTransceiver:
    """
    Handles network communication, audio encoding/decoding, and client management.
    """
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

        self.active_clients = {}
        self.clients_lock = Lock()
        self.received_opus_packets = queue.Queue(maxsize=self.audio_config.get('playback_queue_size', 20) * 2)
        self.shutdown_event = Event()
        self.mcast_grp = self.net_config.get('multicast_group', '239.255.42.99')
        self.port = self.net_config.get('port', 5005)
        self.ttl = self.net_config.get('ttl', 1)
        self.socket_buffer_size = self.net_config.get('socket_buffer_size', 65536)
        self.sample_rate = self.audio_config.get('sample_rate', 16000)
        self.channels = self.audio_config.get('channels', 1)
        self.block_size = self.audio_config.get('block_size', 320)
        self.dtype = self.audio_config.get('dtype', 'int16')
        opus_app_str = self.audio_config.get('opus_application', 'voip')
        self.opus_application = OPUS_APPLICATION_MAP.get(opus_app_str, opuslib.APPLICATION_VOIP)
        self.packet_type_audio = PACKET_TYPE_AUDIO
        self.packet_type_ping = PACKET_TYPE_PING

        # Initialize audio mixer
        self.mixer = AudioMixer(
            sample_rate=self.sample_rate,
            channels=self.channels,
            block_size=self.block_size,
            dtype=self.dtype
        )

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
        if hasattr(self, 'sock_send'):
            try: self.sock_send.close(); logging.info("Send socket closed.")
            except Exception as e: logging.error(f"Error closing send socket: {e}")
        if hasattr(self, 'sock_recv'):
            try:
                mreq = struct.pack("4sl", socket.inet_aton(self.mcast_grp), socket.INADDR_ANY)
                self.sock_recv.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
                logging.info(f"Left multicast group {self.mcast_grp}.")
            except socket.error as e: logging.warning(f"Failed to leave multicast group (socket may already be closed): {e}")
            except AttributeError: logging.warning("Multicast group leave skipped (socket likely already closed/invalid).")
            except Exception as e: logging.error(f"Error attempting to leave multicast group: {e}")
            try: self.sock_recv.close(); logging.info("Receive socket closed.")
            except Exception as e: logging.error(f"Error closing receive socket: {e}")
        logging.info("AudioTransceiver cleanup finished.")

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
        logging.debug(f"[DEBUG] send_ping called")
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
                self.sock_recv.settimeout(0.5)
                data, addr = self.sock_recv.recvfrom(self.socket_buffer_size)
                logging.debug(f"Received packet {len(data)} bytes from {addr}")

                if addr[0] == self.local_ip: continue

                if data.startswith(self.packet_type_audio):
                    opus_packet = data[len(self.packet_type_audio):]
                    packet_tuple = (addr[0], opus_packet)
                    try:
                        self.received_opus_packets.put_nowait(packet_tuple)
                        logging.debug(f"Audio packet ({len(opus_packet)} bytes from {addr[0]}) added to queue.")
                    except queue.Full:
                        try:
                            dropped_tuple = self.received_opus_packets.get_nowait()
                            self.received_opus_packets.put_nowait(packet_tuple)
                            logging.warning(f"Audio packet queue full. Dropped packet from {dropped_tuple[0]}. Added new from {addr[0]}.")
                        except queue.Empty: pass
                        except queue.Full: logging.warning("Queue is full even after removal, new audio packet skipped.")

                elif data.startswith(self.packet_type_ping):
                    nickname_bytes = data[len(self.packet_type_ping):]
                    try:
                        nickname = nickname_bytes.decode('utf-8', errors='replace').strip()
                    except Exception as e:
                        logging.warning(f"Failed to decode nickname from PING from {addr[0]}: {e}")
                        nickname = ""

                    with self.clients_lock:
                        client_info = self.active_clients.get(addr[0], {})
                        client_info['last_seen'] = time.time()
                        client_info['nickname'] = nickname
                        self.active_clients[addr[0]] = client_info
                    logging.info(f"Received PING from {addr[0]} (Nick: '{nickname}'). Client active.")

                else:
                    logging.warning(f"Received unknown packet type from {addr}: {data[:10]}...")

            except socket.timeout:
                 continue
            except socket.error as e:
                 if self.shutdown_event.is_set():
                     logging.info("Socket closed (expected during shutdown), receiving thread terminating.")
                     break
                 else:
                     logging.error(f"Socket error while receiving packet: {e}")
                     time.sleep(0.1)
            except Exception as e:
                  if not self.shutdown_event.is_set():
                      logging.exception("Unexpected error in receive_packets")

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
                     return None
            else:
                 return None
        except queue.Empty:
            return None
        except Exception as e:
            logging.exception("Unexpected error in get_decoded_audio_packet")
            return None

    def cleanup_inactive_clients(self):
        """Cleanup of inactive clients"""
        current_time = time.time()
        inactive_ips = []
        client_timeout = self.net_config.get('client_timeout_sec', 5)

        with self.clients_lock:
            all_client_ips = list(self.active_clients.keys())

        for ip in all_client_ips:
            last_seen = None
            with self.clients_lock:
                client_info = self.active_clients.get(ip)
                if client_info:
                    last_seen = client_info.get('last_seen')

            if last_seen is None: continue

            if current_time - last_seen > client_timeout:
                inactive_ips.append(ip)

        if inactive_ips:
            logging.debug(f"Candidates for removal due to timeout: {inactive_ips}")
            with self.clients_lock:
                removed_count = 0
                for ip in inactive_ips:
                    client_info = self.active_clients.get(ip)
                    if client_info and current_time - client_info.get('last_seen', 0) > client_timeout:
                        nickname = client_info.get('nickname', '')
                        logging.info(f"Removing inactive client: {ip} (Nickname: '{nickname}', last seen: {current_time - client_info.get('last_seen', 0):.1f}s ago)")
                        del self.active_clients[ip]
                        removed_count += 1
                if removed_count > 0:
                     logging.debug(f"Removed {removed_count} inactive clients.")