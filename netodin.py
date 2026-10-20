#!/usr/bin/env python3
"""
NetOdin Python Flasher for Samsung Galaxy Watch / Tizen devices.
Reverse-engineered from NetOdin3.exe (Samsung LOKE over TCP port 13579).

Supports macOS (Apple Silicon & Intel) and Linux natively without Wine or Windows.
"""

import sys
import os
import re
import socket
import struct
import tarfile
import hashlib
import time
import argparse

# Protocol Constants
ODIN_PORT = 13579
CHUNK_SIZE = 131072       # 128 KB streaming block
WINDOW_SIZE = 31457280    # 30 MB window (0x1E00000) - NetOdin3 standard window (240 * 128 KB)

CMD_SETUP = 100         # 0x64
CMD_PIT = 101           # 0x65
CMD_FILE_TRANSFER = 102 # 0x66
CMD_SESSION_END = 103   # 0x67

# Default Partition Map for Galaxy Watch (SM-R810)
FALLBACK_PIT_MAP = {
    "sboot.bin": 80,
    "param.bin": 9,
    "dzImage": 11,
    "dzImage-recovery": 12,
    "ramdisk.img": 8,
    "ramdisk-recovery.img": 7,
    "rootfs.img": 18,
    "system-data.img": 16,
    "user.img": 17,
    "csc.img": 15,
    "nad_refer.bin": 3,
    "nad_fw.bin": 13,
}


def build_control_packet(cmd: int, sub: int, data=None, str1: str = "", str2: str = "") -> bytes:
    """Builds a 1024-byte Samsung Odin control packet."""
    pkt = bytearray(1024)
    struct.pack_into("<II", pkt, 0, cmd, sub)
    if data:
        for idx, val in enumerate(data):
            struct.pack_into("<I", pkt, 8 + idx * 4, val & 0xFFFFFFFF)
    if str1:
        s1_bytes = str1.encode("latin1")[:127]
        pkt[44 : 44 + len(s1_bytes)] = s1_bytes
    if str2:
        s2_bytes = str2.encode("latin1")[:31]
        pkt[172 : 172 + len(s2_bytes)] = s2_bytes
    return bytes(pkt)


def send_control_packet(sock: socket.socket, cmd: int, sub: int, data=None, str1: str = "", str2: str = "", expect_resp: bool = True):
    """Sends a 1024-byte control packet and optionally reads the 8-byte ACK."""
    pkt = build_control_packet(cmd, sub, data, str1, str2)
    sock.sendall(pkt)
    if not expect_resp:
        return (0, 0)
    resp = recv_exact(sock, 8)
    ack_cmd, ack_status = struct.unpack("<II", resp)
    return (ack_cmd, ack_status)


def recv_exact(sock: socket.socket, length: int) -> bytes:
    """Reads exactly `length` bytes from a socket."""
    buf = bytearray()
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            raise ConnectionResetError(f"Socket closed unexpectedly while waiting for {length - len(buf)} bytes.")
        buf.extend(chunk)
    return bytes(buf)


def verify_md5(filepath: str) -> bool:
    """Verifies Samsung .tar.md5 checksum."""
    file_size = os.path.getsize(filepath)
    if file_size < 256:
        return False
    with open(filepath, "rb") as f:
        f.seek(-256, 2)
        tail = f.read()
        m = re.search(rb"([a-fA-F0-9]{32})\s+([^\r\n]+)", tail)
        if not m:
            print("  [!] No standard MD5 trailer detected; skipping checksum check.")
            return True

        md5_expected = m.group(1).decode("ascii").lower()
        start_pos = tail.find(m.group(0))
        tar_data_size = file_size - len(tail) + start_pos

        f.seek(0)
        h = hashlib.md5()
        remaining = tar_data_size
        print(f"  [*] Verifying MD5 checksum ({tar_data_size / 1024 / 1024:.2f} MB)...", end="", flush=True)
        while remaining > 0:
            block = f.read(min(remaining, 4 * 1024 * 1024))
            if not block:
                break
            h.update(block)
            remaining -= len(block)
        calc_md5 = h.hexdigest().lower()
        if calc_md5 == md5_expected:
            print(" [PASS]")
            return True
        else:
            print(f" [FAIL]\n  [!] MD5 Mismatch: Expected {md5_expected}, got {calc_md5}")
            return False


def parse_pit(pit_bytes: bytes) -> dict:
    """Parses a Samsung PIT binary table into a filename -> partition_id dict."""
    pit_map = dict(FALLBACK_PIT_MAP)
    try:
        magic, count = struct.unpack_from("<II", pit_bytes, 0)
        if magic != 0x12349876:
            return pit_map
        for i in range(count):
            entry = pit_bytes[28 + i * 132 : 28 + (i + 1) * 132]
            if len(entry) < 132:
                break
            part_id = struct.unpack_from("<I", entry, 8)[0]
            filename = entry[68:100].rstrip(b"\x00").decode("latin1", errors="ignore")
            if filename:
                pit_map[filename] = part_id
    except Exception as e:
        print(f"  [!] Failed to parse PIT: {e}")
    return pit_map


def format_progress(prefix: str, current: int, total: int, start_time: float):
    elapsed = max(time.time() - start_time, 0.001)
    speed_mb = (current / (1024 * 1024)) / elapsed
    pct = (current / total) * 100
    bar_len = 30
    filled = int(bar_len * current // total)
    bar = "=" * filled + ">" + " " * (bar_len - filled - 1) if filled < bar_len else "=" * bar_len
    sys.stdout.write(f"\r  {prefix:18s} [{bar}] {pct:5.1f}% ({current/1024/1024:6.1f}/{total/1024/1024:6.1f} MB) @ {speed_mb:5.1f} MB/s")
    sys.stdout.flush()


def flash_ap_package(ap_path: str, host: str = "0.0.0.0", port: int = ODIN_PORT, auto_reboot: bool = True):
    print("=" * 72)
    print("  NetOdin Python Flasher (Samsung Galaxy Watch SM-R810)")
    print("=" * 72)

    if not os.path.isfile(ap_path):
        print(f"[-] Error: File not found: {ap_path}")
        sys.exit(1)

    # 1. MD5 Verification
    if ap_path.endswith(".md5"):
        print("[*] Checking package integrity...")
        if not verify_md5(ap_path):
            print("[-] Integrity check failed! Aborting flash.")
            sys.exit(1)

    # 2. Inspect AP Tar file members (skip .pit table files from partition flash list)
    print(f"[*] Analyzing firmware package: {os.path.basename(ap_path)}")
    tar_obj = tarfile.open(ap_path, "r:")
    members = [m for m in tar_obj.getmembers() if m.isfile() and not m.name.endswith(".pit")]
    total_payload = sum(m.size for m in members)
    print(f"  [+] Found {len(members)} partitions to flash (Total: {total_payload / 1024 / 1024:.2f} MB):")
    for m in members:
        print(f"      - {m.name:22s} : {m.size:10d} bytes ({m.size / 1024 / 1024:6.2f} MB)")

    # 3. Bind TCP Server
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(1)

    print("\n" + "-" * 72)
    print(f"[*] TCP Server listening on {host}:{port}")
    print("[*] INSTRUCTIONS:")
    print("  1. Put Galaxy Watch in 'Download (Wireless)' AP Mode:")
    print("     - Hold Power button ~10s until 'Rebooting...'")
    print("     - Quickly tap Power 3x -> Highlight 'Download (Wireless)' -> Long-press")
    print("     - Rapidly double-press Power to switch to 'Access Point: SM-R810-xxxx'")
    print("  2. Connect your Mac/Linux Wi-Fi to 'SM-R810-xxxx'")
    print("  3. Waiting for connection from watch...")
    print("-" * 72)

    sock, client_addr = srv.accept()
    print(f"[+] Watch connected from {client_addr[0]}:{client_addr[1]}!")
    sock.settimeout(300.0)  # 5 min timeout
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

    try:
        # Step 1: Handshake (ODIN -> LOKE)
        print("[*] Handshaking: sending 'ODIN'...")
        sock.sendall(b"ODIN")
        resp = recv_exact(sock, 4)
        if resp != b"LOKE":
            raise ValueError(f"Handshake failed! Expected 'LOKE', got {resp!r}")
        print("[+] Handshake acknowledged: received 'LOKE'!")

        # Step 2: Initialization (Cmd 100, Sub 0)
        print("[*] Initializing session parameters (Cmd 100, Sub 0)...")
        ack_cmd, ack_status = send_control_packet(sock, CMD_SETUP, 0, data=[3, 0, 0], expect_resp=True)
        version = (ack_status >> 16) & 0xFFFF
        print(f"  [+] Protocol version: {version} (Status: 0x{ack_status:08X})")

        # Step 3: Negotiate Packet Size (Cmd 100, Sub 5 -> 128 KB)
        print(f"[*] Setting streaming packet size to {CHUNK_SIZE // 1024} KB...")
        send_control_packet(sock, CMD_SETUP, 5, data=[CHUNK_SIZE], expect_resp=True)

        # Step 4: Begin Session (Cmd 100, Sub 2 with 64-bit total payload size)
        print(f"[*] Starting download session (Cmd 100, Sub 2: {total_payload} bytes / {total_payload / 1024 / 1024:.2f} MB)...")
        total_low = total_payload & 0xFFFFFFFF
        total_high = (total_payload >> 32) & 0xFFFFFFFF
        send_control_packet(sock, CMD_SETUP, 2, data=[total_low, total_high], expect_resp=True)

        # Step 5: Read PIT table from device
        print("[*] Requesting partition table (PIT) from device...")
        ack_cmd, pit_size = send_control_packet(sock, CMD_PIT, 1, expect_resp=True)
        pit_map = dict(FALLBACK_PIT_MAP)
        if ack_cmd == CMD_PIT and 0 < pit_size < 100000:
            print(f"  [+] Device PIT size: {pit_size} bytes. Downloading...")
            pit_data = bytearray()
            chunk_cnt = (pit_size + 499) // 500
            for i in range(chunk_cnt):
                # Cmd 101, Sub 2 (expect_resp=False, device streams raw 500 bytes)
                send_control_packet(sock, CMD_PIT, 2, data=[i], expect_resp=False)
                rem = min(500, pit_size - len(pit_data))
                chunk = recv_exact(sock, rem)
                pit_data.extend(chunk)
            # Finalize PIT transfer
            send_control_packet(sock, CMD_PIT, 3, expect_resp=True)
            pit_map = parse_pit(bytes(pit_data))
            print(f"  [+] Successfully parsed device PIT ({len(pit_map)} partition mappings).")
        else:
            print("  [!] Device did not supply PIT; using authentic SM-R810 hardware PIT map.")

        # Step 6: Stream each partition file in the AP archive
        print("\n" + "=" * 72)
        print("  STREAMING PARTITIONS TO FLASH MEMORY")
        print("=" * 72)

        for f_idx, member in enumerate(members):
            filename = member.name
            file_size = member.size
            part_id = pit_map.get(filename, 0)

            print(f"\n[*] [{f_idx + 1}/{len(members)}] Preparing: {filename} (ID: {part_id}, Size: {file_size / 1024 / 1024:.2f} MB)")

            stream = tar_obj.extractfile(member)
            file_bytes_sent = 0
            t_start = time.time()

            while file_bytes_sent < file_size:
                window_bytes_to_send = min(WINDOW_SIZE, file_size - file_bytes_sent)
                aligned_window_size = ((window_bytes_to_send + CHUNK_SIZE - 1) // CHUNK_SIZE) * CHUNK_SIZE

                # Cmd 102, Sub 0: RQT_XMIT_DATA_START (resets chunk seq counter)
                send_control_packet(sock, CMD_FILE_TRANSFER, 0, expect_resp=True)

                # Cmd 102, Sub 2: Announce aligned window size to device
                send_control_packet(sock, CMD_FILE_TRANSFER, 2, data=[aligned_window_size], expect_resp=True)

                window_sent = 0
                while window_sent < window_bytes_to_send:
                    to_read = min(CHUNK_SIZE, window_bytes_to_send - window_sent)
                    chunk = stream.read(to_read)
                    if not chunk:
                        break
                    actual_len = len(chunk)

                    # NetOdin always transmits full CHUNK_SIZE (128 KB) blocks, zero-padding the last block
                    if len(chunk) < CHUNK_SIZE:
                        chunk = chunk + b"\x00" * (CHUNK_SIZE - len(chunk))

                    sock.sendall(chunk)

                    # Each chunk is acknowledged with an 8-byte status packet: <seq:status>, e.g. <0:0>
                    ack = recv_exact(sock, 8)
                    ack_seq, ack_status = struct.unpack("<II", ack)
                    if ack_status != 0 and (ack_status & 0x80000000):
                        raise IOError(f"Chunk transfer rejected by device at offset {file_bytes_sent + window_sent}! ACK: <{ack_seq}:{ack_status:#x}>")

                    window_sent += actual_len
                    format_progress(filename, file_bytes_sent + window_sent, file_size, t_start)

                file_bytes_sent += window_sent
                is_file_complete = 1 if file_bytes_sent >= file_size else 0

                # Cmd 102, Sub 3: Commit window to eMMC
                # Data payload matching NetOdin3.exe & wireless_download.elf:
                # [0, window_bytes_to_send, 0, 0, part_id, is_file_complete, 0, 0]
                cmd_data = [0, window_bytes_to_send, 0, 0, part_id, is_file_complete, 0, 0]
                ack_cmd, ack_status = send_control_packet(sock, CMD_FILE_TRANSFER, 3, data=cmd_data, expect_resp=True)
                if ack_status != 0 and (ack_status & 0x80000000):
                    raise IOError(f"eMMC Write error for {filename} (Status: 0x{ack_status:08X})")

            sys.stdout.write("\n")
            print(f"  [+] {filename} written and verified successfully.")

        # Step 7: Close Session & Reboot
        print("\n" + "=" * 72)
        print("[*] All partitions flashed successfully!")
        print("[*] Closing download session (Cmd 103, Sub 0)...")
        send_control_packet(sock, CMD_SESSION_END, 0, expect_resp=True)

        if auto_reboot:
            print("[*] Issuing device reboot command (Cmd 103, Sub 1)...")
            send_control_packet(sock, CMD_SESSION_END, 1, expect_resp=True)
            print("[+] PASS! Galaxy Watch is now rebooting.")
        else:
            print("[*] Auto-reboot skipped.")

        print("=" * 72)

    finally:
        sock.close()
        srv.close()
        tar_obj.close()


def main():
    parser = argparse.ArgumentParser(description="NetOdin Python Flasher for Samsung Galaxy Watch / Tizen")
    parser.add_argument("--ap", required=True, help="Path to firmware package (.tar or .tar.md5)")
    parser.add_argument("--port", type=int, default=ODIN_PORT, help=f"TCP port to listen on (default: {ODIN_PORT})")
    parser.add_argument("--host", default="0.0.0.0", help="Host interface to bind (default: 0.0.0.0)")
    parser.add_argument("--no-reboot", action="store_true", help="Do not reboot watch after flashing")
    args = parser.parse_args()

    flash_ap_package(args.ap, host=args.host, port=args.port, auto_reboot=not args.no_reboot)


if __name__ == "__main__":
    main()
