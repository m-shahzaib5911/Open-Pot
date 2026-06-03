import json
import os
import socket
import sys
import threading
from datetime import datetime, timezone

import paramiko
import requests


LISTEN_HOST = os.getenv("HONEYPOT_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("HONEYPOT_LISTEN_PORT", "2222"))
BANNER = os.getenv("HONEYPOT_BANNER", "Open-Pot SSH")
PROMPT = os.getenv("HONEYPOT_PROMPT", "attacker@open-pot:~$ ")
LOG_PATH = os.getenv("HONEYPOT_LOG_PATH", "/data/events.jsonl")
LOG_ENDPOINT = os.getenv("HONEY_LOG_ENDPOINT", "").strip()
HOST_KEY_PATH = os.getenv("HONEYPOT_HOST_KEY_PATH", "/data/host_key")


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def write_event(event):
    event["ts"] = utc_now()
    line = json.dumps(event, separators=(",", ":"))

    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError as exc:
        print(f"Log write failed: {exc}", file=sys.stderr)

    if LOG_ENDPOINT:
        try:
            requests.post(LOG_ENDPOINT, json=event, timeout=2)
        except requests.RequestException as exc:
            print(f"Log POST failed: {exc}", file=sys.stderr)


def load_host_key():
    os.makedirs(os.path.dirname(HOST_KEY_PATH), exist_ok=True)
    if os.path.exists(HOST_KEY_PATH):
        return paramiko.RSAKey(filename=HOST_KEY_PATH)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_PATH)
    return key


class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, client_ip, client_port):
        self.client_ip = client_ip
        self.client_port = client_port

    def check_auth_password(self, username, password):
        write_event(
            {
                "type": "auth_attempt",
                "client_ip": self.client_ip,
                "client_port": self.client_port,
                "username": username,
                "password": password,
            }
        )
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        return True


def command_response(command):
    responses = {
        "whoami": "root",
        "id": "uid=0(root) gid=0(root) groups=0(root)",
        "pwd": "/root",
        "ls": "backup  configs  deploy  secrets.zip",
        "ls -la": "drwx------  2 root root 4096 .\ndrwxr-xr-x 18 root root 4096 ..",
        "uname -a": "Linux open-pot 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
        "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
    }
    return responses.get(command, f"{command}: command not found")


def handle_client(client, addr, host_key):
    client_ip, client_port = addr
    transport = paramiko.Transport(client)
    transport.local_version = BANNER
    transport.add_server_key(host_key)
    server = HoneypotServer(client_ip, client_port)

    try:
        transport.start_server(server=server)
    except paramiko.SSHException as exc:
        write_event(
            {
                "type": "ssh_error",
                "client_ip": client_ip,
                "client_port": client_port,
                "error": str(exc),
            }
        )
        transport.close()
        return

    channel = transport.accept(20)
    if channel is None:
        transport.close()
        return

    write_event(
        {
            "type": "session_start",
            "client_ip": client_ip,
            "client_port": client_port,
        }
    )

    channel.send("Welcome to Ubuntu 20.04.6 LTS\r\n")

    buffer = b""
    try:
        while True:
            channel.send(PROMPT)
            data = channel.recv(1024)
            if not data:
                break
            buffer += data
            buffer = buffer.replace(b"\r\n", b"\n")
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                command = line.decode(errors="ignore").strip()
                if not command:
                    continue
                write_event(
                    {
                        "type": "command",
                        "client_ip": client_ip,
                        "client_port": client_port,
                        "command": command,
                    }
                )
                if command in {"exit", "quit", "logout"}:
                    channel.send("logout\r\n")
                    channel.close()
                    transport.close()
                    return
                channel.send(command_response(command) + "\r\n")
    except OSError as exc:
        write_event(
            {
                "type": "session_error",
                "client_ip": client_ip,
                "client_port": client_port,
                "error": str(exc),
            }
        )
    finally:
        write_event(
            {
                "type": "session_end",
                "client_ip": client_ip,
                "client_port": client_port,
            }
        )
        channel.close()
        transport.close()


def serve():
    host_key = load_host_key()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((LISTEN_HOST, LISTEN_PORT))
    sock.listen(100)

    print(f"Open-Pot SSH honeypot listening on {LISTEN_HOST}:{LISTEN_PORT}")

    while True:
        client, addr = sock.accept()
        thread = threading.Thread(target=handle_client, args=(client, addr, host_key), daemon=True)
        thread.start()


if __name__ == "__main__":
    serve()
