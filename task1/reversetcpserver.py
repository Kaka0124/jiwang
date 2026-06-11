#!/usr/bin/env python3
"""
TCP 反转服务端 —— Task1
========================
多线程 TCP 服务端，接收客户端发来的文本块，逐块反转后返回。
支持多个客户端同时连接（每客户端一个线程）。

用法：
    python3 reversetcpserver.py <端口号>

示例：
    python3 reversetcpserver.py 8888
"""

import socket
import struct
import threading
import sys

from tcp_protocol import (
    MessageType, TYPE_NAMES, HEADER_SIZE,
    pack_message, recv_message, timestamp,
)

# 最大并发客户端数
MAX_CLIENTS = 10

# 全局日志锁（保证多线程写日志时不会乱序）
log_lock = threading.Lock()
LOG_FILE = "run_log.txt"


def log(msg: str):
    """线程安全的日志函数，同时输出到终端和 run_log.txt"""
    ts = timestamp()
    line = f"[{ts}] {msg}"
    print(line)
    with log_lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def reverse_bytes(data: bytes) -> bytes:
    """将字节串反转（例如 b'abc' → b'cba'）"""
    return data[::-1]


def handle_client(conn: socket.socket, addr: tuple, client_id: int):
    """
    在一个独立线程中处理一个客户端连接。

    流程：
        收到 Initialization(N) → 回复 agree → 循环收 reverseRequest/发 reverseAnswer → 客户端EOF
    """
    client_ip, client_port = addr
    log(f"[Client-{client_id}] 客户端连接来自 {client_ip}:{client_port}")

    try:
        # ---- 阶段1：等待 Initialization 报文（含 4 字节的 N）----
        msg_type, payload = recv_message(conn)
        if msg_type != MessageType.INITIALIZATION:
            log(f"[Client-{client_id}] 错误：期望 Initialization，收到 "
                f"{TYPE_NAMES.get(msg_type, msg_type)}")
            conn.close()
            return

        N = struct.unpack("!I", payload)[0] if len(payload) >= 4 else 0
        log(f"[Client-{client_id}] 收到 Initialization（N={N}）—— 连接建立")

        # 回复 agree
        conn.sendall(pack_message(MessageType.AGREE, b""))
        log(f"[Client-{client_id}] 发送 agree")

        # ---- 阶段2：循环处理 reverseRequest ----
        request_count = 0
        while True:
            try:
                msg_type, payload = recv_message(conn)
            except (ConnectionError, OSError):
                # 客户端关闭了写端 → 所有数据已发完
                log(f"[Client-{client_id}] 客户端数据发送完毕，共 {request_count} 个请求")
                break

            if msg_type == MessageType.REVERSE_REQUEST:
                request_count += 1
                original = payload
                reversed_data = reverse_bytes(original)
                conn.sendall(pack_message(MessageType.REVERSE_ANSWER, reversed_data))
                log(f"[Client-{client_id}] reverseRequest #{request_count}："
                    f"收到 {len(original)} 字节 → 反转 → 发回 {len(reversed_data)} 字节")

            else:
                log(f"[Client-{client_id}] 警告：收到意外报文类型 "
                    f"{TYPE_NAMES.get(msg_type, msg_type)}")

    except (ConnectionError, OSError) as e:
        log(f"[Client-{client_id}] 连接错误：{e}")
    except Exception as e:
        log(f"[Client-{client_id}] 意外错误：{e}")
    finally:
        try:
            conn.close()
        except OSError:
            pass
        log(f"[Client-{client_id}] 已断开")


def main():
    """主函数：启动服务端，循环接受客户端连接"""
    if len(sys.argv) != 2:
        print(f"用法：python3 {sys.argv[0]} <端口号>")
        print(f"示例：python3 {sys.argv[0]} 8888")
        sys.exit(1)

    port = int(sys.argv[1])

    # 清空旧日志文件
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write(f"=== TCP 反转服务端日志 ===\n")
        f.write(f"启动时间：{timestamp()}\n")
        f.write(f"监听端口：{port}\n")
        f.write(f"{'=' * 60}\n\n")

    # 创建 TCP 套接字
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("0.0.0.0", port))
    server_sock.listen(MAX_CLIENTS)

    log(f"服务端已启动 —— 监听 0.0.0.0:{port}（最大 {MAX_CLIENTS} 个客户端）")

    client_counter = 0

    try:
        while True:
            conn, addr = server_sock.accept()        # 阻塞等待客户端连接
            client_counter += 1
            client_id = client_counter

            # 为每个客户端创建一个独立线程
            thread = threading.Thread(
                target=handle_client,
                args=(conn, addr, client_id),
                daemon=True,
                name=f"ClientHandler-{client_id}",
            )
            thread.start()
            log(f"[Main] 接受客户端 #{client_id}，来自 {addr[0]}:{addr[1]} "
                f"（活跃线程数：{threading.active_count() - 1}）")

    except KeyboardInterrupt:
        log("服务端正在关闭（Ctrl+C）...")
    finally:
        server_sock.close()
        log("服务端已停止。")


if __name__ == "__main__":
    main()
