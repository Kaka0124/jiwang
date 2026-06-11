"""
TCP 协议模块 —— Task1 共享常量与工具函数

报文头部（8 字节）：
  偏移  大小  字段
  0     1     报文类型（0x01=Initial, 0x02=ReverseRequest, 0x03=ReverseAnswer, 0x04=Close）
  1     3     保留字段
  4     4     负载长度（大端序 uint32）

8 字节头部之后紧跟负载数据。
"""

import struct
import enum
import socket
import time

HEADER_SIZE = 8
HEADER_FORMAT = "!B3xI"  # 类型(1B) + 保留(3B) + 长度(4B)，大端序


class MessageType(enum.IntEnum):
    """四种报文类型"""
    INITIAL = 0x01          # 初始连接报文（客户端→服务端）
    REVERSE_REQUEST = 0x02  # 反转请求（客户端→服务端，携带待反转数据）
    REVERSE_ANSWER = 0x03   # 反转应答（服务端→客户端，携带反转后数据）
    CLOSE = 0x04            # 关闭连接报文（服务端→客户端）


# 日志可读名称
TYPE_NAMES = {
    MessageType.INITIAL: "Initial",
    MessageType.REVERSE_REQUEST: "ReverseRequest",
    MessageType.REVERSE_ANSWER: "ReverseAnswer",
    MessageType.CLOSE: "Close",
}


def pack_message(msg_type: int, payload: bytes) -> bytes:
    """将报文打包为字节流：8字节头部 + 负载数据"""
    header = struct.pack(HEADER_FORMAT, msg_type, len(payload))
    return header + payload


def unpack_header(data: bytes) -> tuple:
    """
    解析 8 字节报文头部。
    返回 (报文类型, 负载长度)。
    数据不足时抛出 ValueError。
    """
    if len(data) < HEADER_SIZE:
        raise ValueError(
            f"报文头太短：收到 {len(data)} 字节，需要 {HEADER_SIZE} 字节"
        )
    msg_type, payload_length = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
    return msg_type, payload_length


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """
    从 TCP 套接字精确接收 n 字节。
    TCP 是流式协议，单次 recv() 可能返回不足 n 字节，需循环读取直到收满。
    这是解决 TCP "粘包" 问题的关键函数。
    """
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("对端关闭了连接")
        data += chunk
    return data


def recv_message(sock: socket.socket) -> tuple:
    """
    从 TCP 套接字接收一条完整报文。
    先读 8 字节头部 → 获取负载长度 → 再读负载数据。
    返回 (报文类型, 负载数据)。
    """
    header = recv_exact(sock, HEADER_SIZE)
    msg_type, payload_length = unpack_header(header)
    payload = recv_exact(sock, payload_length) if payload_length > 0 else b""
    return msg_type, payload


def timestamp() -> str:
    """返回高精度时间戳，用于日志记录（与 Wireshark 抓包时间戳对应）。"""
    return time.strftime("%Y-%m-%dT%H:%M:%S.", time.localtime()) + \
           f"{int(time.time() * 1_000_000) % 1_000_000:06d}"
