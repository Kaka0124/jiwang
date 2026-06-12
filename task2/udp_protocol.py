"""
UDP 协议模块 —— Task2 共享常量与工具函数

报文头部（18 字节）：
  偏移  大小  字段
  0     2     报文类型（uint16 大端序）
  2     2     StudentID（uint16 大端序）—— 学号后4位 XOR 0x5A3C
  4     4     序列号（uint32 大端序）—— 字节流中的偏移量
  8     4     确认号（uint32 大端序）—— 下一个期望的字节序号
  12    2     校验和（uint16 大端序）—— IP 风格的 16-bit 反码求和
  14    2     数据长度（uint16 大端序）—— 负载的字节数
  16    2     保留 / 窗口大小

报文类型：
  0x0001 = SYN      — 连接请求（三次握手第1步）
  0x0002 = SYN-ACK  — 连接确认（三次握手第2步）
  0x0003 = ACK      — 确认（握手/挥手/数据传输）
  0x0004 = DATA     — 数据包
  0x0005 = FIN      — 连接关闭请求（四次挥手）
  0x0006 = FIN-ACK  — 关闭确认
  0x0007 = NAK      — 否定确认（乱序时通知发送方）
"""

import struct
import enum
import time

HEADER_SIZE = 18
# type(2) + student_id(2) + seq(4) + ack(4) + checksum(2) + data_len(2) + reserved(2)
HEADER_FORMAT = "!HHIIHHH"

# ============ StudentID 配置 ============
STUDENT_ID_LAST4 = 2603  # 学号后4位
STUDENT_ID_XOR = 0x5A3C  # XOR 常量（任务书规定）


def compute_student_id(last4: int = None) -> int:
    """
    计算 StudentID 字段值：学号后4位 XOR 0x5A3C。
    参数 last4：学号后4位数字（0~9999），默认使用全局 STUDENT_ID_LAST4。
    """
    if last4 is None:
        last4 = STUDENT_ID_LAST4
    return (last4 ^ STUDENT_ID_XOR) & 0xFFFF


def validate_student_id(value: int) -> tuple:
    """
    验证 StudentID 字段：对收到的值再次 XOR 0x5A3C，检查是否在 0~9999 范围内。
    返回 (是否合法, 还原后的学号后4位)。
    """
    last4 = (value ^ STUDENT_ID_XOR) & 0xFFFF
    return (0 <= last4 <= 9999), last4


class UDPType(enum.IntEnum):
    """UDP 应用层报文类型（共7种）"""
    SYN = 0x0001      # 连接请求
    SYN_ACK = 0x0002  # 连接确认
    ACK = 0x0003      # 确认
    DATA = 0x0004     # 数据
    FIN = 0x0005      # 关闭请求
    FIN_ACK = 0x0006  # 关闭确认
    NAK = 0x0007      # 否定确认


TYPE_NAMES = {
    UDPType.SYN: "SYN",
    UDPType.SYN_ACK: "SYN-ACK",
    UDPType.ACK: "ACK",
    UDPType.DATA: "DATA",
    UDPType.FIN: "FIN",
    UDPType.FIN_ACK: "FIN-ACK",
    UDPType.NAK: "NAK",
}

# ============ GBN 协议参数 ============
WINDOW_SIZE = 400       # 固定发送窗口：400 字节
TIMEOUT_MS = 300        # 超时重传时间：300ms
PAYLOAD_MIN = 40        # 每包最小数据负载（字节）
PAYLOAD_MAX = 80        # 每包最大数据负载（字节）
TOTAL_PACKETS = 30      # 总共发送 30 个数据包

# ============ 连接状态机 ============
class ConnState(enum.Enum):
    """连接状态（模拟 TCP 状态机）"""
    CLOSED = "CLOSED"
    SYN_SENT = "SYN_SENT"
    SYN_RCVD = "SYN_RCVD"
    ESTABLISHED = "ESTABLISHED"
    FIN_SENT = "FIN_SENT"
    FIN_RCVD = "FIN_RCVD"


def checksum(data: bytes) -> int:
    """
    计算 IP 风格的 16-bit 反码求和校验和。
    将数据按 16 位字相加，处理进位，最后取反码。
    """
    total = 0
    for i in range(0, len(data) - 1, 2):
        word = (data[i] << 8) + data[i + 1]
        total += word
    if len(data) % 2 == 1:
        total += data[-1] << 8
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def pack_message(msg_type: int, seq: int, ack: int, payload: bytes,
                 student_id: int = None, reserved: int = 0) -> bytes:
    """
    将报文打包为字节流。

    参数：
        msg_type:   报文类型
        seq:        序列号
        ack:        确认号
        payload:    负载数据
        student_id: StudentID 字段值（默认自动计算）
        reserved:   保留字段

    校验和分两趟计算：
      1. 先用 checksum=0 构建头部
      2. 计算头部+负载的校验和
      3. 用正确的校验和重新构建头部
    """
    if student_id is None:
        student_id = compute_student_id()
    data_len = len(payload)
    # 第一趟：校验和=0
    header = struct.pack(HEADER_FORMAT, msg_type, student_id, seq, ack, 0, data_len, reserved)
    # 计算校验和
    csum = checksum(header + payload)
    # 第二趟：填入正确校验和
    header = struct.pack(HEADER_FORMAT, msg_type, student_id, seq, ack, csum, data_len, reserved)
    return header + payload


def unpack_message(data: bytes) -> dict:
    """
    解析 UDP 报文。
    返回字典包含：type, student_id, seq, ack, checksum, data_len, reserved, payload, valid_checksum
    """
    if len(data) < HEADER_SIZE:
        raise ValueError(f"报文太短：{len(data)} 字节 < {HEADER_SIZE} 字节")

    msg_type, student_id, seq, ack, csum, data_len, reserved = struct.unpack(
        HEADER_FORMAT, data[:HEADER_SIZE])
    payload = data[HEADER_SIZE:HEADER_SIZE + data_len] if data_len > 0 else b""

    # 验证校验和（校验和为0则跳过）
    valid = True
    if csum != 0:
        zero_header = struct.pack(HEADER_FORMAT, msg_type, student_id, seq, ack, 0, data_len, reserved)
        calc = checksum(zero_header + payload)
        valid = (calc == csum)

    return {
        "type": msg_type,
        "student_id": student_id,
        "seq": seq,
        "ack": ack,
        "checksum": csum,
        "data_len": data_len,
        "reserved": reserved,
        "payload": payload,
        "valid_checksum": valid,
        "total_len": HEADER_SIZE + data_len,
    }


def timestamp() -> str:
    """返回高精度时间戳，用于日志记录（与 Wireshark 抓包时间戳对应）。"""
    t = time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%S.", time.localtime(t)) + \
           f"{int(t * 1_000_000) % 1_000_000:06d}"


def time_ms() -> float:
    """返回当前时间的毫秒值（用于 RTT 计算）。"""
    return time.time() * 1000.0
