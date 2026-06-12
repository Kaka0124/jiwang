#!/usr/bin/env python3
"""
UDP 服务端 —— Task2
====================
在 UDP 应用层模拟 TCP 的可靠数据接收：
  - 应用层三次握手（连接建立）
  - 应用层四次挥手（连接断开）
  - Go-Back-N 接收方：按序交付、累积确认
  - 模拟丢包（可配置丢包率，仅针对 DATA 报文）

用法：
    python3 udpserver.py <端口> [丢包率]

示例：
    python3 udpserver.py 9999              # 不模拟丢包
    python3 udpserver.py 9999 0.15         # 15% 丢包率
"""

import socket
import sys
import random
import struct

from udp_protocol import (
    UDPType, TYPE_NAMES, HEADER_SIZE,
    pack_message, unpack_message,
    ConnState, validate_student_id,
    timestamp,
)

LOG_FILE = "run_log.txt"


def log(msg: str):
    """输出日志到终端和 run_log.txt"""
    ts = timestamp()
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


class UDPServer:
    """UDP 服务端：TCP 风格的连接管理 + GBN 接收方"""

    def __init__(self, port: int, drop_rate: float = 0.0):
        self.port = port
        self.drop_rate = drop_rate          # 模拟丢包概率（仅针对 DATA 报文）
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", port))
        self.sock.settimeout(30.0)          # 30s 空闲超时

        # 每个客户端的状态，键为 (ip, port)
        self.clients = {}

    def _should_drop(self, msg_type: int) -> bool:
        """
        随机决定是否模拟丢包。
        仅丢弃 DATA 报文，控制报文（SYN、ACK、FIN、NAK）总是送达。
        """
        if msg_type != UDPType.DATA:
            return False
        return random.random() < self.drop_rate

    def run(self):
        """服务端主循环"""
        log(f"[服务端] 已启动，监听 0.0.0.0:{self.port}（丢包率={self.drop_rate:.0%}）")

        while True:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                log("[服务端] 空闲超时 —— 30s 无活动，关闭")
                break

            # 模拟入站丢包（仅 DATA 报文）
            if len(data) >= 2:
                pkt_type = struct.unpack("!H", data[:2])[0]
                if self._should_drop(pkt_type):
                    log(f"[服务端] [模拟丢包] 丢弃了来自 {addr[0]}:{addr[1]} 的 "
                        f"{TYPE_NAMES.get(pkt_type, pkt_type)} 报文")
                    continue

            self._handle_packet(data, addr)

        self.sock.close()
        log("[服务端] 已停止")

    def _handle_packet(self, data: bytes, addr: tuple):
        """处理收到的 UDP 报文，按类型分发"""
        try:
            msg = unpack_message(data)
        except ValueError as e:
            log(f"[服务端] 解析报文失败，来自 {addr}：{e}")
            return

        if not msg["valid_checksum"]:
            log(f"[服务端] 警告：校验和不匹配，来自 {addr} —— 丢弃")
            return

        msg_type = msg["type"]

        # 按报文类型分发处理
        if msg_type == UDPType.SYN:
            self._handle_syn(msg, addr)          # 三次握手第1步
        elif msg_type == UDPType.ACK:
            self._handle_ack(msg, addr)          # 握手/挥手的 ACK
        elif msg_type == UDPType.DATA:
            self._handle_data(msg, addr)         # 数据传输（GBN 接收）
        elif msg_type == UDPType.FIN:
            self._handle_fin(msg, addr)          # 四次挥手
        else:
            log(f"[服务端] 意外的报文类型 {TYPE_NAMES.get(msg_type, msg_type)}，来自 {addr}")

    # ==================== 三次握手 ====================

    def _handle_syn(self, msg: dict, addr: tuple):
        """处理 SYN：三次握手 第1步→第2步（含 StudentID 验证）"""
        client_seq = msg["seq"]
        student_id = msg.get("student_id", 0)

        # 验证 StudentID：再次 XOR 0x5A3C，检查是否在 0~9999 范围
        valid, last4 = validate_student_id(student_id)
        if not valid:
            log(f"[服务端] [{addr[0]}:{addr[1]}] StudentID 验证失败！"
                f"收到值={student_id}（0x{student_id:04X}），"
                f"还原={last4}，不合法 —— 拒绝连接")
            return  # 不回复，拒绝连接

        log(f"[服务端] [{addr[0]}:{addr[1]}] StudentID 验证通过（学号后4位={last4}）")

        # 初始化客户端状态
        server_isn = random.randint(0, 2**31 - 1)
        self.clients[addr] = {
            "state": ConnState.SYN_RCVD,
            "server_isn": server_isn,
            "expected_seq": client_seq + 1,
            "received_data": bytearray(),
            "packets_received": 0,
            "client_student_id": student_id,
            "student_last4": last4,
        }

        log(f"[服务端] [{addr[0]}:{addr[1]}] 收到 SYN（client_seq={client_seq}，"
            f"StudentID=0x{student_id:04X}）→ SYN_RCVD")
        log(f"[服务端] [{addr[0]}:{addr[1]}] 发送 SYN-ACK（server_seq={server_isn}，"
            f"ack={client_seq + 1}）")

        # 发送 SYN-ACK
        syn_ack = pack_message(UDPType.SYN_ACK, server_isn, client_seq + 1, b"")
        self.sock.sendto(syn_ack, addr)

    def _handle_ack(self, msg: dict, addr: tuple):
        """处理 ACK：用于握手确认或挥手确认"""
        if addr not in self.clients:
            log(f"[服务端] [{addr[0]}:{addr[1]}] 收到 ACK 但没有客户端状态 —— 忽略")
            return

        state = self.clients[addr]["state"]

        if state == ConnState.SYN_RCVD:
            # 三次握手 第2步→第3步：收到客户端 ACK → 进入 ESTABLISHED
            self.clients[addr]["state"] = ConnState.ESTABLISHED
            log(f"[服务端] [{addr[0]}:{addr[1]}] 收到 ACK → ESTABLISHED "
                f"（ack={msg['ack']}）")

        elif state == ConnState.FIN_RCVD:
            # 四次挥手 第4步：收到客户端最终 ACK → CLOSED
            log(f"[服务端] [{addr[0]}:{addr[1]}] 收到最终 ACK → CLOSED")
            self._cleanup_client(addr)

    # ==================== 数据传输（GBN 接收方）====================

    def _handle_data(self, msg: dict, addr: tuple):
        """处理 DATA 报文：GBN 接收方，按序交付 + 累积确认"""
        if addr not in self.clients:
            log(f"[服务端] [{addr[0]}:{addr[1]}] 收到 DATA 但没有连接 —— 忽略")
            return

        client = self.clients[addr]
        if client["state"] != ConnState.ESTABLISHED:
            log(f"[服务端] [{addr[0]}:{addr[1]}] 收到 DATA 但未 ESTABLISHED"
                f"（状态={client['state'].value}）—— 忽略")
            return

        seq = msg["seq"]
        expected = client["expected_seq"]
        payload = msg["payload"]
        data_len = msg["data_len"]

        client["packets_received"] += 1
        pkt_num = client["packets_received"]

        if seq == expected:
            # 按序到达 → 接收数据，推进期望序号
            client["received_data"].extend(payload)
            client["expected_seq"] += data_len

            log(f"[服务端] [{addr[0]}:{addr[1]}] DATA #{pkt_num}：seq={seq}，"
                f"len={data_len} —— 按序 ✓")

            # 发送累积 ACK（确认所有连续收到的字节）
            ack = pack_message(UDPType.ACK, 0, client["expected_seq"], b"")
            self.sock.sendto(ack, addr)
            log(f"[服务端] [{addr[0]}:{addr[1]}] → 累积 ACK={client['expected_seq']}")

        elif seq < expected:
            # 重复包（之前的 ACK 可能丢了）→ 重发 ACK
            log(f"[服务端] [{addr[0]}:{addr[1]}] DATA #{pkt_num}：seq={seq}，"
                f"len={data_len} —— 重复（期望={expected}）")
            ack = pack_message(UDPType.ACK, 0, expected, b"")
            self.sock.sendto(ack, addr)
            log(f"[服务端] [{addr[0]}:{addr[1]}] → 重发 ACK={expected}")

        else:
            # 乱序包 → GBN 策略：直接丢弃
            log(f"[服务端] [{addr[0]}:{addr[1]}] DATA #{pkt_num}：seq={seq}，"
                f"len={data_len} —— 乱序（期望={expected}）—— 丢弃")
            # 发送 NAK，告知期望的序号（帮助客户端更快发现丢包）
            nak = pack_message(UDPType.NAK, 0, expected, b"")
            self.sock.sendto(nak, addr)
            log(f"[服务端] [{addr[0]}:{addr[1]}] → NAK，期望={expected}")

    # ==================== 四次挥手 ====================

    def _handle_fin(self, msg: dict, addr: tuple):
        """处理 FIN：四次挥手"""
        if addr not in self.clients:
            log(f"[服务端] [{addr[0]}:{addr[1]}] 收到 FIN 但没有状态 —— 忽略")
            return

        client = self.clients[addr]
        client["state"] = ConnState.FIN_RCVD

        log(f"[服务端] [{addr[0]}:{addr[1]}] 收到 FIN → FIN_RCVD")
        log(f"[服务端] [{addr[0]}:{addr[1]}] 发送 FIN 的 ACK")

        # 第2步：发送 ACK 确认 FIN
        fin_ack = pack_message(UDPType.ACK, 0, msg["seq"] + 1, b"")
        self.sock.sendto(fin_ack, addr)

        # 第3步：发送服务端自己的 FIN
        log(f"[服务端] [{addr[0]}:{addr[1]}] 发送 FIN")
        fin_pkt = pack_message(UDPType.FIN, client["server_isn"] + 1, 0, b"")
        self.sock.sendto(fin_pkt, addr)

        # 打印数据接收汇总
        data = bytes(client["received_data"])
        log(f"[服务端] [{addr[0]}:{addr[1]}] 共收到数据：{len(data)} 字节，"
            f"{client['packets_received']} 个报文")

    def _cleanup_client(self, addr: tuple):
        """清理客户端状态"""
        if addr in self.clients:
            del self.clients[addr]
            log(f"[服务端] [{addr[0]}:{addr[1]}] 客户端状态已清理")


def main():
    if len(sys.argv) < 2:
        print(f"用法：python3 {sys.argv[0]} <端口> [丢包率]")
        print(f"示例：python3 {sys.argv[0]} 9999")
        print(f"      python3 {sys.argv[0]} 9999 0.15  # 15% 丢包")
        sys.exit(1)

    port = int(sys.argv[1])
    drop_rate = float(sys.argv[2]) if len(sys.argv) > 2 else 0.0

    if drop_rate < 0 or drop_rate > 1:
        print("错误：丢包率必须在 0.0~1.0 之间")
        sys.exit(1)

    # 清空旧日志
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write(f"=== UDP 服务端日志 ===\n")
        f.write(f"启动时间：{timestamp()}\n")
        f.write(f"端口：{port}，丢包率：{drop_rate:.0%}\n")
        f.write(f"{'=' * 60}\n\n")

    server = UDPServer(port, drop_rate)
    try:
        server.run()
    except KeyboardInterrupt:
        log("[服务端] 关闭中（Ctrl+C）...")
        server.sock.close()


if __name__ == "__main__":
    main()
