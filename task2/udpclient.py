#!/usr/bin/env python3
"""
UDP 客户端 —— Task2
====================
在 UDP 应用层模拟 TCP 的可靠数据传输：
  - 应用层三次握手（连接建立）
  - 应用层四次挥手（连接断开）
  - Go-Back-N 发送方：固定 400 字节窗口、累积确认
  - 超时重传（300ms）
  - 统计信息：丢包率、最大/最小/平均 RTT

用法：
    python3 udpclient.py <服务器IP> <端口>

示例：
    python3 udpclient.py 127.0.0.1 9999
"""

import socket
import sys
import random
import time

from udp_protocol import (
    UDPType, TYPE_NAMES, HEADER_SIZE,
    pack_message, unpack_message,
    WINDOW_SIZE, TIMEOUT_MS,
    PAYLOAD_MIN, PAYLOAD_MAX, TOTAL_PACKETS,
    compute_student_id,
    timestamp, time_ms,
)

LOG_FILE = "run_log.txt"


def log(msg: str):
    """输出日志到终端和 run_log.txt"""
    ts = timestamp()
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


class GBNSender:
    """
    Go-Back-N 发送方实现。

    窗口流量控制：
      - 窗口大小 = 400 字节
      - 每包数据 40~80 字节（随机），窗口容纳 5~10 个包
      - 发送窗口中所有能发的包
      - 超时后重传窗口中所有未确认的包（回退 N）
      - 收到累积 ACK 后滑动窗口
    """

    def __init__(self, sock: socket.socket, server_addr: tuple,
                 data_chunks: list, timeout_ms: int = TIMEOUT_MS):
        self.sock = sock
        self.server_addr = server_addr
        self.data_chunks = data_chunks           # [(序号, 负载), ...] 列表
        self.total_chunks = len(data_chunks)
        self.timeout_ms = timeout_ms / 1000.0    # 转换为秒

        self.base = 0            # 窗口左边界
        self.next_seq = 0        # 下一个要发送的块索引
        self.window_size = WINDOW_SIZE

        self.acked = set()
        self.send_times = {}     # 块索引 → 发送时间戳（RTT）
        self.total_sends = 0     # 总共发送次数（含重传）
        self.rtt_samples = []

        self.timer_start = None

    def has_more(self) -> bool:
        return self.next_seq < self.total_chunks

    def all_acked(self) -> bool:
        return len(self.acked) >= self.total_chunks and \
               all(i in self.acked for i in range(self.total_chunks))

    def bytes_in_flight(self) -> int:
        """计算当前在途（已发送但未确认）的字节总数"""
        total = 0
        for i in range(self.base, min(self.next_seq, self.total_chunks)):
            if i not in self.acked:
                total += len(self.data_chunks[i][1])
        return total

    def send_window(self):
        """发送窗口中所有可发的包"""
        while self.has_more():
            next_payload_len = len(self.data_chunks[self.next_seq][1])
            if self.bytes_in_flight() + next_payload_len > self.window_size:
                break

            i = self.next_seq
            seq, payload = self.data_chunks[i]

            pkt = pack_message(UDPType.DATA, seq, 0, payload)
            self.sock.sendto(pkt, self.server_addr)
            self.total_sends += 1

            now = time_ms()
            self.send_times[i] = now
            self.next_seq += 1

            if self.timer_start is None:
                self.timer_start = now

            pkt_num = i + 1
            byte_start = seq
            byte_end = seq + len(payload) - 1
            log(f"第{pkt_num}个（第{byte_start}~{byte_end}字节）client=>server发送数据")

    def on_ack(self, ack_seq: int):
        """处理累积 ACK"""
        newly_acked = 0
        for i in range(self.base, self.total_chunks):
            chunk_seq, chunk_payload = self.data_chunks[i]
            chunk_end = chunk_seq + len(chunk_payload)
            if chunk_end <= ack_seq:
                if i not in self.acked:
                    self.acked.add(i)
                    newly_acked += 1
                    if i in self.send_times:
                        rtt = time_ms() - self.send_times[i]
                        self.rtt_samples.append(rtt)
            else:
                break

        while self.base < self.total_chunks and self.base in self.acked:
            self.base += 1

        if newly_acked > 0:
            log(f"第{self.base}个（第{ack_seq}字节）server=>client收到响应")

        if self.base < self.next_seq:
            self.timer_start = time_ms()
        else:
            self.timer_start = None

    def on_nak(self, expected_seq: int):
        """处理 NAK"""
        log(f"收到 NAK：服务端期望 seq={expected_seq}，当前 base 块 seq="
            f"{self.data_chunks[self.base][0] if self.base < self.total_chunks else 'N/A'}")

        for i in range(self.base, self.total_chunks):
            chunk_seq = self.data_chunks[i][0]
            if chunk_seq >= expected_seq:
                for j in range(self.base, i):
                    if j not in self.acked:
                        self.acked.add(j)
                while self.base < self.total_chunks and self.base in self.acked:
                    self.base += 1
                break
        self._retransmit_window()

    def check_timeout(self) -> bool:
        """检查超时，返回 True 表示触发了重传"""
        if self.timer_start is None:
            return False

        elapsed = time_ms() - self.timer_start
        if elapsed > self.timeout_ms * 1000:
            oldest = None
            for i in range(self.base, min(self.next_seq, self.total_chunks)):
                if i not in self.acked:
                    oldest = i + 1
                    break

            oldest_seq = self.data_chunks[self.base][0] if self.base < self.total_chunks else 0
            oldest_end = oldest_seq + len(self.data_chunks[self.base][1]) - 1 if self.base < self.total_chunks else 0
            log(f"第{oldest}个（第{oldest_seq}~{oldest_end}字节）超时，重传")
            self._retransmit_window()
            return True
        return False

    def _retransmit_window(self):
        """重传窗口中所有未确认的包（GBN 回退 N）"""
        retrans_count = 0
        for i in range(self.base, min(self.next_seq, self.total_chunks)):
            if i not in self.acked:
                seq, payload = self.data_chunks[i]
                pkt = pack_message(UDPType.DATA, seq, 0, payload)
                self.sock.sendto(pkt, self.server_addr)
                self.total_sends += 1
                self.send_times[i] = time_ms()
                retrans_count += 1

        if retrans_count > 0:
            self.timer_start = time_ms()

    def stats(self) -> dict:
        """计算统计信息"""
        unique = self.total_chunks
        pct_loss = (unique / self.total_sends * 100) if self.total_sends > 0 else 100

        rtts = self.rtt_samples
        if rtts:
            max_rtt = max(rtts)
            min_rtt = min(rtts)
            avg_rtt = sum(rtts) / len(rtts)
        else:
            max_rtt = min_rtt = avg_rtt = 0

        return {
            "unique_packets": unique,
            "total_sent": self.total_sends,
            "loss_rate": pct_loss,
            "max_rtt_ms": max_rtt,
            "min_rtt_ms": min_rtt,
            "avg_rtt_ms": avg_rtt,
            "rtt_samples": len(rtts),
        }


def generate_data(start_seq: int = 0) -> list:
    """
    生成 30 个数据块。每块数据 40~80 字节随机（任务书要求）。
    返回 [(序号, 负载字节), ...] 列表。
    """
    chunks = []
    seq = start_seq
    for i in range(TOTAL_PACKETS):
        payload_size = random.randint(PAYLOAD_MIN, PAYLOAD_MAX)
        # 构造带包号标识的数据
        header = f"PKT{i + 1:02d}|".encode("ascii")
        padding = b"X" * (payload_size - len(header) - 8)
        footer = f"|END{i + 1:02d}".encode("ascii")
        payload = header + padding + footer
        payload = payload[:payload_size]

        chunks.append((seq, payload))
        seq += len(payload)

    return chunks


def main():
    """主函数"""
    if len(sys.argv) != 3:
        print(f"用法：python3 {sys.argv[0]} <服务器IP> <端口>")
        print(f"示例：python3 {sys.argv[0]} 127.0.0.1 9999")
        sys.exit(1)

    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    server_addr = (server_ip, server_port)

    # 清空旧日志
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write(f"=== UDP 客户端-服务端日志 ===\n")
        f.write(f"启动时间：{timestamp()}\n")
        f.write(f"服务器：{server_ip}:{server_port}\n")
        f.write(f"{'=' * 60}\n\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT_MS / 1000.0)

    # ============ 阶段1：三次握手 ============
    log("[客户端] === 连接建立（三次握手）===")

    client_isn = random.randint(0, 2**31 - 1)
    server_isn = None
    student_id = compute_student_id()

    max_syn_retries = 5
    for syn_attempt in range(max_syn_retries):
        if syn_attempt > 0:
            log(f"[客户端] → SYN（seq={client_isn}，StudentID={student_id}）—— 重试 #{syn_attempt}")
        else:
            log(f"[客户端] → SYN（seq={client_isn}，StudentID={student_id}）")
        syn_pkt = pack_message(UDPType.SYN, client_isn, 0, b"")
        sock.sendto(syn_pkt, server_addr)

        try:
            data, _ = sock.recvfrom(65535)
            msg = unpack_message(data)
            if msg["type"] != UDPType.SYN_ACK:
                log(f"[客户端] 警告：期望 SYN-ACK，收到 "
                    f"{TYPE_NAMES.get(msg['type'], msg['type'])} —— 重试")
                continue
            server_isn = msg["seq"]
            server_ack = msg["ack"]
            log(f"[客户端] ← SYN-ACK（server_seq={server_isn}，ack={server_ack}）")
            if server_ack != client_isn + 1:
                log(f"[客户端] 警告：SYN-ACK ack={server_ack}，期望 {client_isn + 1}")
            break
        except socket.timeout:
            log(f"[客户端] 等待 SYN-ACK 超时（第 {syn_attempt + 1}/{max_syn_retries} 次）")
    else:
        log("[客户端] 错误：多次重试后仍未收到 SYN-ACK")
        sys.exit(1)

    # 第3步：发送 ACK
    ack_pkt = pack_message(UDPType.ACK, client_isn + 1, server_isn + 1, b"")
    sock.sendto(ack_pkt, server_addr)
    log(f"[客户端] → ACK（seq={client_isn + 1}，ack={server_isn + 1}）")
    log("[客户端] 连接已建立 ✓")
    log("")

    # ============ 阶段2：生成数据块 ============
    data_start_seq = client_isn + 1
    data_chunks = generate_data(start_seq=data_start_seq)
    total_bytes = sum(len(p[1]) for p in data_chunks)
    log(f"[客户端] 已生成 {len(data_chunks)} 个数据块，"
        f"共 {total_bytes} 字节，窗口={WINDOW_SIZE}B，每包 {PAYLOAD_MIN}~{PAYLOAD_MAX}B")

    # ============ 阶段3：GBN 数据传输 ============
    log("[客户端] === 数据传输（Go-Back-N）===")

    gbn = GBNSender(sock, server_addr, data_chunks, TIMEOUT_MS)
    start_time = time.time()
    handshake_ack_pkt = ack_pkt
    no_response_count = 0

    while not gbn.all_acked():
        gbn.send_window()

        try:
            data, _ = sock.recvfrom(65535)
            msg = unpack_message(data)
            no_response_count = 0

            if not msg["valid_checksum"]:
                log("[客户端] 警告：校验和无效 —— 忽略")
                continue

            if msg["type"] == UDPType.ACK:
                gbn.on_ack(msg["ack"])
            elif msg["type"] == UDPType.NAK:
                gbn.on_nak(msg["ack"])

        except socket.timeout:
            gbn.check_timeout()
            no_response_count += 1

            if no_response_count >= 3:
                log("[客户端] 连续 3 次无响应 —— 重传握手 ACK")
                sock.sendto(handshake_ack_pkt, server_addr)
                no_response_count = 0

        gbn.check_timeout()
        time.sleep(0.001)

    elapsed = time.time() - start_time
    log("")

    # ============ 阶段4：四次挥手 ============
    log("[客户端] === 连接断开（四次挥手）===")

    fin_seq = client_isn + 1 + total_bytes
    log(f"[客户端] → FIN（seq={fin_seq}）")
    fin_pkt = pack_message(UDPType.FIN, fin_seq, 0, b"")
    sock.sendto(fin_pkt, server_addr)

    try:
        data, _ = sock.recvfrom(65535)
        msg = unpack_message(data)
        if msg["type"] == UDPType.ACK:
            log(f"[客户端] ← FIN 的 ACK（ack={msg['ack']}）")
    except socket.timeout:
        log("[客户端] 警告：等待 FIN 的 ACK 超时")

    try:
        data, _ = sock.recvfrom(65535)
        msg = unpack_message(data)
        if msg["type"] == UDPType.FIN:
            log(f"[客户端] ← 服务端 FIN（seq={msg['seq']}）")
            final_ack = pack_message(UDPType.ACK, 0, msg["seq"] + 1, b"")
            sock.sendto(final_ack, server_addr)
            log(f"[客户端] → 最终 ACK（ack={msg['seq'] + 1}）")
    except socket.timeout:
        log("[客户端] 警告：等待服务端 FIN 超时")

    log("[客户端] 连接已关闭 ✓")
    log("")

    # ============ 统计汇总 ============
    stats = gbn.stats()
    log(f"{'=' * 50}")
    log(f"汇总：")
    log(f"  唯一数据包数：        {stats['unique_packets']}")
    log(f"  实际发送次数：        {stats['total_sent']}（含重传）")
    log(f"  丢包率：              {stats['loss_rate']:.1f}%")
    log(f"  RTT 样本数：          {stats['rtt_samples']}")
    log(f"  最大 RTT：            {stats['max_rtt_ms']:.2f} ms")
    log(f"  最小 RTT：            {stats['min_rtt_ms']:.2f} ms")
    log(f"  平均 RTT：            {stats['avg_rtt_ms']:.2f} ms")
    log(f"  总耗时：              {elapsed:.3f}s")
    log(f"{'=' * 50}")

    sock.close()


if __name__ == "__main__":
    main()
