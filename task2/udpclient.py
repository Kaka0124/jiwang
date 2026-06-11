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
    MTU_PAYLOAD, TOTAL_PACKETS,
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

        # ===== 窗口状态 =====
        self.base = 0            # 窗口左边界（最老未确认块的索引）
        self.next_seq = 0        # 下一个要发送的块索引
        self.window_size = WINDOW_SIZE

        # ===== 追踪信息 =====
        self.acked = set()       # 已确认块的索引集合
        self.send_times = {}     # 块索引 → 发送时间戳（用于 RTT 计算）
        self.total_sends = 0     # 总共发送次数（含重传）
        self.rtt_samples = []    # RTT 样本列表（毫秒）

        # ===== 定时器 =====
        self.timer_start = None  # 最老未确认包的定时器启动时间

    def has_more(self) -> bool:
        """是否还有未发送的块"""
        return self.next_seq < self.total_chunks

    def all_acked(self) -> bool:
        """是否所有块都已确认"""
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
        """
        发送窗口中所有可发的包。
        窗口限制：在途字节 + 下一个包的负载 ≤ 窗口大小。
        """
        sent_count = 0
        while self.has_more():
            next_payload_len = len(self.data_chunks[self.next_seq][1])
            # 检查下一个包是否能放入剩余窗口
            if self.bytes_in_flight() + next_payload_len > self.window_size:
                break

            i = self.next_seq
            seq, payload = self.data_chunks[i]

            # 构造并发送 DATA 报文
            pkt = pack_message(UDPType.DATA, seq, 0, payload)
            self.sock.sendto(pkt, self.server_addr)
            self.total_sends += 1

            now = time_ms()
            self.send_times[i] = now
            self.next_seq += 1
            sent_count += 1

            # 如果这是唯一的未确认包，启动定时器
            if self.timer_start is None:
                self.timer_start = now

            pkt_num = i + 1
            byte_start = seq
            byte_end = seq + len(payload) - 1
            log(f"[客户端] 发送第 {pkt_num}/{self.total_chunks} 个数据包："
                f"第 {byte_start}~{byte_end} 字节，seq={seq}，len={len(payload)}")

        return sent_count

    def on_ack(self, ack_seq: int):
        """
        处理累积 ACK。
        ack_seq 是服务端期望的下一个字节 → 所有 < ack_seq 的字节已确认。
        """
        newly_acked = 0
        for i in range(self.base, self.total_chunks):
            chunk_seq, chunk_payload = self.data_chunks[i]
            chunk_end = chunk_seq + len(chunk_payload)
            if chunk_end <= ack_seq:
                if i not in self.acked:
                    self.acked.add(i)
                    newly_acked += 1
                    # 记录 RTT
                    if i in self.send_times:
                        rtt = time_ms() - self.send_times[i]
                        self.rtt_samples.append(rtt)
            else:
                break

        # 滑动窗口
        while self.base < self.total_chunks and self.base in self.acked:
            self.base += 1

        if newly_acked > 0:
            log(f"[客户端] 收到 ACK：ack_seq={ack_seq}，"
                f"新确认 {newly_acked} 个，base={self.base}，next={self.next_seq}")

        # 重启定时器
        if self.base < self.next_seq:
            self.timer_start = time_ms()
        else:
            self.timer_start = None

    def on_nak(self, expected_seq: int):
        """
        处理 NAK —— 服务端期望 expected_seq。
        这意味着 expected_seq 之前的数据都已收到，可以滑动 base。
        然后重传窗口中所有未确认的包。
        """
        log(f"[客户端] 收到 NAK：服务端期望 seq={expected_seq}，"
            f"当前 base 块的 seq={self.data_chunks[self.base][0] if self.base < self.total_chunks else 'N/A'}")

        # 找到包含 expected_seq 的块索引
        for i in range(self.base, self.total_chunks):
            chunk_seq = self.data_chunks[i][0]
            if chunk_seq >= expected_seq:
                # 确认该块之前的所有块
                for j in range(self.base, i):
                    if j not in self.acked:
                        self.acked.add(j)
                while self.base < self.total_chunks and self.base in self.acked:
                    self.base += 1
                break

        # 重传窗口中所有未确认的包
        self._retransmit_window()

    def check_timeout(self) -> bool:
        """检查是否超时。返回 True 表示触发了重传。"""
        if self.timer_start is None:
            return False

        elapsed = time_ms() - self.timer_start
        if elapsed > self.timeout_ms * 1000:
            # 找到最老的未确认包号
            oldest = None
            for i in range(self.base, min(self.next_seq, self.total_chunks)):
                if i not in self.acked:
                    oldest = i + 1  # 1-based 包号
                    break

            log(f"[客户端] 第 {oldest} 个数据包超时 "
                f"（已过 {elapsed:.1f}ms > {self.timeout_ms * 1000:.0f}ms），"
                f"重传窗口 [base={self.base}, next={min(self.next_seq, self.total_chunks)})")

            self._retransmit_window()
            return True
        return False

    def _retransmit_window(self):
        """重传窗口中所有未确认的包（GBN 的核心行为：回退 N）"""
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
            log(f"[客户端] 重传了 {retrans_count} 个包")
            self.timer_start = time_ms()

    def stats(self) -> dict:
        """计算并返回统计信息"""
        unique = self.total_chunks
        # 丢包率 = 30 / 实际发送的UDP包总数 × 100%
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


def generate_data(start_seq: int = 0, payload_size: int = 180) -> list:
    """
    生成 30 个数据块。
    每块约 payload_size 字节（默认 180B，约 2 个包放入 400B 窗口）。
    返回 [(序号, 负载字节), ...] 列表。
    """
    chunks = []
    seq = start_seq
    for i in range(TOTAL_PACKETS):
        # 构造带包号标识的数据
        msg = (f"PKT{i + 1:02d}|" + "X" * (payload_size - 20) + f"|END{i + 1:02d}")
        msg = msg[:payload_size]
        payload = msg.encode("ascii")

        if len(payload) > MTU_PAYLOAD:
            payload = payload[:MTU_PAYLOAD]

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

    # 创建 UDP 套接字
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT_MS / 1000.0)  # 接收超时设为 300ms

    # ============ 阶段1：三次握手 ============
    log("[客户端] === 连接建立（三次握手）===")

    client_isn = random.randint(0, 2**31 - 1)  # 客户端初始序列号
    server_isn = None

    # 第1~2步：发送 SYN，等待 SYN-ACK（支持重试）
    max_syn_retries = 5
    for syn_attempt in range(max_syn_retries):
        if syn_attempt > 0:
            log(f"[客户端] → SYN（seq={client_isn}）—— 重试 #{syn_attempt}")
        else:
            log(f"[客户端] → SYN（seq={client_isn}）")
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
    data_start_seq = client_isn + 1  # 数据序号从握手之后连续
    data_chunks = generate_data(start_seq=data_start_seq)
    total_bytes = sum(len(p[1]) for p in data_chunks)
    log(f"[客户端] 已生成 {len(data_chunks)} 个数据块，"
        f"共 {total_bytes} 字节，窗口={WINDOW_SIZE}B")

    # ============ 阶段3：GBN 数据传输 ============
    log("[客户端] === 数据传输（Go-Back-N）===")
    log("")

    gbn = GBNSender(sock, server_addr, data_chunks, TIMEOUT_MS)

    start_time = time.time()
    handshake_ack_pkt = ack_pkt  # 保存握手 ACK，以防需要重传
    no_response_count = 0

    while not gbn.all_acked():
        # 1. 发送窗口内的包
        gbn.send_window()

        # 2. 尝试接收 ACK/NAK
        try:
            data, _ = sock.recvfrom(65535)
            msg = unpack_message(data)
            no_response_count = 0  # 有响应则重置计数器

            if not msg["valid_checksum"]:
                log("[客户端] 警告：校验和无效 —— 忽略")
                continue

            if msg["type"] == UDPType.ACK:
                gbn.on_ack(msg["ack"])
            elif msg["type"] == UDPType.NAK:
                gbn.on_nak(msg["ack"])  # NAK 的 ack 字段携带期望序号

        except socket.timeout:
            # 无响应 → 检查 GBN 超时
            gbn.check_timeout()
            no_response_count += 1

            # 连续多次无响应 → 可能是握手 ACK 丢了 → 重传之
            if no_response_count >= 3:
                log("[客户端] 连续 3 次无响应 —— "
                    "重传握手 ACK（可能之前丢了）")
                sock.sendto(handshake_ack_pkt, server_addr)
                no_response_count = 0

        # 3. 再次检查 GBN 定时器
        gbn.check_timeout()

        # 防止忙等待
        time.sleep(0.001)

    elapsed = time.time() - start_time
    log("")

    # ============ 阶段4：四次挥手 ============
    log("[客户端] === 连接断开（四次挥手）===")

    # 第1步：发送 FIN
    fin_seq = client_isn + 1 + total_bytes  # 所有数据之后的序号
    log(f"[客户端] → FIN（seq={fin_seq}）")
    fin_pkt = pack_message(UDPType.FIN, fin_seq, 0, b"")
    sock.sendto(fin_pkt, server_addr)

    # 第2步：等待 FIN 的 ACK
    try:
        data, _ = sock.recvfrom(65535)
        msg = unpack_message(data)
        if msg["type"] == UDPType.ACK:
            log(f"[客户端] ← FIN 的 ACK（ack={msg['ack']}）")
    except socket.timeout:
        log("[客户端] 警告：等待 FIN 的 ACK 超时")

    # 第3步：等待服务端的 FIN
    try:
        data, _ = sock.recvfrom(65535)
        msg = unpack_message(data)
        if msg["type"] == UDPType.FIN:
            log(f"[客户端] ← 服务端 FIN（seq={msg['seq']}）")
            # 第4步：发送最终 ACK
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
