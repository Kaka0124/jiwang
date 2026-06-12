UDP Socket Programming — Packet Capture Documentation

1. Wireshark 包捕获截图

抓包设置
- Interface: lo0 (loopback)
- Filter: udp.port == 9999
- 步骤:
  1. 先启动 Wireshark，选择 lo0 接口开始抓包
  2. 启动 server: python3 udpserver.py 9999 0.15
  3. 启动 client: python3 udpclient.py 127.0.0.1 9999
  4. 停止抓包，应用过滤器分析

截图 1：三次握手（连接建立）
- SYN (client→server): UDP payload 首 2 字节为 0x0001，StudentID 字段为学号后5位，seq 为客户端 ISN
- SYN-ACK (server→client): 首 2 字节为 0x0002，seq 为服务端 ISN，ack 为 client_ISN+1
- ACK (client→server): 首 2 字节为 0x0003，ack 为 server_ISN+1

可在 Wireshark 中展开 UDP payload，对比 20 字节头部各字段。

截图 2：数据传输 — GBN 窗口发送
- DATA 包: 首 2 字节为 0x0004，seq 为字节偏移，data_len 指示负载长度
- ACK 包: 首 2 字节为 0x0003，ack 为累积确认的下一期望字节
- 可观察到 client 连续发送 2-3 个 DATA 包（窗口 400B 内），server 返回累积 ACK

截图 3：超时重传 / NAK 重传
- NAK (server→client): 首 2 字节为 0x0007，ack 字段指示期望的 seq
- 重传的 DATA 包: seq 与之前丢失的包相同
- 可在 Wireshark 时间戳中计算重传间隔

截图 4：四次挥手（连接断开）
- FIN (client→server): 首 2 字节为 0x0005
- ACK (server→client): 首 2 字节为 0x0003，确认 FIN
- FIN (server→client): 首 2 字节为 0x0005，服务器主动关闭
- Final ACK (client→server): 首 2 字节为 0x0003，确认服务器 FIN

2. 实现关键点及代码说明

2.1 自定义应用层协议报文格式

报文首部设计（20 字节）:

| 偏移 | 大小 | 字段       | 说明                                  |
|------|------|------------|---------------------------------------|
| 0    | 2    | Type       | 报文类型（uint16 BE）                  |
| 2    | 4    | StudentID  | 学号后5位（uint32 BE），连接建立必填    |
| 6    | 4    | Seq        | 序列号（字节偏移，uint32 BE）           |
| 10   | 4    | Ack        | 确认号（下一期望字节，uint32 BE）       |
| 14   | 2    | Checksum   | 校验和（IP 风格 16-bit ones' complement）|
| 16   | 2    | Data Length| 数据负载长度（uint16 BE）              |
| 18   | 2    | Reserved   | 保留 / 窗口大小                       |

任务书要求连接建立报文首部必须包含 StudentID 字段（学号后5位），因此头部从 16 字节扩展到 20 字节。

HEADER_SIZE = 20
HEADER_FORMAT = "!HIIIHHH"  # type + student_id + seq + ack + checksum + data_len + reserved

七种报文类型:

class UDPType(enum.IntEnum):
    SYN = 0x0001      # 连接请求（三次握手第1步）
    SYN_ACK = 0x0002  # 连接确认（三次握手第2步）
    ACK = 0x0003      # 确认（握手/挥手/数据传输）
    DATA = 0x0004     # 数据
    FIN = 0x0005      # 连接关闭请求
    FIN_ACK = 0x0006  # 关闭确认
    NAK = 0x0007      # 否定确认

设计理由：
- 7 种报文类型完整覆盖 TCP 的连接管理 + 可靠传输语义
- StudentID 字段（4 字节）满足任务书要求，置于 Type 之后便于识别
- Seq/Ack 使用 uint32，类 TCP 的字节流序号空间
- Checksum 使用 IP 风格 16-bit ones' complement，可检测传输错误

校验和实现（udp_protocol.py）:
def checksum(data):
    total = 0
    for i in range(0, len(data) - 1, 2):
        word = (data[i] << 8) + data[i + 1]
        total += word
    if len(data) % 2 == 1:
        total += data[-1] << 8
    while total >> 16:                    # 将进位加回低位
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF              # 取反码

2.2 应用层连接管理（三次握手 + 四次挥手）

状态机设计:

Client: CLOSED → SYN_SENT → ESTABLISHED → FIN_SENT → CLOSED
Server: CLOSED → SYN_RCVD → ESTABLISHED → FIN_RCVD → CLOSED

class ConnState(enum.Enum):
    CLOSED = "CLOSED"
    SYN_SENT = "SYN_SENT"
    SYN_RCVD = "SYN_RCVD"
    ESTABLISHED = "ESTABLISHED"
    FIN_SENT = "FIN_SENT"
    FIN_RCVD = "FIN_RCVD"

三次握手流程（udpclient.py）：

# Step 1: 发送 SYN（携带学号后5位）
client_isn = random.randint(0, 2**31 - 1)
syn_pkt = pack_message(UDPType.SYN, client_isn, 0, b"")
sock.sendto(syn_pkt, server_addr)

# Step 2: 等待 SYN-ACK
data, _ = sock.recvfrom(65535)
msg = unpack_message(data)
server_isn = msg["seq"]     # 服务端 ISN

# Step 3: 发送 ACK
ack_pkt = pack_message(UDPType.ACK, client_isn + 1, server_isn + 1, b"")
sock.sendto(ack_pkt, server_addr)
# → ESTABLISHED

服务端处理 SYN（udpserver.py）：

def _handle_syn(self, msg, addr):
    client_seq = msg["seq"]
    student_id = msg.get("student_id", 0)  # 记录客户端学号
    server_isn = random.randint(0, 2**31 - 1)
    self.clients[addr] = {"state": ConnState.SYN_RCVD, ...}
    # 发送 SYN-ACK
    syn_ack = pack_message(UDPType.SYN_ACK, server_isn, client_seq + 1, b"")
    self.sock.sendto(syn_ack, addr)

四次挥手流程（udpserver.py _handle_fin）：

# Step 1-2: 收到客户端 FIN → 发送 ACK
client["state"] = ConnState.FIN_RCVD
fin_ack = pack_message(UDPType.ACK, 0, msg["seq"] + 1, b"")
self.sock.sendto(fin_ack, addr)

# Step 3: 发送服务端 FIN
fin_pkt = pack_message(UDPType.FIN, client["server_isn"] + 1, 0, b"")
self.sock.sendto(fin_pkt, addr)

# Step 4: 收到客户端最终 ACK → CLOSED

2.3 Go-Back-N (GBN) 可靠传输

核心参数:
  WINDOW_SIZE = 400       # 固定发送窗口: 400 字节
  TIMEOUT_MS = 300        # 超时重传: 300ms
  MTU_PAYLOAD = 1400      # 每包最大负载
  TOTAL_PACKETS = 30      # 共发送 30 个数据包

GBN 发送方核心（udpclient.py GBNSender 类）:

class GBNSender:
    """
    base = 0           窗口左边界（最老未确认的包索引）
    next_seq = 0       下一个要发送的包索引
    window_size = 400  固定窗口大小
    send_times = {}    记录每个包的发送时间（用于 RTT）
    """

    def send_window(self):
        """发送窗口内所有可发的包"""
        while self.has_more():
            next_len = len(self.data_chunks[self.next_seq][1])
            if self.bytes_in_flight() + next_len > self.window_size:
                break  # 窗口满，停止发送

    def on_ack(self, ack_seq):
        """累积确认处理：所有 chunk_end <= ack_seq 的包都被确认"""
        for i in range(self.base, self.total_chunks):
            if chunk_end <= ack_seq:
                self.acked.add(i)
                rtt = time_ms() - self.send_times[i]  # 计算 RTT
        while self.base in self.acked:
            self.base += 1  # 滑动窗口

    def check_timeout(self):
        """超时重传"""
        if time_ms() - self.timer_start > TIMEOUT_MS:
            self._retransmit_window()  # 重传 base 到 next_seq-1 的所有包（回退 N）

GBN 接收方核心（udpserver.py _handle_data）:

def _handle_data(self, msg, addr):
    seq = msg["seq"]
    expected = client["expected_seq"]
    if seq == expected:
        client["received_data"].extend(payload)  # 按序 → 接收
        client["expected_seq"] += data_len
        send_ack(expected_seq)  # 累积 ACK
    elif seq < expected:
        send_ack(expected)      # 重复包 → 重发 ACK
    else:
        send_nak(expected)      # 乱序包 → GBN 丢弃，发 NAK

关键设计决策：
1. 累积确认：ACK 的 ack_number 表示"所有小于此号的字节已收到"
2. 固定窗口（400B）：bytes_in_flight + next_payload <= window_size 确保不超窗口
3. NAK 辅助：收到乱序包发送 NAK（携带 expected_seq），帮助发送方更快重传
4. timer_start 管理：每次收到 ACK 重置；所有包确认后取消定时器

2.4 统计信息收集

# 统计项
stats = {
    "unique_packets": 30,       # 唯一数据包数
    "total_sent": 36,           # 实际发送次数（含重传）
    "loss_rate": 83.3,          # 30/36 * 100%
    "max_rtt_ms": 5.52,         # 最大 RTT
    "min_rtt_ms": 0.19,         # 最小 RTT
    "avg_rtt_ms": 3.01,         # 平均 RTT
}

丢包率计算公式：30 / 实际发送的UDP包总数 * 100%
RTT 计算：每次发送记录 send_times[i] = time_ms()，收到 ACK 时 RTT = time_ms() - send_times[i]

2.5 服务端丢包模拟

class UDPServer:
    def __init__(self, port, drop_rate=0.0):
        self.drop_rate = drop_rate  # 丢包概率（仅 DATA 包）

    def _should_drop(self, msg_type):
        if msg_type != UDPType.DATA:
            return False  # 控制报文不丢
        return random.random() < self.drop_rate

3. 知识点总结

理解深刻的知识点

1. TCP 状态机的本质：通过在 UDP 应用层实现 CLOSED → SYN_SENT → SYN_RCVD → ESTABLISHED → FIN_SENT → FIN_RCVD → CLOSED 状态转换，深刻理解了 TCP 连接管理是"在不可靠网络上的端到端状态同步"。

2. Go-Back-N 协议：理解了滑动窗口、累积确认、超时回退 N 的核心机制。窗口大小直接影响吞吐量（window/RTT），以及 GBN 在丢包时效率低的原因（重传整个窗口）。

3. 序列号空间：理解了 TCP 为什么使用字节偏移而非包序号——更灵活地支持变长数据段和重传时的分片重组。

4. 定时器管理：理解了 GBN 只需为一个"最老未确认包"维护一个定时器的原因——收到累积 ACK 后重置，超时后重传整个窗口。

5. 丢包率与 RTT 的统计：通过区分 unique_packets 和 total_sends 计算丢包率；通过记录每个包的 send_time 和 ack_time 计算 RTT 样本。

6. StudentID 字段设计：按任务书要求在 20 字节头部中加入 StudentID 字段（uint32），连接建立时双方交换并记录。

还有疑惑的知识点

1. 快重传（Fast Retransmit）：当前实现了基于 NAK 的重传触发，但真正的 TCP 快重传是基于 3 个重复 ACK 触发，不需要等超时。

2. Selective Repeat (SR)：GBN 在丢包时回退整个窗口效率低。SR 协议只重传丢失的包，但需要更复杂的接收缓冲区管理。

3. 拥塞控制 vs 流量控制：当前只实现了固定窗口的流量控制。TCP 真正的拥塞控制（慢启动、拥塞避免、快恢复）是基于对网络状况的探测。

4. checksum 的实际效果：虽然实现了 IP 风格的 ones' complement checksum，但在 loopback 环境下不会出现比特错误。

5. 动态 RTT 超时计算：当前使用固定 300ms 超时。更精确的做法是不断采集 RTT 样本，实时计算超时重传时间（如 TCP 的 Jacobsen 算法），这是加分项。

4. 运行说明

启动服务端
  python3 udpserver.py 9999           # 无丢包
  python3 udpserver.py 9999 0.15      # 15% 丢包率

启动客户端
  python3 udpclient.py 127.0.0.1 9999

预期输出:
  === 连接建立（三次握手）===
  [客户端] → SYN（seq=2112275825，StudentID=6271）
  [客户端] ← SYN-ACK（server_seq=456875862，ack=2112275826）
  [客户端] → ACK（seq=2112275826，ack=456875863）
  [客户端] 连接已建立

  === 数据传输（Go-Back-N）===
  [客户端] 发送第 1/30 个数据包：第 2112275826~2112275997 字节
  [客户端] 发送第 2/30 个数据包：第 2112275998~2112276169 字节
  [客户端] 收到 ACK：ack_seq=2112275998，新确认 1 个

  === 连接断开（四次挥手）===
  [客户端] → FIN（seq=2112280986）
  [客户端] ← FIN 的 ACK
  [客户端] ← 服务端 FIN
  [客户端] → 最终 ACK
  [客户端] 连接已关闭

  汇总：
    唯一数据包数：30
    实际发送次数：36（含重传）
    丢包率：83.3%
    最大 RTT：5.52 ms
    最小 RTT：0.19 ms
    平均 RTT：3.01 ms

5. Git 仓库
  https://github.com/Kaka0124/jiwang