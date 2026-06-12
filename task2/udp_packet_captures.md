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
- SYN (client→server): UDP payload 首 2 字节为 0x0001，StudentID 字段为 XOR 计算值 0x5017，seq 为客户端 ISN
- SYN-ACK (server→client): 首 2 字节为 0x0002，seq 为服务端 ISN，ack 为 client_ISN+1
- ACK (client→server): 首 2 字节为 0x0003，ack 为 server_ISN+1

可在 Wireshark 中展开 UDP payload，对比 18 字节头部各字段。

截图 2：数据传输 — GBN 窗口发送
- DATA 包: 首 2 字节为 0x0004，seq 为字节偏移，data_len 指示负载长度（40~80 字节）
- ACK 包: 首 2 字节为 0x0003，ack 为累积确认的下一期望字节
- 可观察到 client 连续发送 5~10 个 DATA 包（窗口 400B 内），server 返回累积 ACK

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

报文首部设计（18 字节）:

| 偏移 | 大小 | 字段       | 说明                                  |
|------|------|------------|---------------------------------------|
| 0    | 2    | Type       | 报文类型（uint16 BE）                  |
| 2    | 2    | StudentID  | 学号后4位 XOR 0x5A3C（uint16 BE）      |
| 4    | 4    | Seq        | 序列号（字节偏移，uint32 BE）           |
| 8    | 4    | Ack        | 确认号（下一期望字节，uint32 BE）       |
| 12   | 2    | Checksum   | 校验和（IP 风格 16-bit ones' complement）|
| 14   | 2    | Data Length| 数据负载长度（uint16 BE）              |
| 16   | 2    | Reserved   | 保留 / 窗口大小                       |

HEADER_SIZE = 18
HEADER_FORMAT = "!HHIIHHH"  # type(2) + student_id(2) + seq(4) + ack(4) + checksum(2) + data_len(2) + reserved(2)

StudentID 字段设计（任务书要求）:
- 取学号后4位数字（如 2603），与 0x5A3C 做 XOR 运算
- 2603 ^ 0x5A3C = 0x5017 = 20503，填入 2 字节 uint16 字段
- 服务端验证：对收到值再次 XOR 0x5A3C，检查是否在 0~9999 范围
- 不合法则拒绝连接

def compute_student_id(last4):
    return (last4 ^ 0x5A3C) & 0xFFFF

def validate_student_id(value):
    last4 = (value ^ 0x5A3C) & 0xFFFF
    return (0 <= last4 <= 9999), last4

七种报文类型:

class UDPType(enum.IntEnum):
    SYN = 0x0001      # 连接请求（三次握手第1步）
    SYN_ACK = 0x0002  # 连接确认（三次握手第2步）
    ACK = 0x0003      # 确认（握手/挥手/数据传输）
    DATA = 0x0004     # 数据
    FIN = 0x0005      # 连接关闭请求
    FIN_ACK = 0x0006  # 关闭确认
    NAK = 0x0007      # 否定确认

校验和实现（udp_protocol.py）:
def checksum(data):
    total = 0
    for i in range(0, len(data) - 1, 2):
        word = (data[i] << 8) + data[i + 1]
        total += word
    if len(data) % 2 == 1:
        total += data[-1] << 8
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF

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

三次握手流程（udpclient.py）:

# Step 1: 发送 SYN（携带 XOR 后的 StudentID）
client_isn = random.randint(0, 2**31 - 1)
syn_pkt = pack_message(UDPType.SYN, client_isn, 0, b"")
sock.sendto(syn_pkt, server_addr)

# Step 2: 等待 SYN-ACK
data, _ = sock.recvfrom(65535)
msg = unpack_message(data)
server_isn = msg["seq"]

# Step 3: 发送 ACK
ack_pkt = pack_message(UDPType.ACK, client_isn + 1, server_isn + 1, b"")
sock.sendto(ack_pkt, server_addr)

服务端 StudentID 验证（udpserver.py _handle_syn）:

def _handle_syn(self, msg, addr):
    student_id = msg.get("student_id", 0)
    valid, last4 = validate_student_id(student_id)
    if not valid:
        log(f"StudentID 验证失败！收到值={student_id}，拒绝连接")
        return  # 不回复，拒绝连接
    log(f"StudentID 验证通过（学号后4位={last4}）")
    # ... 继续握手

四次挥手流程（udpserver.py _handle_fin）:

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
  PAYLOAD_MIN = 40        # 每包最小负载: 40 字节
  PAYLOAD_MAX = 80        # 每包最大负载: 80 字节
  TOTAL_PACKETS = 30      # 共发送 30 个数据包

窗口管理: 400 字节窗口容纳 5~10 个数据包（每包 40~80 字节）

GBN 发送方核心（udpclient.py GBNSender 类）:

class GBNSender:
    def send_window(self):
        while self.has_more():
            next_len = len(self.data_chunks[self.next_seq][1])
            if self.bytes_in_flight() + next_len > self.window_size:
                break  # 窗口满

    def on_ack(self, ack_seq):
        """累积确认：所有 chunk_end <= ack_seq 的包都被确认"""
        for i in range(self.base, self.total_chunks):
            if chunk_end <= ack_seq:
                self.acked.add(i)
                rtt = time_ms() - self.send_times[i]
        while self.base in self.acked:
            self.base += 1  # 滑动窗口

    def check_timeout(self):
        """超时后重传整个窗口（回退 N）"""
        if time_ms() - self.timer_start > TIMEOUT_MS:
            self._retransmit_window()

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
        send_nak(expected)      # 乱序 → 丢弃 + NAK

2.4 打印输出格式

按要求格式打印每包信息:

发送数据: log(f"第{n}个（第{seq}~{end}字节）client=>server发送数据")
收到响应: log(f"第{n}个（第{ack}字节）server=>client收到响应")
超时重传: log(f"第{n}个（第{seq}~{end}字节）超时，重传")

实际输出示例:
  第1个（第756235079~756235136字节）client=>server发送数据
  第2个（第756235137~756235176字节）client=>server发送数据
  第1个（第756235137字节）server=>client收到响应
  第2个（第756235177字节）server=>client收到响应

2.5 统计信息收集

丢包率计算公式: 30 / 实际发送的UDP包总数 * 100%

stats = {
    "unique_packets": 30,       # 唯一数据包数
    "total_sent": 30,           # 实际发送次数（含重传）
    "loss_rate": 100.0,         # 30/30 * 100%（无重传）
    "max_rtt_ms": 9.97,         # 最大 RTT
    "min_rtt_ms": 0.56,         # 最小 RTT
    "avg_rtt_ms": 7.47,         # 平均 RTT
}

RTT 计算: 发送时记录 send_times[i] = time_ms()，收到 ACK 时 RTT = time_ms() - send_times[i]

2.6 服务端丢包模拟

class UDPServer:
    def _should_drop(self, msg_type):
        if msg_type != UDPType.DATA:
            return False  # 控制报文不丢，只丢 DATA 包
        return random.random() < self.drop_rate

3. 知识点总结

理解深刻的知识点

1. TCP 状态机的本质：通过在 UDP 应用层实现状态转换，理解了 TCP 连接管理是"在不可靠网络上的端到端状态同步"。

2. Go-Back-N 协议：理解了滑动窗口、累积确认、超时回退 N。窗口 400B，每包 40~80B，窗口可容纳 5~10 个包。

3. StudentID 验证机制：通过 XOR 运算实现简单但有效的身份验证，服务端必须验证合法性。

4. 序列号空间：使用字节偏移而非包序号，支持变长数据段（40~80 字节随机）。

5. 定时器管理：GBN 只为最老未确认包维护一个定时器，收到累积 ACK 后重置。

6. 丢包率与 RTT 统计：区分 unique_packets 和 total_sends；记录 send_time 和 ack_time 计算 RTT。

还有疑惑的知识点

1. 快重传（Fast Retransmit）：当前基于 NAK 触发重传，真正 TCP 快重传基于 3 个重复 ACK。

2. Selective Repeat (SR)：GBN 丢包时回退整个窗口效率低。SR 只重传丢失的包。

3. 拥塞控制 vs 流量控制：当前固定窗口 400B。TCP 真实的慢启动、拥塞避免还需深入学习。

4. 动态 RTT 超时计算：当前固定 300ms。更精确的做法是实时采集 RTT 样本计算超时（如 Jacobsen 算法）。

4. 运行说明

启动服务端
  python3 udpserver.py 9999           # 无丢包
  python3 udpserver.py 9999 0.15      # 15% 丢包率

启动客户端
  python3 udpclient.py 127.0.0.1 9999

预期输出:
  [客户端] === 连接建立（三次握手）===
  [客户端] → SYN（seq=756235078，StudentID=20503）
  第1个（第756235079~756235136字节）client=>server发送数据
  第2个（第756235137~756235176字节）client=>server发送数据
  ...
  第1个（第756235137字节）server=>client收到响应
  ...
  [客户端] === 连接断开（四次挥手）===
  [客户端] → FIN（seq=756236736）
  [客户端] ← FIN 的 ACK
  [客户端] ← 服务端 FIN
  [客户端] → 最终 ACK
  [客户端] 连接已关闭 ✓

  汇总：
    唯一数据包数：30
    实际发送次数：30
    丢包率：100.0%
    最大 RTT：9.97 ms
    最小 RTT：0.56 ms
    平均 RTT：7.47 ms

5. Git 仓库
  https://github.com/Kaka0124/jiwang