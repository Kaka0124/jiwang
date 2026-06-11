# UDP Socket Programming — Packet Capture Documentation

## 1. Wireshark 包捕获截图

### 抓包设置
- **Interface**: `lo0` (loopback)
- **Filter**: `udp.port == <port>` (例如 `udp.port == 9999`)
- **步骤**:
  1. 先启动 Wireshark，选择 lo0 接口开始抓包
  2. 启动 server: `python3 udpserver.py 9999 0.15`
  3. 启动 client: `python3 udpclient.py 127.0.0.1 9999`
  4. 停止抓包，应用过滤器分析

### 截图 1：三次握手（连接建立）
<!-- TODO: 插入 Wireshark 截图，显示 SYN → SYN-ACK → ACK -->
- **SYN** (client→server): UDP payload 首 2 字节为 `0x0001`，seq 字段为客户端 ISN
- **SYN-ACK** (server→client): 首 2 字节为 `0x0002`，seq 为服务端 ISN，ack 为 client_ISN+1
- **ACK** (client→server): 首 2 字节为 `0x0003`，ack 为 server_ISN+1

可在 Wireshark 中展开 UDP payload，对比 16 字节头部各字段。

### 截图 2：数据传输 — GBN 窗口发送
<!-- TODO: 插入 Wireshark 截图，显示连续多个 DATA 包 + ACK -->
- **DATA** 包: 首 2 字节为 `0x0004`，seq 为字节偏移，data_len 指示负载长度
- **ACK** 包: 首 2 字节为 `0x0003`，ack 为累积确认的下一期望字节
- 可观察到 client 连续发送 2-3 个 DATA 包（窗口 400B 内），server 返回累积 ACK

### 截图 3：超时重传 / NAK 重传
<!-- TODO: 插入 Wireshark 截图，显示丢包后的 NAK + 重传 -->
- **NAK** (server→client): 首 2 字节为 `0x0007`，ack 字段指示期望的 seq
- 重传的 DATA 包: seq 与之前丢失的包相同
- 可在 Wireshark 时间戳中计算重传间隔

### 截图 4：四次挥手（连接断开）
<!-- TODO: 插入 Wireshark 截图，显示 FIN → ACK → FIN → ACK -->
- **FIN** (client→server): 首 2 字节为 `0x0005`
- **ACK** (server→client): 首 2 字节为 `0x0003`，确认 FIN
- **FIN** (server→client): 首 2 字节为 `0x0005`，服务器主动关闭
- **Final ACK** (client→server): 首 2 字节为 `0x0003`，确认服务器 FIN

---

## 2. 实现关键点及代码说明

### 2.1 自定义应用层协议报文格式

**报文首部设计（16 字节）**:

| 偏移 | 大小 | 字段       | 说明                                  |
|------|------|------------|---------------------------------------|
| 0    | 2    | Type       | 报文类型（uint16 BE）                  |
| 2    | 4    | Seq Number | 序列号（字节偏移，uint32 BE）           |
| 6    | 4    | Ack Number | 确认号（下一期望字节，uint32 BE）       |
| 10   | 2    | Checksum   | 校验和（IP 风格 16-bit ones' complement）|
| 12   | 2    | Data Length| 数据负载长度（uint16 BE）              |
| 14   | 2    | Reserved   | 保留 / 窗口大小                       |

```python
# udp_protocol.py
HEADER_SIZE = 16
HEADER_FORMAT = "!HIIHHH"  # type + seq + ack + checksum + data_len + reserved

class UDPType(enum.IntEnum):
    SYN = 0x0001      # 连接请求
    SYN_ACK = 0x0002  # 连接确认
    ACK = 0x0003      # 确认
    DATA = 0x0004     # 数据
    FIN = 0x0005      # 连接关闭请求
    FIN_ACK = 0x0006  # 关闭确认
    NAK = 0x0007      # 否定确认（可选）
```

**设计理由**：
- 7 种报文类型完整覆盖 TCP 的连接管理 + 可靠传输语义
- Seq/Ack 字段使用 uint32（4 字节），类 TCP 的字节流序号空间
- Checksum 使用 IP 风格 16-bit ones' complement，可检测传输错误（非必须但加分）
- 16 字节固定头部，在 UDP 1472 字节有效负载中开销很小

**校验和实现**：
```python
# udp_protocol.py
def checksum(data: bytes) -> int:
    """IP-style 16-bit ones' complement checksum."""
    total = 0
    for i in range(0, len(data) - 1, 2):
        word = (data[i] << 8) + data[i + 1]
        total += word
    if len(data) % 2 == 1:
        total += data[-1] << 8
    while total >> 16:                       # Fold carry bits
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF                 # Ones' complement
```

### 2.2 应用层连接管理（三次握手 + 四次挥手）

**状态机设计**：

```
Client:  CLOSED → SYN_SENT → ESTABLISHED → FIN_SENT → CLOSED
Server:  CLOSED → SYN_RCVD → ESTABLISHED → FIN_RCVD → CLOSED
```

```python
# udp_protocol.py
class ConnState(enum.Enum):
    CLOSED = "CLOSED"
    SYN_SENT = "SYN_SENT"
    SYN_RCVD = "SYN_RCVD"
    ESTABLISHED = "ESTABLISHED"
    FIN_SENT = "FIN_SENT"
    FIN_RCVD = "FIN_RCVD"
```

**三次握手流程**（udpclient.py main 函数）：
```python
# Step 1: SYN
client_isn = random.randint(0, 2**31 - 1)
syn_pkt = pack_message(UDPType.SYN, client_isn, 0, b"")
sock.sendto(syn_pkt, server_addr)

# Step 2: Wait for SYN-ACK
data, _ = sock.recvfrom(65535)
msg = unpack_message(data)
server_isn = msg["seq"]     # 服务端 ISN
# server_ack should == client_isn + 1

# Step 3: Send ACK
ack_pkt = pack_message(UDPType.ACK, client_isn + 1, server_isn + 1, b"")
sock.sendto(ack_pkt, server_addr)
# → ESTABLISHED
```

**四次挥手流程**（udpserver.py `_handle_fin`）：
```python
# Step 1: Client sends FIN
# Step 2: Server sends ACK for FIN, then its own FIN
client["state"] = ConnState.FIN_RCVD
fin_ack = pack_message(UDPType.ACK, 0, msg["seq"] + 1, b"")
sock.sendto(fin_ack, addr)
fin_pkt = pack_message(UDPType.FIN, client["server_isn"] + 1, 0, b"")
sock.sendto(fin_pkt, addr)
# Step 3: Client sends ACK for server's FIN
# → CLOSED
```

**关键点**：
- ISN (Initial Sequence Number) 使用随机数，模拟 TCP 的安全性设计
- 序列号空间连续：SYN 消耗一个序号 → 数据从 ISN+1 开始 → FIN 消耗数据后的下一个序号
- 状态机确保只在 ESTABLISHED 状态处理数据，在 CLOSED 状态清理资源

### 2.3 Go-Back-N (GBN) 可靠传输

**核心参数**：
```python
WINDOW_SIZE = 400       # 固定发送窗口: 400 字节
TIMEOUT_MS = 300        # 超时重传: 300ms
MTU_PAYLOAD = 1400      # 每包最大负载
TOTAL_PACKETS = 30      # 共发送 30 个数据包
```

**GBN 发送方实现**（udpclient.py `GBNSender` 类）：

```python
class GBNSender:
    def __init__(self):
        self.base = 0            # 窗口左边界（最老未确认的包索引）
        self.next_seq = 0        # 下一个要发送的包索引
        self.window_size = 400   # 固定窗口大小
        self.send_times = {}     # 记录每个包的发送时间（用于 RTT）

    def send_window(self):
        """发送窗口内所有可发的包"""
        while self.has_more():
            next_len = len(self.data_chunks[self.next_seq][1])
            if self.bytes_in_flight() + next_len > self.window_size:
                break  # 窗口满，停止发送
            # ... 发送包，记录发送时间

    def on_ack(self, ack_seq: int):
        """累积确认处理"""
        # 所有 chunk_end <= ack_seq 的包都被确认
        for i in range(self.base, self.total_chunks):
            chunk_end = seq + len(payload)
            if chunk_end <= ack_seq:
                self.acked.add(i)
                # 计算 RTT
                rtt = time_ms() - self.send_times[i]
                self.rtt_samples.append(rtt)
        # 滑动窗口
        while self.base in self.acked:
            self.base += 1

    def check_timeout(self):
        """超时重传"""
        if time_ms() - self.timer_start > TIMEOUT_MS:
            self._retransmit_window()  # 重传 base 到 next_seq-1 的所有包

    def _retransmit_window(self):
        """GBN 回退 N 重传"""
        for i in range(self.base, self.next_seq):
            if i not in self.acked:
                # 重传此包
                sock.sendto(pkt, server_addr)
```

**GBN 接收方实现**（udpserver.py `_handle_data`）：

```python
def _handle_data(self, msg, addr):
    seq = msg["seq"]
    expected = client["expected_seq"]

    if seq == expected:
        # 按序到达 → 接收，滑动期望序号
        client["received_data"].extend(payload)
        client["expected_seq"] += data_len
        # 发送累积 ACK
        send_ack(expected_seq)

    elif seq < expected:
        # 重复包 → 重发 ACK（可能之前的 ACK 丢了）
        send_ack(expected)

    else:
        # 乱序包 → GBN 策略：直接丢弃
        # 发送 NAK，告知期望的序号
        send_nak(expected)
```

**关键设计决策**：
1. **累积确认**：ACK 的 ack_number 表示"所有小于此号的字节已收到"，减少 ACK 包数量
2. **固定窗口（400B）**：每个包约 172B，窗口可容纳 2 个包。`bytes_in_flight + next_payload <= window_size` 确保不超窗口
3. **NAK 辅助**：当收到乱序包时发送 NAK（携带 expected_seq），帮助发送方更快发现丢包，比纯超时更高效
4. **timer_start 管理**：每次收到 ACK 重置定时器；如果所有包都已确认则取消定时器

### 2.4 超时重传机制

```python
# 主循环
while not gbn.all_acked():
    gbn.send_window()        # 发送窗口内数据

    try:
        data, _ = sock.recvfrom(65535)  # 300ms socket timeout
        msg = unpack_message(data)
        if msg["type"] == UDPType.ACK:
            gbn.on_ack(msg["ack"])
        elif msg["type"] == UDPType.NAK:
            gbn.on_nak(msg["ack"])
    except socket.timeout:
        gbn.check_timeout()  # 检查 GBN 层超时

    gbn.check_timeout()      # 再次检查（以防 ACK 刚到就超时）
```

**关键点**：
- socket 级别超时设为 300ms，与 GBN 超时一致
- GBN 自身也维护一个定时器（基于 `timer_start`），双重保障
- 超时后重传整个窗口的所有未确认包（Go-Back-N 的核心行为）

### 2.5 统计信息收集

```python
# 统计项
stats = {
    "unique_packets": 30,       # 唯一数据包数
    "total_sent": 36,           # 实际发送次数（含重传）
    "loss_rate": 83.3,          # 30/36 * 100% = 83.3%
    "max_rtt_ms": 5.52,         # 最大 RTT
    "min_rtt_ms": 0.19,         # 最小 RTT
    "avg_rtt_ms": 3.01,         # 平均 RTT
}
```

**RTT 计算**：
- 每次发送包时记录 `send_times[i] = time_ms()`
- 收到 ACK 确认该包时计算 `rtt = time_ms() - send_times[i]`
- 对于重传的包，以最后一次发送时间为准

### 2.6 服务端丢包模拟

```python
# udpserver.py
class UDPServer:
    def __init__(self, port, drop_rate=0.0):
        self.drop_rate = drop_rate  # 丢包概率

    def _should_drop(self):
        return random.random() < self.drop_rate

    def run(self):
        data, addr = self.sock.recvfrom(65535)
        if self._should_drop():
            log(f"[DROP SIM] Dropped incoming packet (simulated)")
            continue  # 假装没收到
        self._handle_packet(data, addr)
```

---

## 3. 知识点总结

### 理解深刻的知识点

1. **TCP 状态机的本质**：通过在 UDP 应用层实现 CLOSED → SYN_SENT → SYN_RCVD → ESTABLISHED → FIN_SENT → FIN_RCVD → CLOSED 状态转换，深刻理解了 TCP 连接管理是"在不可靠网络上的端到端状态同步"。

2. **Go-Back-N 协议**：理解了滑动窗口、累积确认、超时回退 N 的核心机制。窗口大小直接影响吞吐量（window/RTT），以及 GBN 在丢包时效率低的原因（重传整个窗口）。

3. **序列号空间**：理解了 TCP 为什么使用字节偏移而非包序号——更灵活地支持变长数据段和重传时的分片重组。

4. **定时器管理**：理解了 GBN 只需为一个"最老未确认包"维护一个定时器的原因——收到累积 ACK 后重置，超时后重传整个窗口。

5. **丢包率与 RTT 的统计**：通过区分 unique_packets 和 total_sends 计算丢包率；通过记录每个包的 send_time 和 ack_time 计算 RTT 样本。

### 还有疑惑的知识点

1. **快重传（Fast Retransmit）**：当前实现了基于 NAK 的重传触发，但真正的 TCP 快重传是基于 3 个重复 ACK 触发，不需要等超时。加分项可以实现。

2. **Selective Repeat (SR)**：GBN 在丢包时回退整个窗口效率低。SR 协议只重传丢失的包，但需要更复杂的接收缓冲区管理。理解其与 GBN 的适用场景差异还需要更多实践。

3. **拥塞控制 vs 流量控制**：当前只实现了固定窗口的流量控制。TCP 真正的拥塞控制（慢启动、拥塞避免、快恢复）是基于对网络状况的探测，这部分理解还不够深入。

4. **checksum 的实际效果**：虽然实现了 IP 风格的 ones' complement checksum，但在 loopback 环境下不会出现比特错误。在真实网络中的效果需要更多实验验证。

5. **时钟粒度问题**：Python `time.time()` 的精度在不同操作系统上表现不同，可能影响 RTT 测量的准确性。

---

## 4. 运行说明

### 启动服务端
```bash
python3 udpserver.py <port> [drop_rate]
# 示例: 15% 丢包率
python3 udpserver.py 9999 0.15
# 无丢包
python3 udpserver.py 9999
```

### 启动客户端
```bash
python3 udpclient.py <server_ip> <server_port>
# 示例
python3 udpclient.py 127.0.0.1 9999
```

### 预期输出示例
```
[Client] === Connection Establishment (3-Way Handshake) ===
[Client] → SYN (seq=2112275825)
[Client] ← SYN-ACK (server_seq=456875862, ack=2112275826)
[Client] → ACK (seq=2112275826, ack=456875863)
[Client] Connection ESTABLISHED ✓

[Client] === Data Transfer (Go-Back-N) ===
[Client] Sent packet 1/30: bytes 2112275826-2112275997, seq=2112275826, len=172
[Client] Sent packet 2/30: bytes 2112275998-2112276169, seq=2112275998, len=172
[Client] ACK received: ack_seq=2112275998, 1 newly acked, base=1, next=2
...
[Client] NAK received: server expects seq=2112277890
[Client] Retransmitted 3 packets

[Client] === Connection Teardown (4-Way) ===
[Client] → FIN (seq=2112280986)
[Client] ← ACK for FIN
[Client] ← FIN from server
[Client] → Final ACK
[Client] Connection CLOSED ✓

==================================================
SUMMARY:
  Total unique packets:  30
  Total sends:           36 (including retransmissions)
  Packet loss rate:      83.3%
  Max RTT:               5.52 ms
  Min RTT:               0.19 ms
  Avg RTT:               3.01 ms
==================================================
```

---

## 5. Git 仓库
<!-- TODO: 填写 Git 仓库 URL -->
