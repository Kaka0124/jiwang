# TCP Socket Programming — Packet Capture Documentation

## 1. Wireshark 包捕获截图

### 抓包设置
- **Interface**: `lo0` (loopback)
- **Filter**: `tcp.port == <port>` (例如 `tcp.port == 8888`)
- **步骤**:
  1. 先启动 Wireshark，选择 lo0 接口开始抓包
  2. 启动 server: `python3 reversetcpserver.py 8888`
  3. 启动 client: `python3 reversetcpclient.py 127.0.0.1 8888 10 50 test_input.txt`
  4. 停止抓包，应用过滤器分析

### 截图 1：Initial 报文（连接建立）
<!-- TODO: 插入 Wireshark 截图，显示 Initial 和 Initial ACK -->
- 第一个 TCP 包：client → server，payload 以 `0x01` 开头（Initial 类型）
- 第二个 TCP 包：server → client，payload 以 `0x01` 开头（Initial ACK）

### 截图 2：ReverseRequest / ReverseAnswer 报文（数据传输）
<!-- TODO: 插入 Wireshark 截图，显示一对 Request/Answer -->
- ReverseRequest: payload 首字节 `0x02`，后跟 3 字节保留 + 4 字节长度 + 文本数据
- ReverseAnswer: payload 首字节 `0x03`，后跟反转后的数据
- 可以清晰看到 Answer 的 payload 是 Request payload 的反转

### 截图 3：Close 报文（连接关闭）
<!-- TODO: 插入 Wireshark 截图，显示 Close 和 Close ACK -->
- Close: payload 首字节 `0x04`
- Close ACK: payload 首字节 `0x04`

### 截图 4：多客户端并发（可选）
<!-- TODO: 插入 Wireshark 截图，显示多个 TCP 连接同时存在 -->
- 同时运行 2-3 个 client，在 Wireshark 中可以看到多个 TCP stream

---

## 2. 实现关键点及代码说明

### 2.1 自定义应用层协议报文格式

**报文首部设计（8 字节）**:

| 偏移 | 大小 | 字段        | 说明                        |
|------|------|-------------|-----------------------------|
| 0    | 1    | Type        | 报文类型（1-4）              |
| 1    | 3    | Reserved    | 保留字段，为 0               |
| 4    | 4    | Payload Len | 负载长度（大端序 uint32）     |

```python
# tcp_protocol.py
HEADER_SIZE = 8
HEADER_FORMAT = "!B3xI"  # type(1B) + reserved(3B) + length(4B)

class MessageType(enum.IntEnum):
    INITIAL = 0x01
    REVERSE_REQUEST = 0x02
    REVERSE_ANSWER = 0x03
    CLOSE = 0x04
```

**设计理由**：
- Type 字段放在第一个字节，方便 Wireshark 识别报文类型
- Payload Length 使用 4 字节大端序，支持最大 4GB 负载
- 8 字节固定头部，解析简单高效

### 2.2 TCP 流式数据的精确读取

TCP 是流式协议，单次 `recv()` 不一定返回完整报文。使用 `recv_exact()` 循环读取：

```python
# tcp_protocol.py
def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes from a TCP socket."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed by peer")
        data += chunk
    return data

def recv_message(sock: socket.socket) -> tuple:
    """Receive one complete message."""
    header = recv_exact(sock, HEADER_SIZE)
    msg_type, payload_length = unpack_header(header)
    payload = recv_exact(sock, payload_length) if payload_length > 0 else b""
    return msg_type, payload
```

**关键点**：先读 8 字节头部获取长度，再根据长度读 payload，保证报文边界正确。

### 2.3 服务端多线程并发处理

```python
# reversetcpserver.py
def main():
    server_sock.listen(MAX_CLIENTS)
    while True:
        conn, addr = server_sock.accept()
        client_counter += 1
        thread = threading.Thread(
            target=handle_client,
            args=(conn, addr, client_counter),
            daemon=True,
        )
        thread.start()
```

**关键点**：
- 每个客户端连接创建一个独立线程处理
- `daemon=True` 确保主线程退出时子线程自动结束
- 使用 `log_lock = threading.Lock()` 保证日志写入线程安全

### 2.4 客户端验证机制

```python
# reversetcpclient.py
def verify_reversal(original: str, received: str) -> bool:
    """Verify byte-level reversal correctness."""
    expected = original.encode("ascii")[::-1].decode("ascii")
    return received == expected
```

**关键点**：使用 Python 切片 `[::-1]` 进行字节级反转，确保与服务器行为一致。

### 2.5 随机分块策略

```python
# reversetcpclient.py
num_chunks = random.randint(3, min(max_chunks, 20))  # 随机块数 3-20

def split_into_chunks(text, lmin, lmax, num_chunks):
    for i in range(num_chunks):
        chunk_len = random.randint(lmin, lmax)  # 随机长度
        chunk_len = min(chunk_len, text_len - pos)  # 不超出文本
        chunks.append(text[pos:pos + chunk_len])
        pos += chunk_len
    if pos < text_len:
        chunks.append(text[pos:])  # 剩余部分作为最后一块
    return chunks
```

---

## 3. 知识点总结

### 理解深刻的知识点

1. **TCP 流式传输特性**：TCP 是字节流，不保留消息边界。必须在应用层设计报文格式（头部 + 负载）并通过精确读取来划分消息边界。这是本次实验最核心的理解。

2. **自定义应用层协议设计**：通过固定头部中的 Type 字段标识 4 种报文类型，Payload Length 字段指定负载长度，实现了简单的应用层协议。理解了 HTTP、SMTP 等协议的基本设计思路。

3. **多线程并发服务器模型**：每个客户端一个线程（one-thread-per-client），适合中等并发量。理解了线程安全（Lock）的必要性。

4. **Wireshark 抓包分析**：熟练使用 Wireshark 在 loopback 接口抓包，通过过滤器定位特定 TCP 流，分析自定义协议的报文结构。

### 还有疑惑的知识点

1. **高并发场景的优化**：当前 one-thread-per-client 模型在 C10K 场景下性能较差。如何过渡到 `select`/`epoll`/`asyncio` 模型还需要进一步学习。

2. **TCP 粘包/拆包的底层机制**：虽然通过 `recv_exact()` 解决了粘包问题，但对 TCP 的 Nagle 算法、MSS 对分片的影响理解还不够深入。

3. **报文边界设计的通用模式**：除了"头部定长 + 长度字段"模式，还有"分隔符"模式（如 HTTP `\r\n\r\n`）和"固定长度"模式，各模式的适用场景和性能对比需要更多实践。

---

## 4. 运行说明

### 启动服务端
```bash
python3 reversetcpserver.py <port>
# 示例
python3 reversetcpserver.py 8888
```

### 启动客户端
```bash
python3 reversetcpclient.py <server_ip> <server_port> <Lmin> <Lmax> <input_file>
# 示例
python3 reversetcpclient.py 127.0.0.1 8888 10 50 test_input.txt
```

### 多客户端并发测试
```bash
# 同时运行 3 个客户端
python3 reversetcpclient.py 127.0.0.1 8888 5 20 test_input.txt &
python3 reversetcpclient.py 127.0.0.1 8888 8 30 test_input.txt &
python3 reversetcpclient.py 127.0.0.1 8888 10 50 test_input.txt &
wait
```

---

## 5. Git 仓库
<!-- TODO: 填写 Git 仓库 URL -->
