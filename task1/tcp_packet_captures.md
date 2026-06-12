TCP Socket Programming — Packet Capture Documentation

1. Wireshark 包捕获截图

抓包设置
- Interface: lo0 (loopback)
- Filter: tcp.port == 8888
- 步骤:
  1. 先启动 Wireshark，选择 lo0 接口开始抓包
  2. 启动 server: python3 reversetcpserver.py 8888
  3. 启动 client: python3 reversetcpclient.py 127.0.0.1 8888 50 100 test_input.txt 42
  4. 停止抓包，应用过滤器分析

截图 1：Initialization / agree 报文（连接建立）
- Initialization: client → server，payload 首字节 0x01，后跟 4 字节 N（块数）
- agree: server → client，payload 首字节 0x02，负载为空

截图 2：reverseRequest / reverseAnswer 报文（数据传输）
- reverseRequest: payload 首字节 0x03，后跟 3 字节保留 + 4 字节长度 + 文本数据
- reverseAnswer: payload 首字节 0x04，后跟反转后的数据

截图 3：多客户端并发
- 同时运行 2-3 个 client，在 Wireshark 中可以看到多个 TCP stream

2. 实现关键点及代码说明

2.1 自定义应用层协议报文格式

报文首部设计（8 字节）:

| 偏移 | 大小 | 字段        | 说明                        |
|------|------|-------------|-----------------------------|
| 0    | 1    | Type        | 报文类型（1-4）              |
| 1    | 3    | Reserved    | 保留字段，为 0               |
| 4    | 4    | Payload Len | 负载长度（大端序 uint32）     |

四种报文类型（按任务书要求）:
  Type=1 (0x01): Initialization — 客户端→服务端，携带 4 字节的 N（块数）
  Type=2 (0x02): agree — 服务端→客户端，确认连接建立
  Type=3 (0x03): reverseRequest — 客户端→服务端，携带待反转的 Data
  Type=4 (0x04): reverseAnswer — 服务端→客户端，携带反转后的 reverseData

代码位置: tcp_protocol.py

HEADER_SIZE = 8
HEADER_FORMAT = "!B3xI"  # type(1B) + reserved(3B) + length(4B)

class MessageType(enum.IntEnum):
    INITIALIZATION = 0x01   # 客户端→服务端：告知要反转的块数 N
    AGREE = 0x02            # 服务端→客户端：同意连接
    REVERSE_REQUEST = 0x03  # 客户端→服务端：携带待反转数据
    REVERSE_ANSWER = 0x04   # 服务端→客户端：携带反转后数据

设计理由：
- Type 字段放在第一个字节，方便 Wireshark 识别报文类型
- Payload Length 使用 4 字节大端序，支持最大 4GB 负载
- 8 字节固定头部，解析简单高效

2.2 TCP 流式数据的精确读取

TCP 是流式协议，单次 recv() 不一定返回完整报文。使用 recv_exact() 循环读取：

def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("对端关闭了连接")
        data += chunk
    return data

def recv_message(sock):
    header = recv_exact(sock, HEADER_SIZE)         # 先读 8 字节头部
    msg_type, payload_length = unpack_header(header)
    payload = recv_exact(sock, payload_length)     # 再读负载
    return msg_type, payload

关键点：先读 8 字节头部获取长度，再根据长度读 payload，保证报文边界正确。

2.3 分块算法

按任务书要求：先生成各块的随机长度，直到覆盖整个文件，再计算块数 N。

def generate_chunks(text, lmin, lmax, seed=None):
    if seed is not None:
        random.seed(seed)
    chunks = []
    pos = 0
    text_len = len(text)
    while pos < text_len:
        chunk_len = random.randint(lmin, lmax)
        chunk_len = min(chunk_len, text_len - pos)  # 最后一块不超出文件
        chunks.append(text[pos:pos + chunk_len])
        pos += chunk_len
    return chunks, len(chunks)

验收示例（seed=42, Lmin=50, Lmax=100, 文件504字节）:
  N=8, 各块长度: [90, 57, 51, 97, 67, 65, 64, 13]
  第1块起始=0, 第2块起始=90, 第3块起始=147(=90+57) ...

2.4 服务端多线程并发处理

每个客户端连接创建一个独立线程：
  thread = threading.Thread(target=handle_client, args=(conn, addr, cid), daemon=True)
  thread.start()

关键点：
- daemon=True 确保主线程退出时子线程自动结束
- log_lock = threading.Lock() 保证多线程日志写入安全

2.5 客户端验证机制

def verify_reversal(original, received):
    expected = original.encode("ascii")[::-1].decode("ascii")
    return received == expected

收到 reverseAnswer 后打印 "第x块：反转的文本"（验收要求）

3. 知识点总结

理解深刻的知识点

1. TCP 流式传输特性：TCP 是字节流，不保留消息边界。必须在应用层设计报文格式（头部 + 负载）并通过精确读取来划分消息边界。这是本次实验最核心的理解。

2. 自定义应用层协议设计：通过固定头部中的 Type 字段标识 4 种报文类型，Payload Length 字段指定负载长度，实现了简单的应用层协议。

3. 多线程并发服务器模型：每个客户端一个线程（one-thread-per-client），适合中等并发量。理解了线程安全（Lock）的必要性。

4. Wireshark 抓包分析：熟练使用 Wireshark 在 loopback 接口抓包，通过过滤器定位特定 TCP 流，分析自定义协议的报文结构。

还有疑惑的知识点

1. 高并发场景的优化：当前 one-thread-per-client 模型在 C10K 场景下性能较差。如何过渡到 select/epoll/asyncio 模型还需要进一步学习。

2. TCP 粘包/拆包的底层机制：虽然通过 recv_exact() 解决了粘包问题，但对 TCP 的 Nagle 算法、MSS 对分片的影响理解还不够深入。

3. 报文边界设计的通用模式：除了"头部定长 + 长度字段"模式，还有"分隔符"模式和"固定长度"模式，各模式的适用场景和性能对比需要更多实践。

4. 运行说明

启动服务端
  python3 reversetcpserver.py 8888

启动客户端
  python3 reversetcpclient.py 127.0.0.1 8888 50 100 test_input.txt 42

多客户端并发测试
  python3 reversetcpclient.py 127.0.0.1 8888 5 20 test_input.txt &
  python3 reversetcpclient.py 127.0.0.1 8888 8 30 test_input.txt &
  python3 reversetcpclient.py 127.0.0.1 8888 10 50 test_input.txt &
  wait

5. Git 仓库
  https://github.com/Kaka0124/jiwang