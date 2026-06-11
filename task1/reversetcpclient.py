#!/usr/bin/env python3
"""
TCP 反转客户端 —— Task1
========================
TCP 客户端，读取 ASCII 文本文件，逐段随机长度分块发送给服务端反转，
收到反转结果后逐块验证正确性，最后保存反转后的完整文件。

分块算法（按任务书要求）：
  先生成各块的随机长度 [Lmin, Lmax]，直到覆盖整个文件，再计算块数 N。
  最后一块可能不足 Lmin（文件剩余部分）。

用法：
    python3 reversetcpclient.py <服务器IP> <端口> <Lmin> <Lmax> <输入文件> [seed]

示例：
    python3 reversetcpclient.py 127.0.0.1 8888 10 50 test_input.txt           # 随机
    python3 reversetcpclient.py 127.0.0.1 8888 50 100 test.txt 42             # 指定种子
"""

import socket
import struct
import sys
import random
import time

from tcp_protocol import (
    MessageType, TYPE_NAMES,
    pack_message, recv_message, timestamp,
)

LOG_FILE = "run_log.txt"


def log(msg: str):
    """输出日志到终端和 run_log.txt"""
    ts = timestamp()
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def read_file(filepath: str) -> str:
    """读取整个 ASCII 文本文件"""
    with open(filepath, "r", encoding="ascii") as f:
        return f.read()


def generate_chunks(text: str, lmin: int, lmax: int, seed: int = None) -> list:
    """
    【核心分块算法】按任务书要求实现：

    1. 先设定随机种子（如有）
    2. 不断生成 [Lmin, Lmax] 范围内的随机长度
    3. 逐段从文件中切出，直到文件读完
    4. 最后一块可能不足 Lmin（剩余部分直接作为一块）
    5. 块数 N = 生成的块数

    验收时老师会给定 seed，你需要能口算/手推出 N 及各块长度。

    参数：
        text:  原始文本
        lmin:  最小块长度
        lmax:  最大块长度
        seed:  随机种子（验收时指定，None 表示不设种子）

    返回：
        (字符串列表, N, 各块长度列表)
    """
    if seed is not None:
        random.seed(seed)

    chunks = []
    lengths = []
    pos = 0
    text_len = len(text)

    while pos < text_len:
        # 在 [lmin, lmax] 范围内随机生成本块长度
        chunk_len = random.randint(lmin, lmax)
        # 最后一块不能超出文件末尾
        chunk_len = min(chunk_len, text_len - pos)
        chunks.append(text[pos:pos + chunk_len])
        lengths.append(chunk_len)
        pos += chunk_len

    return chunks, len(chunks), lengths


def verify_reversal(original: str, received: str) -> bool:
    """
    验证反转正确性：将原文按字节反转，对比收到的结果。
    例如原文 "abc" → 期望 "cba"
    """
    expected = original.encode("ascii")[::-1].decode("ascii")
    return received == expected


def main():
    """主函数"""
    if len(sys.argv) < 6 or len(sys.argv) > 7:
        print(f"用法：python3 {sys.argv[0]} <服务器IP> <端口> <Lmin> <Lmax> <输入文件> [seed]")
        print(f"示例：python3 {sys.argv[0]} 127.0.0.1 8888 10 50 test_input.txt")
        print(f"      python3 {sys.argv[0]} 127.0.0.1 8888 50 100 test.txt 42")
        print(f"  seed：可选，随机种子。不指定则每次结果不同")
        sys.exit(1)

    # 解析命令行参数
    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    lmin = int(sys.argv[3])
    lmax = int(sys.argv[4])
    input_file = sys.argv[5]
    seed = int(sys.argv[6]) if len(sys.argv) == 7 else None

    if lmin < 1 or lmax < lmin:
        log("错误：Lmin/Lmax 无效。需要 1 <= Lmin <= Lmax")
        sys.exit(1)

    # 读取输入文件
    try:
        text = read_file(input_file)
    except FileNotFoundError:
        log(f"错误：找不到输入文件 '{input_file}'")
        sys.exit(1)
    except UnicodeDecodeError:
        log(f"错误：输入文件 '{input_file}' 不是有效的 ASCII 文件")
        sys.exit(1)

    total_bytes = len(text)
    log(f"读取输入文件 '{input_file}'：{total_bytes} 字节")

    # ---- 分块：先生成长度，再算 N ----
    if seed is not None:
        log(f"使用指定随机种子 seed={seed}")
    chunks, N, lengths = generate_chunks(text, lmin, lmax, seed)
    log(f"分块完成：N={N}，Lmin={lmin}，Lmax={lmax}")
    for i, (chunk, length) in enumerate(zip(chunks, lengths), start=1):
        log(f"  第{i}块长度：{length} 字节（起始={sum(lengths[:i-1])}）")

    # 连接服务端
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((server_ip, server_port))
        log(f"已连接到 {server_ip}:{server_port}")
    except (ConnectionRefusedError, OSError) as e:
        log(f"错误：无法连接 {server_ip}:{server_port} —— {e}")
        sys.exit(1)

    try:
        # ---- 阶段1：发送 Initialization（payload 携带 4 字节的 N）----
        start_time = time.time()
        n_bytes = struct.pack("!I", N)
        sock.sendall(pack_message(MessageType.INITIALIZATION, n_bytes))
        log(f"发送 Initialization（N={N}）")

        # 接收 agree
        msg_type, _ = recv_message(sock)
        if msg_type != MessageType.AGREE:
            log(f"错误：期望 agree，收到 {TYPE_NAMES.get(msg_type, msg_type)}")
            sys.exit(1)
        log("收到 agree —— 连接建立，开始传输")

        # ---- 阶段2：逐块发送 reverseRequest / 接收 reverseAnswer ----
        output_chunks = []
        verification_errors = 0

        for i, chunk in enumerate(chunks, start=1):
            payload = chunk.encode("ascii")

            # 发送 reverseRequest
            sock.sendall(pack_message(MessageType.REVERSE_REQUEST, payload))
            log(f"发送 reverseRequest #{i}/{N}：{len(payload)} 字节")

            # 接收 reverseAnswer
            msg_type, reversed_payload = recv_message(sock)
            if msg_type != MessageType.REVERSE_ANSWER:
                log(f"错误：期望 reverseAnswer，收到 {TYPE_NAMES.get(msg_type, msg_type)}")
                verification_errors += 1
                continue

            received_text = reversed_payload.decode("ascii")
            log(f"收到 reverseAnswer #{i}：{len(reversed_payload)} 字节")

            # 打印反转后的文本（验收要求）
            print(f"{i}：{received_text}")

            # 验证反转正确性
            if verify_reversal(chunk, received_text):
                log(f"  ✓ 验证 #{i} 通过")
            else:
                log(f"  ✗ 验证 #{i} 失败：原文与反转不匹配！")
                log(f"    原文：     {chunk[:50]}{'...' if len(chunk) > 50 else ''}")
                log(f"    期望：     {chunk.encode('ascii')[::-1].decode('ascii')[:50]}...")
                log(f"    收到：     {received_text[:50]}...")
                verification_errors += 1

            output_chunks.append(received_text)

        # ---- 阶段3：数据传输完成，关闭连接 ----
        sock.shutdown(socket.SHUT_WR)
        log("所有数据块发送完毕——连接关闭")
        elapsed = time.time() - start_time

        # ---- 写出反转结果文件 ----
        output_file = f"reversed_output_{int(time.time())}.txt"
        with open(output_file, "w", encoding="ascii") as f:
            f.write("".join(output_chunks))
        log(f"结果已写入 '{output_file}'")

        # ---- 汇总信息 ----
        log(f"{'=' * 50}")
        log(f"汇总：")
        log(f"  文件：{input_file}（{total_bytes} 字节）")
        log(f"  分块：N={N}（Lmin={lmin}，Lmax={lmax}）")
        log(f"  各块长度：{lengths}")
        log(f"  验证错误：{verification_errors}/{N}")
        log(f"  耗时：{elapsed:.3f}s")
        if verification_errors == 0:
            log(f"  状态：✓ 全部验证通过")
        else:
            log(f"  状态：✗ 存在 {verification_errors} 个验证错误")

    except (ConnectionError, OSError) as e:
        log(f"错误：连接异常：{e}")
        sys.exit(1)
    finally:
        sock.close()


if __name__ == "__main__":
    main()
