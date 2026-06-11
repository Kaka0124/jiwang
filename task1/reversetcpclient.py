#!/usr/bin/env python3
"""
TCP 反转客户端 —— Task1
========================
TCP 客户端，读取 ASCII 文本文件，按随机长度分块发送给服务端反转，
收到反转结果后逐块验证正确性，最后保存反转后的完整文件。

用法：
    python3 reversetcpclient.py <服务器IP> <端口> <Lmin> <Lmax> <输入文件> [块数]

示例：
    python3 reversetcpclient.py 127.0.0.1 8888 10 50 test_input.txt        # 随机块数
    python3 reversetcpclient.py 127.0.0.1 8888 10 50 test_input.txt 8      # 指定8块
"""

import socket
import sys
import random
import time
import os

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


def split_into_chunks(text: str, lmin: int, lmax: int, num_chunks: int) -> list:
    """
    分块算法：将文本切分为 num_chunks 块，每块长度在 [lmin, lmax] 范围内随机。
    如果分完 num_chunks 块后还有剩余文本，追加为最后一块。

    参数：
        text:       原始文本
        lmin:       最小块长度
        lmax:       最大块长度
        num_chunks: 期望的分块数

    返回：
        字符串列表，每个元素为一个块
    """
    chunks = []
    pos = 0
    text_len = len(text)

    for i in range(num_chunks):
        if pos >= text_len:
            break
        # 随机生成本块长度
        chunk_len = random.randint(lmin, lmax)
        # 不能超出剩余文本
        chunk_len = min(chunk_len, text_len - pos)
        chunks.append(text[pos:pos + chunk_len])
        pos += chunk_len

    # 剩余文本追加为最后一块
    if pos < text_len:
        chunks.append(text[pos:])

    return chunks


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
        print(f"用法：python3 {sys.argv[0]} <服务器IP> <端口> <Lmin> <Lmax> <输入文件> [块数]")
        print(f"示例：python3 {sys.argv[0]} 127.0.0.1 8888 10 50 test_input.txt")
        print(f"      python3 {sys.argv[0]} 127.0.0.1 8888 10 50 test_input.txt 8  （指定8块）")
        print(f"  块数：可选参数，不指定则随机(3~20)")
        sys.exit(1)

    # 解析命令行参数
    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    lmin = int(sys.argv[3])
    lmax = int(sys.argv[4])
    input_file = sys.argv[5]
    specified_chunks = int(sys.argv[6]) if len(sys.argv) == 7 else None

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

    # 确定分块数：优先使用命令行指定值，否则随机生成
    if specified_chunks is not None:
        num_chunks = specified_chunks
        log(f"使用指定分块数：{num_chunks}")
    else:
        max_chunks = max(3, total_bytes // lmin) if total_bytes >= lmin else 1
        num_chunks = random.randint(3, min(max_chunks, 20))
        log(f"随机分块数：{num_chunks}，Lmin={lmin}，Lmax={lmax}")

    # 执行分块
    chunks = split_into_chunks(text, lmin, lmax, num_chunks)
    actual_chunks = len(chunks)
    log(f"已切分为 {actual_chunks} 块")

    # 连接服务端
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((server_ip, server_port))
        log(f"已连接到 {server_ip}:{server_port}")
    except (ConnectionRefusedError, OSError) as e:
        log(f"错误：无法连接 {server_ip}:{server_port} —— {e}")
        sys.exit(1)

    try:
        # ---- 阶段1：Initial 握手 ----
        start_time = time.time()
        sock.sendall(pack_message(MessageType.INITIAL, b""))
        log("发送 Initial")

        msg_type, _ = recv_message(sock)
        if msg_type != MessageType.INITIAL:
            log(f"错误：期望 Initial ACK，收到 {TYPE_NAMES.get(msg_type, msg_type)}")
            sys.exit(1)
        log("收到 Initial ACK —— 连接已建立")

        # ---- 阶段2：逐块发送并验证反转结果 ----
        output_chunks = []
        verification_errors = 0

        for i, chunk in enumerate(chunks, start=1):
            payload = chunk.encode("ascii")

            # 发送 ReverseRequest
            sock.sendall(pack_message(MessageType.REVERSE_REQUEST, payload))
            log(f"发送 ReverseRequest #{i}/{actual_chunks}：{len(payload)} 字节")

            # 接收 ReverseAnswer
            msg_type, reversed_payload = recv_message(sock)
            if msg_type != MessageType.REVERSE_ANSWER:
                log(f"错误：期望 ReverseAnswer，收到 {TYPE_NAMES.get(msg_type, msg_type)}")
                verification_errors += 1
                continue

            received_text = reversed_payload.decode("ascii")
            log(f"收到 ReverseAnswer #{i}：{len(reversed_payload)} 字节")

            # 打印反转后的文本（验收要求）
            log(f"第{i}块：{received_text}")

            # 验证反转正确性：原文反转后应等于收到的结果
            if verify_reversal(chunk, received_text):
                log(f"  ✓ 验证 #{i} 通过")
            else:
                log(f"  ✗ 验证 #{i} 失败：原文与反转不匹配！")
                log(f"    原文：     {chunk[:50]}{'...' if len(chunk) > 50 else ''}")
                log(f"    期望：     {chunk.encode('ascii')[::-1].decode('ascii')[:50]}...")
                log(f"    收到：     {received_text[:50]}...")
                verification_errors += 1

            output_chunks.append(received_text)

        # ---- 阶段3：关闭连接（按协议规定，Close 由服务端发起）----
        # 关闭写端，通知服务端数据发送完毕
        sock.shutdown(socket.SHUT_WR)
        log("数据发送完毕 —— 等待服务端发送 Close")

        msg_type, _ = recv_message(sock)
        if msg_type == MessageType.CLOSE:
            log("收到服务端 Close —— 连接正常关闭")

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
        log(f"  分块：{actual_chunks} 块（Lmin={lmin}，Lmax={lmax}）")
        log(f"  验证错误：{verification_errors}/{actual_chunks}")
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
