# decrypt_stream.py


import os
import sys
import struct
import argparse
import hashlib
import hmac
from Crypto.Cipher import AES

# 常量定义（均以字节为单位）
MAGIC = b"AESMACGH"      # 8 bytes：固定标志，用于识别容器格式
VERSION = b"\x01"         # 1 byte ：版本号 = 0x01
SALT_LEN = 16            # 16 bytes：PBKDF2 用到的随机 salt 长度
IV_LEN = 16              # 16 bytes：AES-CBC 用到的初始化向量长度
ITER_BYTES = 4           # 4 bytes：迭代次数占用 4 字节（big-endian）
HMAC_LEN = 32            # 32 bytes：HMAC-SHA256 输出长度
CHUNK_SIZE = 64 * 1024   # 64 KB：流式读写时的块大小，用于解密分块

def derive_keys(passphrase: bytes, salt: bytes, iterations: int):
    """
    从 passphrase 和 salt 派生出 64 字节密钥：
    前 32 字节用于 AES-256-CBC 解密；后 32 字节用于 HMAC-SHA256 校验。
    """
    dk = hashlib.pbkdf2_hmac('sha256', passphrase, salt, iterations, dklen=64)
    return dk[:32], dk[32:]

def pkcs7_unpad(data: bytes):
    """
    去除 PKCS#7 填充。最后一个字节 n 表示要去掉的填充长度，共删去 n 个值为 n 的字节。
    """
    if not data or len(data) % 16 != 0:
        raise ValueError("Ciphertext is not a multiple of block size")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding length")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding")
    return data[:-pad_len]

def decrypt_stream(input_path: str, output_path: str, passphrase: bytes):
    total_size = os.path.getsize(input_path)
    # 1. 文件至少要 ≥ 8+1+16+16+4+32 = 77 字节
    if total_size < len(MAGIC) + 1 + SALT_LEN + IV_LEN + ITER_BYTES + HMAC_LEN:
        print("File too small or not valid format.")
        sys.exit(1)

    with open(input_path, 'rb') as f:
        # 2. 读取并校验 MAGIC (8 bytes)
        magic = f.read(len(MAGIC))
        if magic != MAGIC:
            print("Magic mismatch. Not a MYAESENC file.")
            sys.exit(1)

        # 3. 读取并校验 Version (1 byte)
        version = f.read(1)
        if version != VERSION:
            print("Unsupported version:", version)
            sys.exit(1)

        # 4. 读取 Salt (16 bytes)
        salt = f.read(SALT_LEN)
        # 5. 读取 IV (16 bytes)
        iv = f.read(IV_LEN)
        # 6. 读取 Iterations (4 bytes, big-endian)
        iterations = struct.unpack(">I", f.read(ITER_BYTES))[0]

        # 7. 计算 ciphertext_len = total_size - header_len(45) - HMAC_LEN(32)
        header_len = len(MAGIC) + 1 + SALT_LEN + IV_LEN + ITER_BYTES
        ciphertext_len = total_size - header_len - HMAC_LEN
        if ciphertext_len <= 0 or ciphertext_len % 16 != 0:
            print("Invalid ciphertext length.")
            sys.exit(1)

        # 8. 派生 AES key 与 HMAC key
        aes_key, hmac_key = derive_keys(passphrase, salt, iterations)

        # 9. 验证 HMAC
        hmac_obj = hmac.new(hmac_key, digestmod=hashlib.sha256)
        # HMAC 先 update VERSION‖salt‖iv‖iterations
        hmac_obj.update(version + salt + iv + struct.pack(">I", iterations))

        # 流式读取 ciphertext 长度，逐块 HMAC_update
        bytes_to_read = ciphertext_len
        while bytes_to_read > 0:
            chunk = f.read(min(CHUNK_SIZE, bytes_to_read))
            hmac_obj.update(chunk)
            bytes_to_read -= len(chunk)

        # 10. 读取并对比尾部 HMAC Tag (32 bytes)
        tag_read = f.read(HMAC_LEN)
        tag_calc = hmac_obj.digest()
        if not hmac.compare_digest(tag_calc, tag_read):
            print("HMAC mismatch. Integrity check failed.")
            sys.exit(1)

    # 11. HMAC 校验通过后，真正解密
    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        f_in.seek(header_len)  # 定位到 ciphertext 开始

        cipher = AES.new(aes_key, AES.MODE_CBC, iv)

        remaining = ciphertext_len
        prev_plain = b""
        first_pass = True

        while remaining > 0:
            chunk = f_in.read(min(CHUNK_SIZE, remaining))
            remaining -= len(chunk)
            plain_chunk = cipher.decrypt(chunk)

            if first_pass:
                # 首次解密结果暂存
                prev_plain = plain_chunk
                first_pass = False
            else:
                # 将上一块（非最后一块）写出
                f_out.write(prev_plain)
                prev_plain = plain_chunk

        # 12. 处理最后一块 prev_plain，去 PKCS#7 填充
        try:
            unpadded = pkcs7_unpad(prev_plain)
        except ValueError as e:
            print("Padding error:", e)
            sys.exit(1)

        # 写去填充后的明文
        f_out.write(unpadded)

    print(f"Decryption complete ==> {output_path}")

def main():
    parser = argparse.ArgumentParser(
        description="streamed I/O AES-256-CBC + PBKDF2 + HMAC-SHA256 decrypt"
    )
    parser.add_argument('--decrypt',
                        metavar='ENCRYPTED_FILE',
                        required=True,
                        help='要解密的加密容器文件路径')
    parser.add_argument('--output',
                        metavar='PLAINTEXT_FILE',
                        required=True,
                        help='解密后明文输出路径')
    parser.add_argument('--passphrase',
                        metavar='PASSPHRASE',
                        required=True,
                        help='用于派生密钥的口令 (UTF-8 字符串)')

    args = parser.parse_args()

    if not args.decrypt:
        print("错误：必须指定 --decrypt <ENCRYPTED_FILE>")
        parser.print_usage()
        sys.exit(1)

    if not args.output:
        print("错误：必须指定 --output <PLAINTEXT_FILE>")
        parser.print_usage()
        sys.exit(1)

    if not args.passphrase:
        print("错误：必须指定 --passphrase <PASSPHRASE>")
        parser.print_usage()
        sys.exit(1)

    ciphertext_path = args.decrypt
    plaintext_path = args.output
    passphrase = args.passphrase.encode('utf-8')

    if not os.path.isfile(ciphertext_path):
        print(f"错误：找不到加密文件 '{ciphertext_path}'")
        sys.exit(1)

    decrypt_stream(ciphertext_path, plaintext_path, passphrase)

if __name__ == "__main__":
    main()
