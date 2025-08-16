# encrypt_stream.py


import os
import sys
import struct
import argparse
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# 常量定义（均以字节为单位）
MAGIC = b"AESMACGH"      # 8 bytes：固定标志，用于识别容器格式
VERSION = b"\x01"        # 1 byte：版本号 0x01
SALT_LEN = 16            # 16 bytes：PBKDF2 用到的随机 salt 长度
IV_LEN = 16              # 16 bytes：AES-CBC 用到的初始化向量长度
ITER_DEFAULT = 100000    # PBKDF2 默认迭代次数（整数，不占字节）
CHUNK_SIZE = 64 * 1024   # 64 KB：流式读写时的块大小，用于加密分块

def derive_keys(passphrase: bytes, salt: bytes, iterations: int):
    """
    从 passphrase 和 salt 派生出 64 字节密钥：
    - 前 32 字节用于 AES-256-CBC 加密，
    - 后 32 字节用于 HMAC-SHA256 校验。
    """
    dk = hashlib.pbkdf2_hmac('sha256', passphrase, salt, iterations, dklen=64)
    return dk[:32], dk[32:]

def pkcs7_pad_block(block: bytes):
    """
    对单个数据块做 PKCS#7 填充，使其长度为 16 的整数倍。
    """
    pad_len = 16 - (len(block) % 16)
    return block + bytes([pad_len]) * pad_len

def encrypt_stream(input_path: str, output_path: str, passphrase: bytes, iterations: int = ITER_DEFAULT):
    # 1. 随机生成 16 字节 salt 和 16 字节 iv
    salt = get_random_bytes(SALT_LEN)
    iv = get_random_bytes(IV_LEN)

    # 2. PBKDF2-HMAC-SHA256 派生出 64 字节密钥
    aes_key, hmac_key = derive_keys(passphrase, salt, iterations)

    # 3. 构建并写入 header（共 45 字节）：
    #    MAGIC (8B) ‖ VERSION (1B) ‖ salt (16B) ‖ iv (16B) ‖ iterations (4B big-endian)
    header_parts = [MAGIC, VERSION, salt, iv, struct.pack(">I", iterations)]
    header = b"".join(header_parts)
    with open(output_path, 'wb') as outf:
        outf.write(header)

        # 4. 初始化 HMAC-SHA256，仅对 VERSION‖salt‖iv‖iterations 做 update
        hmac_obj = hmac.new(hmac_key, digestmod=hashlib.sha256)
        hmac_obj.update(VERSION + salt + iv + struct.pack(">I", iterations))

        # 5. 初始化 AES-256-CBC 加密器
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)

        # 6. 流式读取明文并加密
        with open(input_path, 'rb') as inf:
            while True:
                chunk = inf.read(CHUNK_SIZE)
                if len(chunk) == 0:
                    # 文件末尾：生成一个全填充块 (16B)
                    padded = pkcs7_pad_block(b"")
                    ct = cipher.encrypt(padded)
                    outf.write(ct)
                    hmac_obj.update(ct)
                    break

                if len(chunk) < CHUNK_SIZE:
                    # 最后一块，不足 CHUNK_SIZE：做 PKCS#7 填充 (最多 16B)
                    padded = pkcs7_pad_block(chunk)
                    ct = cipher.encrypt(padded)
                    outf.write(ct)
                    hmac_obj.update(ct)
                    break

                # 普通整块 (64KB)：直接加密并更新 HMAC
                ct = cipher.encrypt(chunk)
                outf.write(ct)
                hmac_obj.update(ct)

        # 7. 写入 32 字节 HMAC Tag
        tag = hmac_obj.digest()
        outf.write(tag)

    print(f"Encryption complete ==> {output_path}")

def main():
    parser = argparse.ArgumentParser(
        description="streamed I/O AES-256-CBC + PBKDF2 + HMAC-SHA256 encrypt"
    )
    parser.add_argument('--encrypt',
                        metavar='PLAINTEXT_FILE',
                        required=True,
                        help='要加密的明文文件路径')
    parser.add_argument('--output',
                        metavar='ENCRYPTED_FILE',
                        required=True,
                        help='加密后输出文件路径')
    parser.add_argument('--passphrase',
                        metavar='PASSPHRASE',
                        required=True,
                        help='用于派生密钥的口令 (UTF-8 字符串)')
    parser.add_argument('--iter',
                        metavar='ITERATIONS',
                        type=int,
                        default=ITER_DEFAULT,
                        help=f'PBKDF2 迭代次数，默认 {ITER_DEFAULT}')

    args = parser.parse_args()

    if not args.encrypt:
        print("错误：必须指定 --encrypt <PLAINTEXT_FILE>")
        parser.print_usage()
        sys.exit(1)

    if not args.output:
        print("错误：必须指定 --output <ENCRYPTED_FILE>")
        parser.print_usage()
        sys.exit(1)

    if not args.passphrase:
        print("错误：必须指定 --passphrase <PASSPHRASE>")
        parser.print_usage()
        sys.exit(1)

    plaintext_path = args.encrypt
    encrypted_path = args.output
    passphrase = args.passphrase.encode('utf-8')
    iterations = args.iter

    if not os.path.isfile(plaintext_path):
        print(f"错误：找不到明文文件 '{plaintext_path}'")
        sys.exit(1)

    encrypt_stream(plaintext_path, encrypted_path, passphrase, iterations)

if __name__ == "__main__":
    main()
