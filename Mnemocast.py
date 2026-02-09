import binascii
import ipaddress
import sys
import re
import hashlib
from mnemonic import Mnemonic

# BIP-39 官方支持语言
SUPPORTED_LANGS = {
    "1": ("english", "英语"), "2": ("chinese_simplified", "简体中文"),
    "3": ("chinese_traditional", "繁体中文"), "4": ("japanese", "日语"),
    "5": ("korean", "韩语"), "6": ("french", "法语"),
    "7": ("italian", "意大利语"), "8": ("spanish", "西班牙语"),
    "9": ("portuguese", "葡萄牙语")
}

def clean_input(raw_input):
    """支持空格、中英文逗号、换行等多种分隔符清洗"""
    parts = re.split(r'[,\s，]+', raw_input.strip())
    return [p for p in parts if p]

def get_salt_mask(salt_str):
    """将任意盐值通过 SHA-256 转换为 128 位掩码"""
    hash_digest = hashlib.sha256(salt_str.encode()).digest()
    return int.from_bytes(hash_digest[:16], 'big')

def get_mnemo_by_choice():
    print("\n--- 选择语言 ---")
    for k, v in SUPPORTED_LANGS.items():
        print(f"{k}. {v[1]}")
    choice = input("请输入序号 [默认1]: ").strip() or "1"
    lang_name = SUPPORTED_LANGS.get(choice, SUPPORTED_LANGS["1"])[0]
    return Mnemonic(lang_name), lang_name

def get_details(entropy_int, mnemo):
    """根据熵整数提取助记词、十进制序号、二进制流"""
    hex_entropy = hex(entropy_int)[2:].zfill(32)
    entropy_bytes = binascii.unhexlify(hex_entropy)
    words = mnemo.to_mnemonic(entropy_bytes)
    word_list = words.split()
    indices = [mnemo.wordlist.index(w) for w in word_list]
    bin_parts = [bin(i)[2:].zfill(11) for i in indices]
    return words, " ".join(map(str, indices)), " ".join(bin_parts)

def run_m2i():
    print("\n>>> 模式 1：助记词 -> IPv6 (加盐加密)")
    mnemo, lang = get_mnemo_by_choice()
    raw_in = input(f"请输入12位助记词 ({lang}):\n> ").strip()
    salt_in = input("请输入你的私人盐值: ").strip()
    
    parts = clean_input(raw_in)
    if len(parts) != 12: print(f"错误: 检测到 {len(parts)} 个词，需12个"); return

    try:
        orig_entropy = int.from_bytes(mnemo.to_entropy(" ".join(parts)), 'big')
        obf_entropy = orig_entropy ^ get_salt_mask(salt_in)
        ipv6_addr = ipaddress.IPv6Address(obf_entropy)
        _, idx_s, bin_s = get_details(orig_entropy, mnemo)
        
        print("\n" + "="*50)
        print(f"生成的 IPv6 (已加密): \033[1;32m{ipv6_addr}\033[0m")
        print(f"原始十进制序号: \033[1;34m{idx_s}\033[0m")
        print(f"原始二进制序列: \n\033[1;36m{bin_s}\033[0m")
        print("="*50)
    except Exception as e: print(f"错误: {e}")

def run_i2m():
    print("\n>>> 模式 2：IPv6 -> 助记词 (去盐解密)")
    ipv6_in = input("请输入 IPv6 地址:\n> ").strip()
    salt_in = input("请输入你的私人盐值: ").strip()
    mnemo, lang = get_mnemo_by_choice()

    try:
        obf_entropy = int(ipaddress.IPv6Address(ipv6_in))
        orig_entropy = obf_entropy ^ get_salt_mask(salt_in)
        words, idx_s, bin_s = get_details(orig_entropy, mnemo)
        
        print("\n" + "="*50)
        print(f"助记词 ({lang}): \033[1;33m{words}\033[0m")
        print(f"十进制序号: \033[1;34m{idx_s}\033[0m")
        print(f"二进制序列: \n\033[1;36m{bin_s}\033[0m")
        print("="*50)
    except Exception as e: print(f"解密失败: 盐值或IP错误 ({e})")

def run_idx2all():
    print("\n>>> 模式 3：十进制序号 -> 全部 (加盐加密)")
    mnemo, lang = get_mnemo_by_choice()
    raw_in = input("请输入12个十进制序号 (0-2047):\n> ").strip()
    salt_in = input("请输入你的私人盐值: ").strip()
    
    parts = clean_input(raw_in)
    try:
        indices = [int(i) for i in parts]
        if len(indices) != 12: print("错误: 需12个序号"); return
        
        words = " ".join([mnemo.wordlist[i] for i in indices])
        orig_entropy = int.from_bytes(mnemo.to_entropy(words), 'big')
        obf_entropy = orig_entropy ^ get_salt_mask(salt_in)
        ipv6_addr = ipaddress.IPv6Address(obf_entropy)
        _, _, bin_s = get_details(orig_entropy, mnemo)

        print("\n" + "="*50)
        print(f"生成助记词: \033[1;33m{words}\033[0m")
        print(f"生成 IPv6  : \033[1;32m{ipv6_addr}\033[0m")
        print(f"二进制序列 : \n\033[1;36m{bin_s}\033[0m")
        print("="*50)
    except Exception as e: print(f"错误: {e}")

def main():
    while True:
        print("\n" + "      BIP-39 & IPv6 终极加密工具")
        print("="*45)
        print("1. 助记词 -> IPv6 / 序号 / 二进制 (加盐)")
        print("2. IPv6   -> 助记词 / 序号 / 二进制 (解盐)")
        print("3. 序号组 -> 助记词 / IPv6 / 二进制 (加盐)")
        print("Q. 退出")
        choice = input("\n请选择模式: ").upper()
        if choice == '1': run_m2i()
        elif choice == '2': run_i2m()
        elif choice == '3': run_idx2all()
        elif choice == 'Q': break
        input("\n按回车继续...")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: sys.exit()