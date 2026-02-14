#!/usr/bin/env python3

import json
import sys

# 密钥表
salt_len = [
    47,53,73,55,61,103,47,103,33,45,73,37,97,71,39,71,31,61,83,101,
    53,97,79,75,37,31,33,69,43,63,39,43,79,55,49,73,83,67,59,69,
    103,39,47,37,41,71,89,55,49,45,33,45,69,49,43,53,59,31,59,101,
    61,41,79,75,83,89,75,67,41,89,63,101,67,63,97
]

# B64
b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
b64_dec = {ord(b64_chars[i]): i for i in range(64)}
b64_dec[ord('=')] = 0

def b64_decode(s):
    s = s.rstrip('=')
    out = bytearray()
    i = 0
    
    while i < len(s):
        block = 0
        cnt = 0
        
        for j in range(4):
            if i < len(s):
                block = (block << 6) | b64_dec[ord(s[i])]
                i += 1
                cnt += 1
        
        for j in range(cnt, 4):
            block <<= 6
        
        if cnt >= 2:
            out.append((block >> 16) & 0xFF)
        if cnt >= 3:
            out.append((block >> 8) & 0xFF)
        if cnt >= 4:
            out.append(block & 0xFF)
    
    return bytes(out)

def decrypt(pkt):
    # 头
    idx = int(pkt[0:2])
    dlen = int(pkt[2:8])
    klen = salt_len[idx]
    
    # 数据
    body = pkt[8:]
    b64_act = body[0:4]
    key = body[4:4 + klen]
    b64_data = body[4 + klen:]
    
    # 解码
    act_bytes = b64_decode(b64_act + "==")
    key_bytes = key.encode()
    data_bytes = b64_decode(b64_data)
    
    # XOR
    out_len = min(len(data_bytes), dlen)
    out = bytearray(out_len)
    for i in range(out_len):
        out[i] = data_bytes[i] ^ key_bytes[i % klen]
    
    # 动作ID
    ah = act_bytes[0] ^ key_bytes[0]
    am = act_bytes[1] ^ key_bytes[1 % klen]
    al = act_bytes[2] ^ key_bytes[2 % klen]
    act_id = (ah << 16) | (am << 8) | al
    
    # 解析
    text = out.decode('utf-8', errors='replace')
    
    # JSON
    try:
        data = json.loads(text)
        text = json.dumps(data, indent=2, ensure_ascii=False)
    except:
        pass
    
    return act_id, text

def main():
    if len(sys.argv) != 2:
        print("用法: python main.py <数据包>")
        sys.exit(1)
    
    try:
        act_id, text = decrypt(sys.argv[1])
        print(f"动作ID: {act_id}")
        print(text)
    except Exception as e:
        print(f"解密失败: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()