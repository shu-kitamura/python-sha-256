K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

def sha256(string: str) -> str:
    blks = preprocess(string)
    return compute_hash(blks)

def preprocess(string: str) -> list:
    byte_string = string.encode("ascii")
    padded = padding(byte_string)

    blocks = []
    for block in [padded[i:i+64] for i in range(0, len(padded), 64)]:
        words = [block[i:i+4] for i in range(0, 64, 4)]
        blocks.append(words)

    return blocks

def compute_hash(blocks: list) -> str:
    ws = [0] * 64
    H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    for block in blocks:
        for t in range(16):
            ws[t] = int.from_bytes(block[t])

        for t in range(16, 64):
            ws[t] = (lower_sigma1(ws[t - 2]) + ws[t -7] + lower_sigma0(ws[t - 15]) + ws[t - 16]) & 0xffffffff

        a, b, c, d, e, f, g, h = H

        for i in range(64):
            t1 = (h + upper_sigma1(e) + ch(e, f, g) + K[i] + ws[i]) & 0xffffffff
            t2 = (upper_sigma0(a) + maj(a, b, c)) & 0xffffffff
            h = g
            g = f
            f = e
            e = (d + t1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xffffffff

        H[0] = (a + H[0]) & 0xffffffff
        H[1] = (b + H[1]) & 0xffffffff
        H[2] = (c + H[2]) & 0xffffffff
        H[3] = (d + H[3]) & 0xffffffff
        H[4] = (e + H[4]) & 0xffffffff
        H[5] = (f + H[5]) & 0xffffffff
        H[6] = (g + H[6]) & 0xffffffff
        H[7] = (h + H[7]) & 0xffffffff

    return "".join([f"{h:08x}" for h in H])

def padding(byte_string: bytes) -> bytes:
    string_length = len(byte_string)

    n = 1
    while (string_length * 8) >= (1 << (8 * n)):
        n += 1

    # ブロックサイズは 64 バイトの倍数
    # SHA-256 では、現在のブロックに長さフィールドが収まらない場合は新たなブロックを追加する
    # ここでは、メッセージ部の長さ m が 56 バイト以上の場合は 長さを 64 の倍数にする
    if string_length % 64 < 56:
        total_length = ((string_length // 64) + 1) * 64
    else:
        total_length = ((string_length // 64) + 2) * 64

    pad_zero_count = total_length - (string_length+ 1 + n)

    return byte_string + b'\x80' + (b'\x00' * pad_zero_count) + (string_length * 8).to_bytes(n, 'big')

def rtor(data: int, shift: int) -> int:
    return data >> shift | data << (32 - shift) & 0xffffffff

def lower_sigma0(int_word: int) -> int:
    return rtor(int_word, 7) ^ rtor(int_word, 18) ^ (int_word >> 3)

def lower_sigma1(int_word: int) -> int:
    return rtor(int_word, 17) ^ rtor(int_word, 19) ^ (int_word >> 10)

def upper_sigma0(int_word: int) -> int:
    return rtor(int_word, 2) ^ rtor(int_word, 13) ^ rtor(int_word, 22)

def upper_sigma1(int_word: int) -> int:
    return rtor(int_word, 6) ^ rtor(int_word, 11) ^ rtor(int_word, 25)

def ch(x: int, y: int, z: int) -> int:
    return (x & y) ^ ((x ^ 0xffffffff) & z)

def maj(x: int, y: int, z: int) -> int:
    return (x & y) ^ (x & z) ^ (y & z)
