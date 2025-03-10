
def padding(s: str) -> bytes:
    msg = s.encode('ascii')
    m = len(msg)
    # 全体が 64 バイトになるためには、メッセージ + 0x80 + ゼロパディング + 1 バイトのトレーラー
    # の合計が 64 になる必要がある
    if m > 62:
        raise ValueError("Input too long")

    zeros = b'\x00' * (64 - m - 2)
    return msg + b'\x80' + zeros + bytes([m])

def get_words(block: bytes) -> list:
    if len(block) != 64:
        raise ValueError("Input block must be exactly 64 bytes")

    return [block[i*4:(i+1)*4] for i in range(16)]
