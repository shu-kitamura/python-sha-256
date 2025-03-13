
def preprocess(string: str) -> list:
    """
    1. padding 関数で string をバイト列に変換しパディングを追加する。
    2. 64 バイトごとのブロックに分割する。
    3. ブロックを 4 バイトごとの word に分割する。

    戻り値は、各ブロックを word のリストとしたリスト。
    """
    padded = padding(string)
    blocks = [padded[i:i+64] for i in range(0, len(padded), 64)]

    words = []
    for block in blocks:
        words.append([block[i:i+4] for i in range(0, 64, 4)])

    return words

def padding(string: str) -> bytes:
    # メッセージを ASCII エンコード
    msg = string.encode('ascii')
    m = len(msg)
    # メッセージのビット長
    L = m * 8

    # L を表現するのに必要な最小バイト数 (最低 1 バイト)
    n = 1
    while L >= (1 << (8 * n)):
        n += 1

    # ブロックサイズは 64 バイトの倍数
    # SHA-256 では、現在のブロックに長さフィールドが収まらない場合は新たなブロックを追加する
    # ここでは、メッセージ部の長さ m が 56 バイト以上の場合は 2 ブロックにする
    if m % 64 < 56:
        total_length = ((m // 64) + 1) * 64
    else:
        total_length = ((m // 64) + 2) * 64

    # ゼロパディングのバイト数を計算
    pad_zero_count = total_length - (m + 1 + n)

    return msg + b'\x80' + (b'\x00' * pad_zero_count) + L.to_bytes(n, 'big')

def rtor(data: int, shift: int) -> int:
    return data >> shift | data << (32 - shift) & 0xffffffff

def lower_sigma0(int_word: int) -> int:
    return rtor(int_word, 7) ^ rtor(int_word, 18) ^ (int_word >> 3)

def lower_sigma1(int_word: bytes) -> int:
    return rtor(int_word, 17) ^ rtor(int_word, 19) ^ (int_word >> 10)

def upper_sigma0(int_word: int) -> int:
    return rtor(int_word, 2) ^ rtor(int_word, 13) ^ rtor(int_word, 22)

def upper_sigma1(int_word: int) -> int:
    return rtor(int_word, 6) ^ rtor(int_word, 11) ^ rtor(int_word, 25)

def ch(x: int, y: int, z: int) -> int:
    return (x & y) ^ ((x ^ 0xffffffff) & z)

def maj(x: int, y: int, z: int) -> int:
    return (x & y) ^ (x & z) ^ (y & z)
