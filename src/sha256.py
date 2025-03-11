
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

def split_into_blocks(data: bytes) -> list:
    return [data[i:i+64] for i in range(0, len(data), 64)]

def split_block_into_words(block: bytes) -> list:
    if len(block) != 64:
        raise ValueError("Input block must be exactly 64 bytes")
    return [block[i:i+4] for i in range(0, 64, 4)]

def preprocess(string: str) -> list:
    """
    1. padding 関数で string をバイト列に変換しパディングを追加する。
    2. split_into_blocks 関数で 64 バイトごとのブロックに分割する。
    3. 各ブロックについて split_block_into_words を実行し、ブロックを 4 バイトごとの word に分割する。
    戻り値は、各ブロックを word のリストとしたリスト。
    """
    padded = padding(string)
    blocks = split_into_blocks(padded)
    words = [split_block_into_words(block) for block in blocks]
    return words
