import pytest

from src.sha256 import padding


def test_padding():
    assert padding("test") == b'\x74\x65\x73\x74\x80' + (b'\x00' * 58) + b'\x04'
    assert padding("") == b'\x80' + (b'\x00' * 62) + b'\x00'
    assert padding("a" * 62) == b'\x61' * 62 + b'\x80' + b'\x3e'

    # 入力が 62 バイトを超えると ValueError が発生する
    with pytest.raises(ValueError) as e:
        padding("a" * 63)
        assert str(e.value) == "Input too long"


