import hashlib

from src.sha256 import (
    ch,
    compute_hash,
    lower_sigma0,
    lower_sigma1,
    maj,
    padding,
    preprocess,
    rtor,
    sha256,
    upper_sigma0,
    upper_sigma1,
)


def test_padding():
    assert padding("test") == b'\x74\x65\x73\x74' + b'\x80' + (b'\x00' * 51) + b'\x00\x00\x00\x00\x00\x00\x00\x20'
    assert padding("") == b'\x80' + (b'\x00' * 62) + b'\x00'
    assert padding("a" * 55) == (b'\x61' * 55) + b'\x80' + b'\x00\x00\x00\x00\x00\x00\x01\xb8'
    assert padding("a" * 56) == (b'\x61' * 56) + b'\x80' + (b'\x00' * 63) + b'\x00\x00\x00\x00\x00\x00\x01\xc0'
    assert padding("a" * 120) == (b'\x61' * 120) + b'\x80' + (b'\x00' * 63) + b'\x00\x00\x00\x00\x00\x00\x03\xc0'

def test_preprocess():
    input_str1 = "test"
    expect1 = [[
        b'\x74\x65\x73\x74', b'\x80\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00',
        b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00',
        b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00',
        b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x20',
    ]]
    assert preprocess(input_str1) == expect1

    input_str2 = "a" * 56
    expect2 = [[
        b'\x61\x61\x61\x61', b'\x61\x61\x61\x61', b'\x61\x61\x61\x61', b'\x61\x61\x61\x61',
        b'\x61\x61\x61\x61', b'\x61\x61\x61\x61', b'\x61\x61\x61\x61', b'\x61\x61\x61\x61',
        b'\x61\x61\x61\x61', b'\x61\x61\x61\x61', b'\x61\x61\x61\x61', b'\x61\x61\x61\x61',
        b'\x61\x61\x61\x61', b'\x61\x61\x61\x61', b'\x80\x00\x00\x00', b'\x00\x00\x00\x00',
    ],[
        b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00',
        b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00',
        b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00',
        b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x01\xc0',
    ]]
    assert preprocess(input_str2) == expect2

    input_str3 = "hello"
    expect3 = [[
        b'\x68\x65\x6c\x6c', b'\x6f\x80\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00',
        b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00',
        b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00',
        b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x28'
    ]]
    assert preprocess(input_str3) == expect3

def test_rtor():
    assert rtor(1870659584, 7) == 14614528 # b'\x6f\x80\x00\x00' を 7bit シフトするケース
    assert rtor(1870659584, 18) == 7136 # b'\x6f\x80\x00\x00' を 18bit シフトするケース
    assert rtor(219, 4) == 2952790029 # b'\x00\x00\x00\xdb' を 4bit シフトするケース

def test_lower_sigma0():
    assert lower_sigma0(1870659584) == 221191136 # b'\x6f\x80\x00\x00' のケース
    assert lower_sigma0(219) == 3057041434 # b'\x00\x00\x00\xdb' のケース

def test_lower_sigma1():
    assert lower_sigma1(1870659584) == 1825328 # b'\x6f\x80\x00\x00' のケース
    assert lower_sigma1(219) == 7790592 # b'\x00\x00\x00\xdb' のケース

def test_upper_sigma0():
    assert upper_sigma0(1870659584) == 467893694 # b'\x6f\x80\x00\x00' のケース
    assert upper_sigma0(219) == 3336268854 # b'\x00\x00\x00\xdb' のケース

def test_upper_sigma1():
    assert upper_sigma1(1870659584) == 3249795127 # b'\x6f\x80\x00\x00' のケース
    assert upper_sigma1(219) == 2002808195 # b'\x00\x00\x00\xdb' のケース

def test_ch():
    assert ch(1359893119, 2600822924, 528734635) == 528861580

def test_maj():
    assert maj(1359893119, 2600822924, 528734635) == 453466287

def test_compute_hash():
    expect = [[
        b'\x68\x65\x6c\x6c', b'\x6f\x80\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00',
        b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00',
        b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00',
        b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x28'
    ]]
    assert compute_hash(expect) == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

def test_sha256():
    # 既存ライブラリの出力と合致することを確認
    assert sha256("hello") == hashlib.sha256("hello".encode("ascii")).hexdigest()
    assert sha256("a" * 120) == hashlib.sha256(("a" * 120).encode("ascii")).hexdigest()
