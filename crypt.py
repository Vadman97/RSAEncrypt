#!/usr/bin/python3.6

import argparse
import base64
import json
import secrets
import sys
import time
import typing

import math
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MIN_PYTHON = (3, 6)
if sys.version_info < MIN_PYTHON:
    sys.exit("Python %s.%s or later is required.\n" % MIN_PYTHON)


class RSAKeyInvalid(Exception):
    def __init__(self, msg: str):
        super(RSAKeyInvalid, self).__init__(msg)


def base64_to_int(encoded: str) -> int:
    return int(base64.b64decode(encoded.encode('utf-8')).decode('utf-8'))


def rsa_pad_pt(pt: str, key_length: int) -> str:
    print("padding ", pt)
    pt_bit_length = int.from_bytes(pt.encode('utf-8'), byteorder='big').bit_length()
    remaining_padding = key_length - pt_bit_length
    start_bits = remaining_padding - 736
    pt = base64.b64encode(secrets.randbits(start_bits).to_bytes(
        math.ceil(start_bits / 8), byteorder='big')
    ).decode('utf-8') + pt
    print("padded ", pt)
    return pt


def rsa_unpad_pt(pt: str, key_length: int) -> str:
    print("unpadding ", pt)
    if key_length == 2048:
        pt = pt[20:]
    elif key_length == 4096:
        pt = pt[360:]
    elif key_length == 8192:
        pt = pt[720:]
    print("unpadded ", pt)
    return pt


def rsa_encrypt(pt: str, key_json: typing.Dict) -> bytes:
    e, n = map(base64_to_int, [key_json['e'], key_json['n']])
    c = int(
        pow(int.from_bytes(rsa_pad_pt(pt, key_json['length']).encode('utf-8'), byteorder='big'), e, n))
    return base64.b64encode(c.to_bytes(math.ceil(c.bit_length() / 8), byteorder='big'))


def rsa_decrypt(ct: bytes, key_json: typing.Dict) -> str:
    d, n = map(base64_to_int, [key_json['d'], key_json['n']])
    msg = int.from_bytes(base64.b64decode(ct), byteorder='big')
    dec = int(pow(msg, d, n))
    try:
        return rsa_unpad_pt(dec.to_bytes(math.ceil(dec.bit_length() / 8), byteorder='big').decode('utf-8'),
                            key_json['length'])
    except UnicodeDecodeError:
        pass
    raise RSAKeyInvalid("could not decrypt AES key using RSA - is your private key correct?")


def decrypt(key_file: str, data_file: str, output_file: str):
    with open(data_file, 'r') as df:
        data, encrypted_aes_key = df.readlines()
        with open(key_file, 'r') as kf:
            key_json = json.load(kf)
            decrypted = json.loads(rsa_decrypt(encrypted_aes_key, key_json))
            aes_key, iv = map(base64_to_int, [decrypted['aes_key'], decrypted['iv']])
            tag = base64.b64decode(decrypted['tag'])

            decryptor = Cipher(
                algorithms.AES(aes_key.to_bytes(16, byteorder='big')),
                modes.GCM(iv.to_bytes(12, byteorder='big'), tag),
                backend=default_backend()
            ).decryptor()

            with open(output_file, 'wb') as outfile:
                data = base64.b64decode(data.encode('utf-8'))
                try:
                    plain_text = decryptor.update(data) + decryptor.finalize()
                    outfile.write(plain_text)
                except InvalidTag:
                    raise RSAKeyInvalid("tag does not match - encrypted AES key was tampered with")


def encrypt(key_file: str, data_file: str, output_file: str):
    with open(data_file, 'rb') as df:
        aes_encryption_key = secrets.randbits(128)
        iv = secrets.randbits(96)
        enc = Cipher(
            algorithms.AES(aes_encryption_key.to_bytes(16, byteorder='big')),
            modes.GCM(iv.to_bytes(12, byteorder='big')),
            backend=default_backend()
        ).encryptor()
        data_ct = base64.b64encode(enc.update(df.read()) + enc.finalize())

    with open(key_file, 'r') as kf:
        key_json = json.load(kf)
        aes_key_ct = rsa_encrypt(json.dumps({
            'aes_key': base64.b64encode(str(aes_encryption_key).encode('utf-8')).decode('utf-8'),
            'iv': base64.b64encode(str(iv).encode('utf-8')).decode('utf-8'),
            'tag': base64.b64encode(enc.tag).decode('utf-8'),
        }), key_json)

    with open(output_file, 'wb') as outfile:
        outfile.write(data_ct)
        outfile.write('\n'.encode('utf-8'))
        outfile.write(aes_key_ct)


def main(e: bool, key_file: str, data_file: str, output_file: str):
    if e:
        encrypt(key_file, data_file, output_file)
    else:
        decrypt(key_file, data_file, output_file)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate RSA public and private keys.')
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('-e', '--encrypt', action='store_true')
    group.add_argument('-d', '--decrypt', action='store_true')
    parser.add_argument('key_name', metavar='key_name', type=str, help='the filename of the key to use')
    parser.add_argument('data_file', metavar='data_file', type=str, help='the input data file name')
    parser.add_argument('output_file', metavar='output_file', type=str, help='the output data file name')
    args = parser.parse_args()
    start_time = time.time()
    e_flag = args.encrypt and not args.decrypt
    main(e_flag, args.key_name, args.data_file, args.output_file)
    print("--- %s seconds ---" % (time.time() - start_time))
