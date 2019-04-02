import argparse
import base64
import json
import math
import secrets
import time
import typing

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def base64_to_int(encoded: str) -> int:
    return int(base64.b64decode(encoded.encode('utf-8')).decode('utf-8'))


def pad_pt(pt: str) -> str:
    print("padding ", pt)
    pt = base64.b64encode((secrets.randbits(256) | (1 << (256 - 1))).to_bytes(32, byteorder='big')).decode('utf-8') + pt
    pt += base64.b64encode((secrets.randbits(256) | (1 << (256 - 1))).to_bytes(32, byteorder='big')).decode('utf-8')
    print("padded ", pt)
    return pt


def unpad_pt(pt: str) -> str:
    print("unpadding ", pt)
    pt = pt[44:-44]
    print("unpadded ", pt)
    return pt


def rsa_encrypt(pt: str, key_json: typing.Dict) -> bytes:
    e, n = map(base64_to_int, [key_json['e'], key_json['n']])
    c = int(pow(int.from_bytes(base64.b64encode(pad_pt(pt).encode('utf-8')), byteorder='big'), e, n))
    return base64.b64encode(c.to_bytes(math.ceil(c.bit_length() / 8), byteorder='big'))


def rsa_decrypt(ct: bytes, key_json: typing.Dict) -> str:
    d, n = map(base64_to_int, [key_json['d'], key_json['n']])
    msg = int.from_bytes(base64.b64decode(ct), byteorder='big')
    dec = int(pow(msg, d, n))
    return unpad_pt(
        base64.b64decode(dec.to_bytes(math.ceil(dec.bit_length() / 8), byteorder='big').decode('utf-8')).decode(
            'utf-8'))


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

            with open(output_file, 'w') as outfile:
                data = base64.b64decode(data.encode('utf-8'))
                plain_text = decryptor.update(data) + decryptor.finalize()
                outfile.write(plain_text.decode('utf-8'))


def encrypt(key_file: str, data_file: str, output_file: str):
    with open(data_file, 'r') as df:
        aes_encryption_key = secrets.randbits(128)
        iv = secrets.randbits(96)
        enc = Cipher(
            algorithms.AES(aes_encryption_key.to_bytes(16, byteorder='big')),
            modes.GCM(iv.to_bytes(12, byteorder='big')),
            backend=default_backend()
        ).encryptor()
        data_ct = base64.b64encode(enc.update(df.read().encode('utf-8')) + enc.finalize()).decode('utf-8')

    with open(key_file, 'r') as kf:
        key_json = json.load(kf)
        aes_key_ct = rsa_encrypt(json.dumps({
            'aes_key': base64.b64encode(str(aes_encryption_key).encode('utf-8')).decode('utf-8'),
            'iv': base64.b64encode(str(iv).encode('utf-8')).decode('utf-8'),
            'tag': base64.b64encode(enc.tag).decode('utf-8'),
        }), key_json).decode('utf-8')

    with open(output_file, 'w') as outfile:
        outfile.write(data_ct)
        outfile.write('\n')
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
