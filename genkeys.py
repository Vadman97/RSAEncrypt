#!/usr/bin/python3.7

import argparse
import base64
import json
import multiprocessing
import secrets
import time
import typing

NUM_PROCESSORS = multiprocessing.cpu_count() - 1


def is_even(n: int) -> bool:
    return n & 0b1 == 0


def basic_is_prime(n):
    if n < 2:
        return False
    elif n == 2 or n == 3:
        return True
    elif is_even(n):
        return False

    for i in range(3, int(n ** 0.5) + 2, 2):
        if n % i == 0:
            return False
    return True


def is_prime_miller_rabin(n, num_rounds=128):
    if n < 2:
        return False
    elif n == 2 or n == 3:
        return True
    elif is_even(n):
        return False

    s = 0
    d = n - 1
    while is_even(s):
        s += 1
        d = d // 2

    for _ in range(num_rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == (n - 1):
            continue
        next_loop = False
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == (n - 1):
                next_loop = True
                break
        if next_loop:
            continue
        else:
            return False

    return True


def is_prime(n):
    if n <= 1000:
        return basic_is_prime(n)
    return is_prime_miller_rabin(n)


FIRST_PRIMES = [x for x in range(1000) if is_prime(x)]


def generate_prime(num_bits: int, queue: multiprocessing.Queue) -> int:
    while True:
        prime = secrets.randbits(num_bits)
        # set MSB to make sure number is actually num_bits bits long
        prime |= 1 << (num_bits - 1)
        # set LSB to make sure number is odd
        prime |= 1

        # try first primes to make sure it's not an obvious composite
        for p in FIRST_PRIMES:
            if prime % p == 0:
                continue

        if is_prime(prime):
            queue.put(prime)
            return prime


# euclid's algorithm
def gcd(a: int, b: int) -> int:
    while b != 0:
        a, b = b, (a % b)
    return a


def modular_multiplicative_inverse(a: int, b: int) -> int:
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = b, a

    while r != 0:
        quot = old_r // r
        old_r, r = r, old_r - quot * r
        old_s, s = s, old_s - quot * s
        old_t, t = t, old_t - quot * t

    return old_s


def generate_key_pair(num_bits=2048) -> typing.Tuple[typing.Tuple[int, int], typing.Tuple[int, int], int]:
    print("generating primes p and q in parallel")
    queue = multiprocessing.Queue()
    processes = []
    for _ in range(NUM_PROCESSORS):
        proc = multiprocessing.Process(target=generate_prime, args=(num_bits, queue))
        proc.start()
        processes.append(proc)
    # grab the first 2 primes we get
    p = queue.get()
    print(p)
    q = queue.get()
    print(q)
    assert p != q
    print("got primes")
    for proc in processes:
        proc.kill()
    print("starting calculation")

    n = p * q
    phi = (p - 1) * (q - 1)

    # choose an integer e such that 1 < e < phi, ensure e and phi are coprime
    e = -1
    max_div = -1
    # coprime if gcd == 1
    while max_div != 1:
        e = secrets.randbelow(phi - 1) + 1
        max_div = gcd(e, phi)

    # find d as modular multiplicative inverse of e % phi
    for e, phi in [(e, phi), (e, -phi), (-e, phi), (-e, -phi)]:
        d = modular_multiplicative_inverse(e, phi)
        if d > 0:
            break
    assert d > 0
    assert (e * d) % phi == 1

    # return public, private pair
    return (e, n), (d, n), num_bits


def write_key_pair(pu: typing.Tuple[int, int], pr: typing.Tuple[int, int], n_bits: int, name: str):
    print("writing public: ", pu)
    print("writing private: ", pr)
    public_key = {
        'length': n_bits,
        'e': base64.b64encode(str(pu[0]).encode('utf-8')).decode('utf-8'),
        'n': base64.b64encode(str(pu[1]).encode('utf-8')).decode('utf-8')
    }
    private_key = {
        'length': n_bits,
        'd': base64.b64encode(str(pr[0]).encode('utf-8')).decode('utf-8'),
        'n': base64.b64encode(str(pr[1]).encode('utf-8')).decode('utf-8')
    }
    print("public_key ", public_key)
    print("private_key ", private_key)
    with open('{}.pub'.format(name), 'w') as f:
        json.dump(public_key, f)
    with open('{}.prv'.format(name), 'w') as f:
        json.dump(private_key, f)


def main(name: str):
    pub, priv, length = generate_key_pair()
    write_key_pair(pub, priv, length, name)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate RSA public and private keys.')
    parser.add_argument('name', metavar='name', type=str,
                        help='the name of the user for whom the keys will be generated')
    args = parser.parse_args()
    start_time = time.time()
    main(args.name)
    print("--- %s seconds ---" % (time.time() - start_time))
