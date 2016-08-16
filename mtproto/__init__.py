import random
import time
import hashlib

from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor


def generate_message_id():
    # Return the time in seconds * 2^32
    return int(time.time() * 2 ** 32)


def aes_calculate(key, auth_key, dir='server'):
    if dir == 'client':
        auth_key = auth_key[8:]
    hash_a = hashlib.sha1(key + auth_key[:32]).digest()
    hash_b = hashlib.sha1(auth_key[32:48] + key + auth_key[48:64]).digest()
    hash_c = hashlib.sha1(auth_key[64:96] + key).digest()
    hash_d = hashlib.sha1(key + auth_key[96:128]).digest()

    return (
        hash_a[:8] + hash_b[8:20] + hash_c[4:16],
        hash_a[8:20] + hash_b[:8] + hash_c[16:20] + hash_d[:8]
    )


def aes_ige(data, key, iv, operation):
    """
    Encrypts or decrypts data using AES in IGE mode.

    Based on telepy by Anton Grigoryev
    (https://github.com/griganton/telepy_old/blob/master/crypt.py)

    :param data: The bytes buffer to encrypt or decrypt
    :param key: The key to encrypt/decrypt with
    :param iv: The IV to encrypt/decrypt with
    :param operation: 'encrypt' to encrypt, 'decrypt' to decrypt
    :return: The decrypted/encrypted data
    """
    if len(key) != 32 or len(iv) != 32:
        raise ValueError('key and iv should be 32 bytes long')

    cipher = AES.new(key, AES.MODE_ECB, iv)
    if len(data) % cipher.block_size != 0:
        raise ValueError('data should be a multiple of {} bytes' % cipher.block_size)

    iv_x = iv[:cipher.block_size]
    iv_y = iv[cipher.block_size:]

    ciphered = bytearray()
    for i in range(0, len(data), cipher.block_size):
        in_data = data[i:i + cipher.block_size]

        if operation == 'decrypt':
            decrypted = cipher.decrypt(strxor(in_data, iv_y))
            out_data = strxor(decrypted, iv_x)
            iv_x = in_data
            iv_y = out_data
        elif operation == 'encrypt':
            encrypted = cipher.encrypt(strxor(in_data, iv_x))
            out_data = strxor(encrypted, iv_y)
            iv_x = out_data
            iv_y = in_data
        else:
            raise ValueError('operation must be \'decrypt\' or \'encrypt\'')

        ciphered.extend(out_data)

    return bytes(ciphered)


def is_prime(n, precision=7):
    # http://en.wikipedia.org/wiki/Miller-Rabin_primality_test#Algorithm_and_running_time
    if n == 1 or n % 2 == 0 or n < 1:
        return False
    elif n < 1:
        raise ValueError("Out of bounds, first argument must be > 0")

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for repeat in range(precision):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for r in range(s - 1):
            x = pow(x, 2, n)
            if x == 1:
                return False
            if x == n - 1:
                break
        else:
            return False

    return True


def is_safe_prime(n):
    if not is_prime(n):
        return False
    if not is_prime((n - 1) // 2):
        return False
    if not 2**2047 < n < 2**2048:
        return False
    return True
