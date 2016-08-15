import time
import os


def generate_nonce():
    return os.urandom(16)


def generate_message_id():
    # Return the time in seconds * 2^32
    return int(time.time() * 2**32)
