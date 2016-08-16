import asyncio
import hashlib
import os
import struct
import time
from binascii import crc32

from Crypto.PublicKey import RSA
from Crypto.Util.strxor import strxor
from sympy.ntheory import factorint

import mtproto
from mtproto import exceptions, messages, scheme
from mtproto.mtbytearray import MTByteArray


class Datacenter:
    def __init__(self):
        self.host = '149.154.167.40'
        self.port = 443

        self.reader = None
        self.writer = None

        with open('rsa.pub', 'r') as f:
            self.public_key = RSA.importKey(f.read())
        self.public_key_fingerprint = 0

        self.sequence_number_out = 0
        self.sequence_number_in = 0

        self.time_delta = 0
        self.server_salt = None
        self.auth_key = None
        self.auth_key_id = 0

    @property
    def config(self):
        data = {
            'time_delta': self.time_delta,
            'server_salt': self.server_salt,
            'auth_key': {
                'key': self.auth_key,
                'id': self.auth_key_id,
            },
            'public_keys': [
                {
                    'fingerprint': self.public_key_fingerprint,
                    'key': self.public_key.exportKey()
                }
            ],
            'host': self.host,
            'port': self.port
        }
        return data

    @config.setter
    def config(self, val):
        self.time_delta = val['time_delta']
        self.server_salt = val['server_salt']
        self.auth_key = val['auth_key']['key']
        self.auth_key_id = val['auth_key']['id']
        self.public_key = RSA.importKey(val['public_keys'][0]['key'])
        self.public_key_fingerprint = val['public_keys'][0]['fingerprint']
        self.host = val['host']
        self.port = val['port']

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)

    def write_message(self, message):
        message_b = message.serialize()

        # Calculate the metadata
        message_len = (len(message_b) + 12).to_bytes(4, 'little')
        sequence_number = self.sequence_number_out.to_bytes(4, 'little')
        self.sequence_number_out += 1

        crc = crc32(message_len + sequence_number + message_b).to_bytes(4, 'little')

        buf = message_len + sequence_number + message_b + crc
        self.writer.write(buf)

    async def read_message(self):
        # Read the length
        message_len = int.from_bytes(await self.reader.read(4), 'little')

        buf = await self.reader.read(message_len - 4)
        sequence_number, payload, crc = struct.unpack('I%dsI' % (message_len - 12), buf)

        # Check the sequence number
        if sequence_number != self.sequence_number_in:
            raise exceptions.SequenceNumberMismatchError('Expected %d, got %d' %
                                                         (self.sequence_number_in, sequence_number))
        self.sequence_number_in += 1

        # Check the CRC
        own_crc = crc32(struct.pack('II%ds' % len(payload), message_len, sequence_number, payload))
        if crc != own_crc:
            raise exceptions.HashMismatchError('Expected {:#x}, got {:#x}'.format(own_crc, crc))

        message = messages.UnencryptedMessage()
        message.deserialize(payload)

        return message

    async def handshake(self):
        # Request a pq variable from the server
        nonce = os.urandom(16)
        obj = scheme.TLReqPQ(nonce=nonce)
        msg = messages.UnencryptedMessage(message_data=obj.serialize())
        self.write_message(msg)

        # Receive the pq variable from the server
        msg = await self.read_message()
        obj = scheme.deserialize(msg.message_data, 0)
        server_nonce = obj.server_nonce
        self.public_key_fingerprint = obj.server_public_key_fingerprints[0]
        if obj.nonce != nonce:
            raise exceptions.NonceMismatchError

        # Factorize the pq variable (proof of work)
        pq = obj.pq
        pq_int = pq.to_int('big')
        [p, q] = sorted(factorint(pq_int).keys())
        assert p * q == pq_int and p < q

        # Serialize p and q
        p_ba = MTByteArray.from_int(p, 4, 'big')
        q_ba = MTByteArray.from_int(q, 4, 'big')

        # Server authentication (presenting proof of work)
        new_nonce = os.urandom(32)
        inner_obj = scheme.TLPQInnerData(pq=pq, p=p_ba, q=q_ba, nonce=nonce,
                                         server_nonce=server_nonce, new_nonce=new_nonce)
        inner_data = inner_obj.serialize()

        sha_digest = hashlib.sha1(inner_data).digest()
        random_bytes = os.urandom(255 - len(inner_data) - len(sha_digest))
        data_with_hash = sha_digest + inner_data + random_bytes
        encrypted_data = self.public_key.encrypt(data_with_hash, 0)[0]

        obj = scheme.TLReqDHParams(nonce=nonce, server_nonce=server_nonce, p=p_ba, q=q_ba,
                                   public_key_fingerprint=self.public_key_fingerprint,
                                   encrypted_data=MTByteArray(encrypted_data))
        msg = messages.UnencryptedMessage(message_data=obj.serialize())
        self.write_message(msg)

        # Receive the response and decrypt it
        msg = await self.read_message()
        obj = scheme.deserialize(msg.message_data, 0)
        if obj.nonce != nonce or obj.server_nonce != server_nonce:
            raise exceptions.NonceMismatchError

        tmp_aes_key = (hashlib.sha1(new_nonce + server_nonce).digest() +
                       hashlib.sha1(server_nonce + new_nonce).digest()[:12])

        tmp_aes_iv = (hashlib.sha1(server_nonce + new_nonce).digest()[12:20] +
                      hashlib.sha1(new_nonce * 2).digest() + new_nonce[:4])

        data_with_hash = mtproto.aes_ige(obj.encrypted_answer.s, tmp_aes_key, tmp_aes_iv, 'decrypt')
        sha_digest = data_with_hash[:20]
        data = data_with_hash[20:]

        # Process the decrypted data
        obj = scheme.deserialize(data, 0)
        if hashlib.sha1(data[:obj.serialized_size]).digest() != sha_digest:
            raise exceptions.HashMismatchError
        if obj.nonce != nonce or obj.server_nonce != server_nonce:
            raise exceptions.NonceMismatchError

        self.time_delta = obj.server_time - int(time.time())
        dh_prime_ba = obj.dh_prime
        dh_prime = dh_prime_ba.to_int('big')
        if not mtproto.is_safe_prime(dh_prime):
            raise exceptions.NotPrimeError

        # TODO check g
        g = obj.g
        g_a = obj.g_a.to_int('big')

        retry_id = 0
        b = int.from_bytes(os.urandom(256), 'big')
        g_b = pow(g, b, dh_prime)

        if not (1 < g < dh_prime - 1 and 1 < g_a < dh_prime - 1 and 1 < g_b < dh_prime - 1):
            raise exceptions.InvalidGeneratorConstantError('g, g_a and g_b should be between 1 and (dh_prime - 1)')

        inner_obj = scheme.TLClientDHInnerData(nonce=nonce, server_nonce=server_nonce, retry_id=retry_id,
                                               g_b=MTByteArray.from_int(g_b, 256, 'big'))
        inner_data = inner_obj.serialize()
        sha_digest = hashlib.sha1(inner_data).digest()
        random_bytes = os.urandom(-(len(sha_digest) + len(inner_data)) % 16)
        encrypted_data = mtproto.aes_ige(sha_digest + inner_data + random_bytes, tmp_aes_key, tmp_aes_iv, 'encrypt')

        for i in range(15):
            obj = scheme.TLSetClientDHParams(nonce=nonce, server_nonce=server_nonce,
                                             encrypted_data=MTByteArray(encrypted_data))
            msg = messages.UnencryptedMessage(message_data=obj.serialize())
            self.write_message(msg)
            msg = await self.read_message()
            obj = scheme.deserialize(msg.message_data, 0)
            if obj.nonce != nonce or obj.server_nonce != server_nonce:
                raise exceptions.NonceMismatchError

            auth_key = pow(g_a, b, dh_prime)
            auth_key_b = auth_key.to_bytes(256, 'big')
            auth_key_sha = hashlib.sha1(auth_key_b).digest()
            auth_key_aux_hash = auth_key_sha[:8]

            new_nonce_hashes = [hashlib.sha1(new_nonce + i.to_bytes(1, 'little') + auth_key_aux_hash).digest()[-16:]
                                for i in range(1, 4)]
            if obj.result == 'ok':
                if obj.new_nonce_hash != new_nonce_hashes[0]:
                    raise exceptions.NonceMismatchError

                self.server_salt = strxor(new_nonce[:8], server_nonce[:8])
                self.auth_key = auth_key_b
                self.auth_key_id = int.from_bytes(auth_key_sha[-8:], 'little')
            elif obj.result == 'retry':
                if obj.new_nonce_hash != new_nonce_hashes[1]:
                    raise exceptions.NonceMismatchError
            elif obj.result == 'fail':
                if obj.new_nonce_hash != new_nonce_hashes[2]:
                    raise exceptions.NonceMismatchError
                raise exceptions.HandshakeError('server did not accept DH parameters')
            else:
                raise Exception('Invalid response from server')
