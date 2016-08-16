import asyncio
import hashlib
import os
import struct
import time

from Crypto.PublicKey import RSA
from Crypto.Util.strxor import strxor
from sympy.ntheory import factorint

import mtproto
from mtproto import exceptions, scheme
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
        self.session_id = os.urandom(8)

        self.__first_message = True

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
        self.__first_message = True

    def send_message(self, message):
        message_id = mtproto.generate_message_id().to_bytes(8, 'little')

        if self.auth_key is None or self.server_salt is None:
            # Send the data unencrypted
            data = bytes(8) + message_id + len(message).to_bytes(4, 'little') + message
        else:
            # Encrypt the data
            to_encrypt = (self.server_salt + self.session_id + message_id +
                          self.sequence_number_out.to_bytes(4, 'little') + len(message).to_bytes(4, 'little') + message)
            key = hashlib.sha1(to_encrypt).digest[-16:]
            padding = os.urandom(-len(to_encrypt) % 16)
            aes_key, aes_iv = mtproto.aes_calculate(key, self.auth_key)
            data = self.auth_key_id + key + mtproto.aes_ige(to_encrypt + padding, aes_key, aes_iv, 'encrypt')

        # If this is the first message, prepend it with 0xEF to indicate the abridged protocol
        if self.__first_message:
            payload = bytearray(b'\xef')
            self.__first_message = False
        else:
            payload = bytearray(b'')

        # Calculate the (abridged) length
        length = len(data) // 4
        if length > 0x7e:
            payload.append(0x7f)
            payload.extend(length.to_bytes(3, 'little'))
        else:
            payload.append(length)

        payload.extend(data)
        self.sequence_number_out += 1

        self.writer.write(bytes(payload))

    async def recv_message(self):
        # Read the length
        length = ord(await self.reader.read(1))
        if length > 0x7e:
            length = int.from_bytes(await self.reader.read(3), 'little')
        length *= 4

        data = await self.reader.read(length)
        auth_key_id = int.from_bytes(data[:8], 'little')
        if auth_key_id == 0:
            # Data is not encrypted
            message_length, = struct.unpack_from('8xI', data, 8)
            return data[20:message_length + 20]
        elif auth_key_id == self.auth_key_id:
            # Data is encrypted
            message_key = data[8:24]
            encrypted_data = data[24:]

            aes_key, aes_iv = mtproto.aes_calculate(message_key, self.auth_key, 'client')
            decrypted_data = mtproto.aes_ige(encrypted_data, aes_key, aes_iv, 'decrypt')

            # Check the salt and session id (TODO make exceptions for this)
            assert decrypted_data[:8] == self.server_salt
            assert decrypted_data[8:16] == self.session_id

            # Check the sequence number
            seq_no = int.from_bytes(decrypted_data[24:28], 'little')
            if seq_no != self.sequence_number_in:
                raise exceptions.SequenceNumberMismatchError('Expected %d, got %d' %
                                                             (self.sequence_number_in, seq_no))
            self.sequence_number_in += 1

            message_length = int.from_bytes(decrypted_data[28:32], 'little')
            return decrypted_data[32:32 + message_length]
        else:
            # TODO make an exception for this
            raise Exception('unknown auth_key id')

    async def handshake(self):
        # Request a pq variable from the server
        nonce = os.urandom(16)
        obj = scheme.TLReqPQ(nonce=nonce)
        self.send_message(obj.serialize())

        # Receive the pq variable from the server
        obj = scheme.deserialize(await self.recv_message(), 0)
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
        self.send_message(obj.serialize())

        # Receive the response and decrypt it
        obj = scheme.deserialize(await self.recv_message(), 0)
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
            self.send_message(obj.serialize())

            obj = scheme.deserialize(await self.recv_message(), 0)
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
                return
            elif obj.result == 'retry':
                if obj.new_nonce_hash != new_nonce_hashes[1]:
                    raise exceptions.NonceMismatchError
            elif obj.result == 'fail':
                if obj.new_nonce_hash != new_nonce_hashes[2]:
                    raise exceptions.NonceMismatchError
                raise exceptions.HandshakeError('server did not accept DH parameters')
            else:
                raise Exception('Invalid response from server: {}'.format(obj.result))

        raise exceptions.HandshakeError('DH negotiation failed after 15 tries')