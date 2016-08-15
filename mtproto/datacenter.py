import asyncio
import hashlib
import os
import struct
from binascii import crc32

from Crypto.PublicKey import RSA
from sympy.ntheory import factorint

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

        self.sequence_number_out = 0
        self.sequence_number_in = 0

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
        print(buf.hex())
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
            raise exceptions.CRCMismatchError('Expected {:#x}, got {:#x}'.format(own_crc, crc))

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
        fingerprint = obj.server_public_key_fingerprints[0]
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

        print('Requesting DH parameters')
        obj = scheme.TLReqDHParams(nonce=nonce, server_nonce=server_nonce, p=p_ba, q=q_ba,
                                   public_key_fingerprint=fingerprint, encrypted_data=MTByteArray(encrypted_data))
        msg = messages.UnencryptedMessage(message_data=obj.serialize())
        self.write_message(msg)

        # Receive the response
        msg = await self.read_message()
        obj = scheme.deserialize(msg.message_data, 0)
        print(obj)
