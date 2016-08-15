import asyncio, hashlib, os, rsa, struct
from mtproto import messages, scheme, generate_nonce
from mtproto.mtbytearray import MTByteArray
from sympy.ntheory import factorint
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from binascii import crc32


class NonceMismatchError(BaseException):
    pass


class SequenceNumberMismatchError(BaseException):
    pass


class CRCMismatchError(BaseException):
    pass


class Datacenter:
    def __init__(self):
        self.host = '149.154.167.40'
        self.port = 443

        self.reader = None
        self.writer = None

        self.public_key = RSA.importKey('''
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAwVACPi9w23mF3tBkdZz+zwrzKOaaQdr01vAbU4E1pvkfj4sqDsm6
lyDONS789sVoD/xCS9Y0hkkC3gtL1tSfTlgCMOOul9lcixlEKzwKENj1Yz/s7daS
an9tqw3bfUV/nqgbhGX81v/+7RFAEd+RwFnK7a+XYl9sluzHRyVVaTTveB2GazTw
Efzk2DWgkBluml8OREmvfraX3bkHZJTKX4EQSjBbbdJ2ZXIsRrYOXfaA+xayEGB+
8hdlLmAjbCVfaigxX0CDqWeR1yFL9kwd9P0NsZRPsmoqVwMbMu7mStFai6aIhc3n
Slv8kg9qv1m6XHVQY3PnEw+QQtqSIXklHwIDAQAB
-----END RSA PUBLIC KEY-----
            '''.strip())
        self.public_key_fingerprint = 0xc3b42b026ce86b21

        self.sequence_number = -1

        self.__is_first_message = True

    async def connect(self):
        self.__is_first_message = True
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)

    def write_message(self, message):
        message_b = message.serialize()

        # Calculate the metadata
        message_len = (len(message_b) + 12).to_bytes(4, 'little')
        self.sequence_number += 1
        sequence_number = self.sequence_number.to_bytes(4, 'little')

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
        if sequence_number != self.sequence_number:
            raise SequenceNumberMismatchError('Expected %d, got %d' % (self.sequence_number, sequence_number))

        # Check the CRC
        own_crc = crc32(struct.pack('II%ds' % len(payload), message_len, sequence_number, payload))
        if crc != own_crc:
            raise CRCMismatchError('Expected {:#x}, got {:#x}'.format(own_crc, crc))

        message = messages.UnencryptedMessage()
        message.deserialize(payload)

        return message

    async def handshake(self):
        # Request a pq variable from the server
        nonce = generate_nonce()
        obj = scheme.TLReqPQ(nonce=nonce)
        msg = messages.UnencryptedMessage(message_data=obj.serialize())
        self.write_message(msg)

        # Receive the pq variable from the server
        msg = await self.read_message()
        obj = scheme.deserialize(msg.message_data, 0)
        server_nonce = obj.server_nonce
        if obj.nonce != nonce:
            raise NonceMismatchError

        # Factorize the pq variable (proof of work)
        pq = obj.pq
        pq_int = int.from_bytes(pq.s, 'big')
        factors = sorted(factorint(pq_int).keys())
        if len(factors) != 2:
            raise Exception('PQ {:#x} has fewer or more than two factors: {}'.format(pq_int, factors))
        p, q = [MTByteArray(x.to_bytes(4, 'big')) for x in factors]
        print('pq: {}; p: {}; q: {}'.format(pq.s.hex(), p.s.hex(), q.s.hex()))

        # Server authentication (presenting proof of work)
        new_nonce = generate_nonce() + generate_nonce()
        inner_obj = scheme.TLPQInnerData(pq=pq, p=p, q=q, nonce=nonce, server_nonce=server_nonce, new_nonce=new_nonce)
        inner_data = inner_obj.serialize()
        data_with_hash = bytearray(SHA.new(inner_data).digest() + inner_data)
        data_with_hash.extend(os.urandom(255 - len(data_with_hash)))
        encrypted_data = self.public_key.encrypt(bytes(data_with_hash), 0)[0]

        obj = scheme.TLReqDHParams(nonce=nonce, server_nonce=server_nonce, p=p, q=q,
                                   public_key_fingerprint=self.public_key_fingerprint,
                                   encrypted_data=MTByteArray(encrypted_data))
        msg = messages.UnencryptedMessage(message_data=obj.serialize())
        self.write_message(msg)

        # Receive the response
        msg = await self.read_message()
        obj = scheme.deserialize(msg.message_data, 0)
        print(obj)