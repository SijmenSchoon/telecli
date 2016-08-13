import struct
import math


class MTByteArray:
    def __init__(self, val=b''):
        self.s = val

    def deserialize(self, buffer, offset=0):
        if buffer[offset] < 254:
            length = buffer[offset]
            self.s = buffer[offset + 1:offset + 1 + length]
        else:
            length = struct.unpack_from('I', buffer, offset=offset)[0] >> 8
            self.s = buffer[offset + 4:offset + 4 + length]

    def serialize(self):
        if len(self.s) < 254:
            size_buf = struct.pack('B', len(self.s))
        else:
            size_buf = struct.pack('I', len(self.s) << 8 | 254)

        padding = -(len(self.s) + len(size_buf)) % 4
        return size_buf + self.s + bytes(padding)

    @property
    def serialized_size(self):
        unpadded_size = (1 if len(self.s) < 254 else 4) + len(self.s)
        return math.ceil(unpadded_size / 4) * 4

    def __repr__(self):
        return 'MTByteArray(%r)' % self.s


class IncorrectMagicNumberError(Exception):
    pass


class TLObject:
    objects = {}

    @staticmethod
    def deserialize(buffer, offset=0):
        magic, = struct.unpack_from('I', buffer, offset=offset)
        try:
            return TLObject.objects[magic](buffer, offset=offset)
        except KeyError:
            raise NotImplementedError(hex(magic))


class TLVector:
    MAGIC = 0x1cb5c415

    def __init__(self, buffer=None, offset=0):
        self.values = []
        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise IncorrectMagicNumberError
        count, = struct.unpack_from('I', buffer, offset=offset + 4)
        self.values = list(struct.unpack_from('%dq' % count, buffer, offset=offset + 8))

    def serialize(self):
        count = len(self.values)
        return struct.pack('II%dq' % count, self.MAGIC, count, *self.values)

    def append(self, *l):
        self.values.append(*l)

    @property
    def serialized_size(self):
        return struct.calcsize('II%dq' % len(self.values))

    def __getitem__(self, key):
        return self.values[key]

    def __setitem__(self, key, value):
        self.values[key] = value

    def __repr__(self):
        return 'TLVector#%x(values=%r)' % (self.MAGIC, self.values)

TLObject.objects[TLVector.MAGIC] = TLVector


class TLMsgsAck:
    MAGIC = 0x62d6b459

    def __init__(self, buffer=None, offset=0):
        self.msg_ids = TLVector()
        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise IncorrectMagicNumberError
        self.msg_ids = TLVector(buffer, offset=offset + 4)

    def serialize(self):
        vec = self.msg_ids.serialize()
        return struct.pack('I%ds' % len(vec), self.MAGIC, vec)

    @property
    def serialized_size(self):
        return struct.calcsize('I%ds' % self.msg_ids.serialized_size)

    def __repr__(self):
        return 'TLMsgsAck#%x(msg_ids=%r)' % (self.MAGIC, self.msg_ids)

TLObject.objects[TLMsgsAck.MAGIC] = TLMsgsAck


class TLMsgContainer:
    MAGIC = 0x73f1f8dc

    def __init__(self, buffer=None, offset=0):
        self.messages = []
        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise IncorrectMagicNumberError
        count, = struct.unpack_from('I', buffer, offset=offset + 4)
        offset += 8
        for _ in range(count):
            message = TLMessage(buffer, offset)
            self.messages.append(message)
            offset += message.serialized_size

    def serialize(self):
        msgs = bytes().join([msg.serialize() for msg in self.messages])
        return struct.pack('II%ds' % len(msgs), self.MAGIC, len(self.messages), msgs)

    @property
    def serialized_size(self):
        size = 0
        for msg in self.messages:
            size += msg.serialized_size
        return struct.calcsize('II%ds' % size)

    def __repr__(self):
        return 'TLMsgContainer#%x(messages=%r)' % (self.MAGIC, self.messages)

TLObject.objects[TLMsgContainer.MAGIC] = TLMsgContainer


class TLMessage:
    MAGIC = 0x5bb8e511

    def __init__(self, buffer=None, offset=0):
        self.msg_id = 0
        self.segno = 0
        self.bytes = 0
        self.body = None
        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise IncorrectMagicNumberError

        self.msg_id, self.segno, self.bytes = struct.unpack_from('qii', buffer, offset=offset + 4)

        # TODO Figure out if the body should be parsed here
        self.body = buffer[20:20 + self.bytes]

    def serialize(self):
        return struct.pack('Iqii%ds' % self.bytes, self.MAGIC, self.msg_id, self.segno, self.bytes, self.body)

    @property
    def serialized_size(self):
        return struct.calcsize('Iqii%ds' % self.bytes)

    def __repr__(self):
        return 'TLMessage#%x(msg_id=%d)' % (self.MAGIC, self.msg_id)

TLObject.objects[TLMessage.MAGIC] = TLMessage


class TLMsgResendReq:
    MAGIC = 0x7d861a08

    def __init__(self, buffer=None, offset=0):
        self.msg_ids = TLVector()
        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise IncorrectMagicNumberError
        self.msg_ids = TLVector(buffer, offset=offset + 4)

    def serialize(self):
        vec = self.msg_ids.serialize()
        return struct.pack('I%ds' % len(vec), self.MAGIC, vec)

    @property
    def serialized_size(self):
        return struct.calcsize('I%ds' % self.msg_ids.serialized_size)

    def __repr__(self):
        return 'TLMsgResendReq#%x(msg_ids=%r)' % (self.MAGIC, self.msg_ids)

TLObject.objects[TLMsgResendReq.MAGIC] = TLMsgResendReq


class TLRpcError:
    MAGIC = 0x2144ca19

    def __init__(self, buffer=None, offset=0):
        self.error_code = 0
        self.error_message = MTByteArray()
        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise IncorrectMagicNumberError
        self.error_code, = struct.unpack_from('i', buffer, offset=offset + 4)
        self.error_message.deserialize(buffer, offset=offset + 8)

    def serialize(self):
        s = self.error_message.serialize()
        return struct.pack('Ii%ds' % len(s), self.MAGIC, self.error_code, s)

    @property
    def serialized_size(self):
        return struct.calcsize('Ii%ds' % self.error_message.serialized_size)

    def __repr__(self):
        return 'TLRpcReqError#%x(error_code=%d, error_message=%r)' % (self.MAGIC, self.error_code, self.error_message)

TLObject.objects[TLRpcError.MAGIC] = TLRpcError


class TLRpcReqError:
    MAGIC = 0x7ae432f5

    def __init__(self, buffer=None, offset=0):
        self.query_id = 0
        self.error_code = 0
        self.error_message = MTByteArray()
        self.__str_size = 0
        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise IncorrectMagicNumberError
        self.query_id, self.error_code = struct.unpack_from('qi', buffer, offset=offset + 4)
        self.error_message.deserialize(buffer, offset)

    def serialize(self):
        error_b = self.error_message.serialize()
        return struct.pack('Iqi%ds' % len(error_b), self.MAGIC, self.query_id, self.error_code, error_b)

    @property
    def serialized_size(self):
        return struct.calcsize('Iqi%ds' % self.error_message.serialized_size)

    def __repr__(self):
        return 'TLRpcReqError#%x(query_id=%d, error_code=%d, error_message=%r)' % \
               (self.MAGIC, self.query_id, self.error_code, self.error_message)

TLObject.objects[TLRpcReqError.MAGIC] = TLRpcReqError


class TLClientDHInnerData:
    MAGIC = 0x6643b654

    def __init__(self, buffer=None, offset=0):
        self.nonce = bytes()
        self.server_nonce = bytes()
        self.retry_id = 0

        # TODO Figure out what this is and rename it to something more appropriate
        self.g_b = MTByteArray()

        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise IncorrectMagicNumberError
        raise NotImplementedError

    def serialize(self):
        gb_b = self.g_b.serialize()
        return struct.pack('I%ds%dsq%ds' % (len(self.nonce), len(self.server_nonce), len(gb_b)),
                           self.MAGIC, self.nonce, self.server_nonce, self.retry_id, gb_b)

    @property
    def serialized_size(self):
        return struct.calcsize('I%ds%dsq%ds' % (len(self.nonce), len(self.server_nonce), self.g_b.serialized_size))

    def __repr__(self):
        return 'TLClientDHInnerData#%x(...)' % self.MAGIC

TLObject.objects[TLClientDHInnerData.MAGIC] = TLClientDHInnerData


class TLServerDHInnerData:
    MAGIC = 0xb5890dba

    def __init__(self, buffer=None, offset=0):
        self.nonce = bytes()
        self.server_nonce = bytes()
        self.g = 0
        self.dh_prime = MTByteArray()
        self.g_a = MTByteArray()
        self.server_time = 0

        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise IncorrectMagicNumberError
        offset += 4

        self.nonce, self.server_nonce, self.g = struct.unpack_from('16s16sI', buffer, offset=offset)
        offset += len(self.nonce) + len(self.server_nonce) + 4

        self.dh_prime.deserialize(buffer, offset=offset)
        offset += self.dh_prime.serialized_size

        self.g_a.deserialize(buffer, offset=offset)
        offset += self.g_a.serialized_size

        self.server_time = struct.unpack_from('i', buffer, offset=offset)

    def serialize(self):
        dh_prime_b = self.dh_prime.serialize()
        g_a_b = self.g_a.serialize()
        return struct.pack('I%ds%dsI%ds%dsi' % (len(self.nonce), len(self.server_nonce), len(dh_prime_b), len(g_a_b)),
                           self.MAGIC, self.nonce, self.server_nonce, self.g, dh_prime_b, g_a_b, self.server_time)

    @property
    def serialized_size(self):
        return struct.calcsize('I%ds%dsI%ds%dsi' % (len(self.nonce), len(self.server_nonce),
                                                    self.dh_prime.serialized_size, self.g_a.serialized_size))

    def __repr__(self):
        return 'TLServerDHInnerData#%x(...)' % self.MAGIC

TLObject.objects[TLServerDHInnerData.MAGIC] = TLServerDHInnerData


class TLReqPQ:
    MAGIC = 0x60469778

    def __init__(self, buffer=None, offset=0):
        self.nonce = bytes()

        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise IncorrectMagicNumberError
        self.nonce, = struct.unpack_from('16s', buffer, offset=offset + 4)

    def serialize(self):
        return struct.pack('I%ds' % len(self.nonce), self.MAGIC, self.nonce)

    @property
    def serialized_size(self):
        return struct.calcsize('I%ds' % len(self.nonce))

    def __repr__(self):
        return 'TLReqPQ#%x(...)' % self.MAGIC

TLObject.objects[TLReqPQ.MAGIC] = TLReqPQ


class TLReqDHParams:
    MAGIC = 0xd712e4be

    def __init__(self, buffer=None, offset=0):
        self.nonce = bytes()
        self.server_nonce = bytes()
        self.p = MTByteArray()
        self.q = MTByteArray()
        self.public_key_fingerprint = 0
        self.encrypted_data = MTByteArray()

        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise IncorrectMagicNumberError
        offset += 4

        self.nonce, self.server_nonce = struct.unpack_from('16s16s', buffer, offset=offset)
        offset += 32

        self.p.deserialize(buffer, offset=offset)
        offset += self.p.serialized_size

        self.q.deserialize(buffer, offset=offset)
        offset += self.q.serialized_size

        self.public_key_fingerprint, = struct.unpack_from('q', buffer, offset=offset)
        offset += 8

        self.encrypted_data.deserialize(buffer, offset=offset)

    def serialize(self):
        p_b = self.p.serialize()
        q_b = self.q.serialize()
        encrypted_data_b = self.encrypted_data.serialize()

        return struct.pack('I16s16s%ds%dsq%ds' % (len(p_b), len(q_b), len(encrypted_data_b)), self.MAGIC, self.nonce,
                           self.server_nonce, p_b, q_b, self.public_key_fingerprint, encrypted_data_b)

    @property
    def serialized_size(self):
        return struct.calcsize('I16s16s%ds%dsq%ds' % (self.p.serialized_size, self.q.serialized_size,
                                                      self.encrypted_data.serialized_size))

    def __repr__(self):
        return 'TLReqDHParams#%x(...)' % self.MAGIC

TLObject.objects[TLReqDHParams.MAGIC] = TLReqDHParams


class TLSetClientDHParams:
    MAGIC = 0xf5045f1f

    def __init__(self, buffer=None, offset=0):
        self.nonce = bytes()
        self.server_nonce = bytes()
        self.encrypted_data = MTByteArray()

        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise IncorrectMagicNumberError

        self.nonce, self.server_nonce = struct.unpack_from('16s16s', buffer, offset=offset + 4)
        self.encrypted_data.deserialize(buffer, offset=offset + 36)

    def serialize(self):
        encrypted_data_b = self.encrypted_data.serialize()
        return struct.pack('I16s16s%ds' % len(encrypted_data_b),
                           self.MAGIC, self.nonce, self.server_nonce, encrypted_data_b)

    @property
    def serialized_size(self):
        return struct.calcsize('I16s16s%ds' % self.encrypted_data.serialized_size)

    def __repr__(self):
        return 'TLSetClientDHParams#%x(...)' % self.MAGIC

TLObject.objects[TLSetClientDHParams.MAGIC] = TLSetClientDHParams


class TLRpcDropAnswer:
    MAGIC = 0x58e4a740

    def __init__(self, buffer=None, offset=0):
        self.req_msg_id = 0

        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise IncorrectMagicNumberError
        self.req_msg_id, = struct.unpack_from('q', buffer, offset=offset + 4)

    def serialize(self):
        return struct.pack('Iq', self.MAGIC, self.req_msg_id)

    @property
    def serialized_size(self):
        return struct.calcsize('Iq')

    def __repr__(self):
        return 'TLRpcDropAnswer#%x(req_msg_id=%d)' % (self.MAGIC, self.req_msg_id)

TLObject.objects[TLRpcDropAnswer.MAGIC] = TLRpcDropAnswer
