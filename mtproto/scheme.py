import struct
from .mtbytearray import MTByteArray

__objects = {}


def __add_object(obj):
    assert obj.MAGIC not in __objects
    __objects[obj.MAGIC] = obj


def deserialize(buffer, offset=0):
    magic, = struct.unpack_from('I', buffer, offset=offset)
    try:
        return __objects[magic](buffer, offset=offset)
    except KeyError:
        raise NotImplementedError(hex(magic))


class IncorrectMagicNumberError(Exception):
    pass


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

__add_object(TLVector)


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

__add_object(TLMsgsAck)


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

__add_object(TLMsgContainer)


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

__add_object(TLMessage)


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

__add_object(TLMsgResendReq)


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

__add_object(TLRpcError)


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

__add_object(TLRpcReqError)


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

__add_object(TLClientDHInnerData)


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

__add_object(TLServerDHInnerData)


class TLReqPQ:
    MAGIC = 0x60469778

    def __init__(self, buffer=None, offset=0, nonce=bytes()):
        self.nonce = nonce

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

__add_object(TLReqPQ)


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

__add_object(TLReqDHParams)


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

__add_object(TLSetClientDHParams)


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

__add_object(TLRpcDropAnswer)


class TLGetFutureSalts:
    MAGIC = 0xb921bd04

    def __init__(self, buffer=None, offset=0):
        self.num = 0

        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise IncorrectMagicNumberError
        self.num, = struct.unpack_from('i', buffer, offset=offset + 4)

    def serialize(self):
        return struct.pack('Ii', self.MAGIC, self.num)

    @property
    def serialized_size(self):
        return struct.calcsize('Ii')

    def __repr__(self):
        return 'TLGetFutureSalts#%x(num=%d)' % (self.MAGIC, self.num)

__add_object(TLGetFutureSalts)


class TLPing:
    MAGIC = 0x7abe77ec

    def __init__(self, buffer=None, offset=0):
        self.ping_id = 0

        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise IncorrectMagicNumberError
        self.ping_id = struct.unpack_from('q', buffer, offset=offset + 4)

    def serialize(self):
        return struct.pack('Iq', self.MAGIC, self.ping_id)

    @property
    def serialized_size(self):
        return struct.calcsize('Iq')

    def __repr__(self):
        return 'TLPing#%x(ping_id=%d)' % (self.MAGIC, self.ping_id)

__add_object(TLPing)


class TLPingDelayDisconnect:
    MAGIC = 0xf3427b8c

    def __init__(self, buffer=None, offset=0):
        self.ping_id = 0
        self.disconnect_delay = 0

        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise IncorrectMagicNumberError
        self.ping_id, self.disconnect_delay = struct.unpack_from('qi', buffer, offset=offset + 4)

    def serialize(self):
        return struct.pack('Iqi', self.MAGIC, self.ping_id, self.disconnect_delay)

    @property
    def serialized_size(self):
        return struct.calcsize('Iqi')

    def __repr__(self):
        return 'TLPingDelayDisconnect#%x(ping_id=%d, disconnect_delay=%d)' % \
               (self.MAGIC, self.ping_id, self.disconnect_delay)

__add_object(TLPingDelayDisconnect)


class TLDestroySession:
    MAGIC = 0xe7512126

    def __init__(self, buffer=None, offset=0, session_id=0):
        self.session_id = session_id

        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise IncorrectMagicNumberError
        self.session_id, = struct.unpack_from('q', buffer, offset=offset + 4)

    def serialize(self):
        return struct.pack('Iq', self.MAGIC, self.session_id)

    @property
    def serialized_size(self):
        return struct.calcsize('Iq')

    def __repr__(self):
        return 'TLDestroySession#%x(session_id=%d)' % (self.MAGIC, self.session_id)

__add_object(TLDestroySession)


class TLGzipPacked:
    MAGIC = 0x3072cfa1

    def __init__(self, buffer=None, offset=0, packed_data=MTByteArray()):
        self.packed_data = packed_data

        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise IncorrectMagicNumberError
        self.packed_data.deserialize(buffer, offset + 4)

    def serialize(self):
        packed_data_b = self.packed_data.serialize()
        return struct.pack('I%ds' % len(packed_data_b), self.MAGIC, packed_data_b)

    @property
    def serialized_size(self):
        return struct.calcsize('I%ds' % self.packed_data.serialized_size)

    def __repr__(self):
        return 'TLGzipPacked#%x(...)' % self.MAGIC

__add_object(TLGzipPacked)


class TLError:
    MAGIC = 0xc4b9f9bb

    def __init__(self, buffer=None, offset=0, code=0, text=MTByteArray()):
        self.code = code
        self.text = text

        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise IncorrectMagicNumberError
        self.code, = struct.unpack_from('i', buffer, offset=offset + 4)
        self.text.deserialize(buffer, offset=offset + 8)

    def serialize(self):
        text_b = self.text.serialize()
        return struct.pack('Ii%ds' % len(text_b), self.MAGIC, self.code, text_b)

    @property
    def serialized_size(self):
        return struct.calcsize('Ii%ds' % self.text.serialized_size)

    def __repr__(self):
        return 'TLError#%x(code=%d, text=%r)' % (self.MAGIC, self.code, self.text)

__add_object(TLError)
