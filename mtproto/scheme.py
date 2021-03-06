import struct

from . import exceptions
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


def print_table():
    keys = sorted(__objects.keys())
    print('+----------+--------------------------------+')
    print('| Magic    | Name                           |')
    print('+----------+--------------------------------+')
    for key in keys:
        value = __objects[key]
        print('| {:08x} | {:<30s} |'.format(key, value.__name__))
    print('+----------+--------------------------------+')


class TLVector:
    MAGIC = 0x1cb5c415

    def __init__(self, buffer=None, offset=0):
        self.values = []
        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise exceptions.IncorrectMagicNumberError
        count, = struct.unpack_from('I', buffer, offset=offset + 4)
        self.values = list(struct.unpack_from('%dQ' % count, buffer, offset=offset + 8))

    def serialize(self):
        count = len(self.values)
        return struct.pack('II%dQ' % count, self.MAGIC, count, *self.values)

    def append(self, *l):
        self.values.append(*l)

    @property
    def serialized_size(self):
        return struct.calcsize('II%dQ' % len(self.values))

    def __getitem__(self, key):
        return self.values[key]

    def __setitem__(self, key, value):
        self.values[key] = value

    def __repr__(self):
        return '%s#%x(values=%r)' % (type(self).__name__, self.MAGIC, self.values)

__add_object(TLVector)


class TLServerDHParamsFail:
    MAGIC = 0x79cb045d

    def __init__(self, buffer=None, offset=0):
        self.nonce = bytes()
        self.server_nonce = bytes()
        self.new_nonce_hash = bytes()

        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise exceptions.IncorrectMagicNumberError
        self.nonce, self.server_nonce, self.new_nonce_hash = struct.unpack_from('16s16s16s', buffer, offset=offset + 4)

    def serialize(self):
        raise NotImplementedError

    @property
    def serialized_size(self):
        raise NotImplementedError

    def __repr__(self):
        return '%s#%x(...)' % (type(self).__name__, self.MAGIC)

__add_object(TLServerDHParamsFail)


class TLServerDHParamsOK:
    MAGIC = 0xd0e8075c

    def __init__(self, buffer=None, offset=0):
        self.nonce = bytes()
        self.server_nonce = bytes()
        self.encrypted_answer = MTByteArray()

        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise exceptions.IncorrectMagicNumberError
        self.nonce, self.server_nonce = struct.unpack_from('16s16s', buffer, offset=offset + 4)
        self.encrypted_answer.deserialize(buffer, offset + 36)

    def serialize(self):
        raise NotImplementedError

    @property
    def serialized_size(self):
        raise NotImplementedError

    def __repr__(self):
        return '%s#%x(...)' % (type(self).__name__, self.MAGIC)

__add_object(TLServerDHParamsOK)


class TLResPQ:
    MAGIC = 0x05162463

    def __init__(self, buffer=None, offset=0):
        self.nonce = bytes()
        self.server_nonce = bytes()
        self.pq = MTByteArray()
        self.server_public_key_fingerprints = TLVector()

        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise exceptions.IncorrectMagicNumberError
        offset += 4

        self.nonce, self.server_nonce = struct.unpack_from('16s16s', buffer, offset=offset)
        offset += 32

        self.pq.deserialize(buffer, offset)
        offset += self.pq.serialized_size

        self.server_public_key_fingerprints.deserialize(buffer, offset)

    def serialize(self):
        pq_b = self.pq.serialize()
        spkf_b = self.server_public_key_fingerprints.serialize()
        return struct.pack('I16s16s%ds%ds' % (len(pq_b), len(spkf_b)),
                           self.MAGIC, self.nonce, self.server_nonce, pq_b, spkf_b)

    @property
    def serialized_size(self):
        return struct.calcsize('I16s16s%ds%ds' % (self.pq.serialized_size,
                                                  self.server_public_key_fingerprints.serialized_size))

    def __repr__(self):
        return '%s#%x(...)' % (type(self).__name__, self.MAGIC)

__add_object(TLResPQ)


class TLPQInnerData:
    MAGIC = 0x83c95aec

    def __init__(self, buffer=None, offset=0, pq=MTByteArray(), p=MTByteArray(), q=MTByteArray(),
                 nonce=bytes(), server_nonce=bytes(), new_nonce=bytes()):
        self.pq = pq
        self.p = p
        self.q = q
        self.nonce = nonce
        self.server_nonce = server_nonce
        self.new_nonce = new_nonce

        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise exceptions.IncorrectMagicNumberError
        raise NotImplementedError

    def serialize(self):
        pq_b = self.pq.serialize()
        p_b = self.p.serialize()
        q_b = self.q.serialize()
        return struct.pack('I%ds%ds%ds16s16s32s' % (len(pq_b), len(p_b), len(q_b)),
                           self.MAGIC, pq_b, p_b, q_b, self.nonce, self.server_nonce, self.new_nonce)

    @property
    def serialized_size(self):
        raise struct.calcsize('I%ds%ds%ds16s16s32s' % (self.pq.serialized_size, self.p.serialized_size,
                                                       self.q.serialized_size))

    def __repr__(self):
        return '%s#%x(...)' % (type(self).__name__, self.MAGIC)

__add_object(TLPQInnerData)


class TLMsgsAck:
    MAGIC = 0x62d6b459

    def __init__(self, buffer=None, offset=0):
        self.msg_ids = TLVector()
        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise exceptions.IncorrectMagicNumberError
        self.msg_ids = TLVector(buffer, offset=offset + 4)

    def serialize(self):
        vec = self.msg_ids.serialize()
        return struct.pack('I%ds' % len(vec), self.MAGIC, vec)

    @property
    def serialized_size(self):
        return struct.calcsize('I%ds' % self.msg_ids.serialized_size)

    def __repr__(self):
        return '%s#%x(msg_ids=%r)' % (type(self).__name__, self.MAGIC, self.msg_ids)

__add_object(TLMsgsAck)


class TLMsgContainer:
    MAGIC = 0x73f1f8dc

    def __init__(self, buffer=None, offset=0):
        self.messages = []
        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise exceptions.IncorrectMagicNumberError
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
        return '%s#%x(messages=%r)' % (type(self).__name__, self.MAGIC, self.messages)

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
            raise exceptions.IncorrectMagicNumberError

        self.msg_id, self.segno, self.bytes = struct.unpack_from('qii', buffer, offset=offset + 4)

        # TODO Figure out if the body should be parsed here
        self.body = buffer[20:20 + self.bytes]

    def serialize(self):
        return struct.pack('Iqii%ds' % self.bytes, self.MAGIC, self.msg_id, self.segno, self.bytes, self.body)

    @property
    def serialized_size(self):
        return struct.calcsize('Iqii%ds' % self.bytes)

    def __repr__(self):
        return '%s#%x(msg_id=%d)' % (type(self).__name__, self.MAGIC, self.msg_id)

__add_object(TLMessage)


class DHGen:
    MAGIC = 0xdeadbeef

    def __init__(self, buffer=None, offset=0):
        self.nonce = bytes()
        self.server_nonce = bytes()
        self.new_nonce_hash = bytes()

        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise exceptions.IncorrectMagicNumberError
        self.nonce, self.server_nonce, self.new_nonce_hash = struct.unpack_from('16s16s16s', buffer, offset=4)

    def serialize(self):
        return struct.pack('I16s16s16s', self.MAGIC, self.nonce, self.server_nonce, self.new_nonce_hash)

    @property
    def serialized_size(self):
        return struct.calcsize('I16s16s16s')

    def __repr__(self):
        return '%s#%x(...)' % (type(self).__name__, self.MAGIC)


class TLDHGenRetry(DHGen):
    MAGIC = 0x46dc1fb9
    result = 'retry'

__add_object(TLDHGenRetry)


class TLDHGenFail(DHGen):
    MAGIC = 0xa69dae02
    result = 'fail'

__add_object(TLDHGenFail)


class TLDHGenOk(DHGen):
    MAGIC = 0x3bcbf734
    result = 'ok'

__add_object(TLDHGenOk)


class TLMsgResendReq:
    MAGIC = 0x7d861a08

    def __init__(self, buffer=None, offset=0):
        self.msg_ids = TLVector()
        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise exceptions.IncorrectMagicNumberError
        self.msg_ids = TLVector(buffer, offset=offset + 4)

    def serialize(self):
        vec = self.msg_ids.serialize()
        return struct.pack('I%ds' % len(vec), self.MAGIC, vec)

    @property
    def serialized_size(self):
        return struct.calcsize('I%ds' % self.msg_ids.serialized_size)

    def __repr__(self):
        return '%s#%x(msg_ids=%r)' % (type(self).__name__, self.MAGIC, self.msg_ids)

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
            raise exceptions.IncorrectMagicNumberError
        self.error_code, = struct.unpack_from('i', buffer, offset=offset + 4)
        self.error_message.deserialize(buffer, offset=offset + 8)

    def serialize(self):
        s = self.error_message.serialize()
        return struct.pack('Ii%ds' % len(s), self.MAGIC, self.error_code, s)

    @property
    def serialized_size(self):
        return struct.calcsize('Ii%ds' % self.error_message.serialized_size)

    def __repr__(self):
        return '%s#%x(error_code=%d, error_message=%r)' % \
               (type(self).__name__, self.MAGIC, self.error_code, self.error_message)

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
            raise exceptions.IncorrectMagicNumberError
        self.query_id, self.error_code = struct.unpack_from('qi', buffer, offset=offset + 4)
        self.error_message.deserialize(buffer, offset)

    def serialize(self):
        error_b = self.error_message.serialize()
        return struct.pack('Iqi%ds' % len(error_b), self.MAGIC, self.query_id, self.error_code, error_b)

    @property
    def serialized_size(self):
        return struct.calcsize('Iqi%ds' % self.error_message.serialized_size)

    def __repr__(self):
        return '%s#%x(query_id=%d, error_code=%d, error_message=%r)' % \
               (type(self).__name__, self.MAGIC, self.query_id, self.error_code, self.error_message)

__add_object(TLRpcReqError)


class TLClientDHInnerData:
    MAGIC = 0x6643b654

    def __init__(self, buffer=None, offset=0, nonce=bytes(), server_nonce=bytes(), retry_id=0, g_b=MTByteArray()):
        self.nonce = nonce
        self.server_nonce = server_nonce
        self.retry_id = retry_id
        self.g_b = g_b

        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise exceptions.IncorrectMagicNumberError
        raise NotImplementedError

    def serialize(self):
        gb_b = self.g_b.serialize()
        return (self.MAGIC.to_bytes(4, 'little') + self.nonce + self.server_nonce +
                self.retry_id.to_bytes(8, 'little') + gb_b)

    @property
    def serialized_size(self):
        return struct.calcsize('I%ds%dsq%ds' % (len(self.nonce), len(self.server_nonce), self.g_b.serialized_size))

    def __repr__(self):
        return '%s#%x(...)' % (type(self).__name__, self.MAGIC)

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
            raise exceptions.IncorrectMagicNumberError
        offset += 4

        self.nonce, self.server_nonce, self.g = struct.unpack_from('16s16sI', buffer, offset=offset)
        offset += len(self.nonce) + len(self.server_nonce) + 4

        self.dh_prime.deserialize(buffer, offset=offset)
        offset += self.dh_prime.serialized_size

        self.g_a.deserialize(buffer, offset=offset)
        offset += self.g_a.serialized_size

        self.server_time, = struct.unpack_from('i', buffer, offset=offset)

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
        return '%s#%x(...)' % (type(self).__name__, self.MAGIC)

__add_object(TLServerDHInnerData)


class TLReqPQ:
    MAGIC = 0x60469778

    def __init__(self, buffer=None, offset=0, nonce=bytes()):
        self.nonce = nonce

        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise exceptions.IncorrectMagicNumberError
        self.nonce, = struct.unpack_from('16s', buffer, offset=offset + 4)

    def serialize(self):
        return struct.pack('I%ds' % len(self.nonce), self.MAGIC, self.nonce)

    @property
    def serialized_size(self):
        return struct.calcsize('I%ds' % len(self.nonce))

    def __repr__(self):
        return '%s#%x(...)' % (type(self).__name__, self.MAGIC)

__add_object(TLReqPQ)


class TLReqDHParams:
    MAGIC = 0xd712e4be

    def __init__(self, buffer=None, offset=0, nonce=bytes(), server_nonce=bytes(), p=MTByteArray(), q=MTByteArray(),
                 public_key_fingerprint=0, encrypted_data=MTByteArray()):
        self.nonce = nonce
        self.server_nonce = server_nonce
        self.p = p
        self.q = q
        self.public_key_fingerprint = public_key_fingerprint
        self.encrypted_data = encrypted_data

        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise exceptions.IncorrectMagicNumberError
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

        return (self.MAGIC.to_bytes(4, 'little') + self.nonce + self.server_nonce + p_b + q_b +
                self.public_key_fingerprint.to_bytes(8, 'little') + encrypted_data_b)

        # return struct.pack('I16s16s%ds%dsq%ds' % (len(p_b), len(q_b), len(encrypted_data_b)), self.MAGIC, self.nonce,
        #                    self.server_nonce, p_b, q_b, self.public_key_fingerprint, encrypted_data_b)

    @property
    def serialized_size(self):
        return struct.calcsize('I16s16s%ds%dsQ%ds' % (self.p.serialized_size, self.q.serialized_size,
                                                      self.encrypted_data.serialized_size))

    def __repr__(self):
        return '%s#%x(...)' % (type(self).__name__, self.MAGIC)

__add_object(TLReqDHParams)


class TLSetClientDHParams:
    MAGIC = 0xf5045f1f

    def __init__(self, buffer=None, offset=0, nonce=bytes(), server_nonce=bytes(), encrypted_data=MTByteArray()):
        self.nonce = nonce
        self.server_nonce = server_nonce
        self.encrypted_data = encrypted_data

        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise exceptions.IncorrectMagicNumberError

        self.nonce, self.server_nonce = struct.unpack_from('16s16s', buffer, offset=offset + 4)
        self.encrypted_data.deserialize(buffer, offset=offset + 36)

    def serialize(self):
        encrypted_data_b = self.encrypted_data.serialize()
        return self.MAGIC.to_bytes(4, 'little') + self.nonce + self.server_nonce + encrypted_data_b
        # return struct.pack('I16s16s%ds' % len(encrypted_data_b),
        #                    self.MAGIC, self.nonce, self.server_nonce, encrypted_data_b)

    @property
    def serialized_size(self):
        return struct.calcsize('I16s16s%ds' % self.encrypted_data.serialized_size)

    def __repr__(self):
        return '%s#%x(...)' % (type(self).__name__, self.MAGIC)

__add_object(TLSetClientDHParams)


class TLRpcDropAnswer:
    MAGIC = 0x58e4a740

    def __init__(self, buffer=None, offset=0):
        self.req_msg_id = 0

        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise exceptions.IncorrectMagicNumberError
        self.req_msg_id, = struct.unpack_from('q', buffer, offset=offset + 4)

    def serialize(self):
        return struct.pack('Iq', self.MAGIC, self.req_msg_id)

    @property
    def serialized_size(self):
        return struct.calcsize('Iq')

    def __repr__(self):
        return '%s#%x(req_msg_id=%d)' % (type(self).__name__, self.MAGIC, self.req_msg_id)

__add_object(TLRpcDropAnswer)


class TLGetFutureSalts:
    MAGIC = 0xb921bd04

    def __init__(self, buffer=None, offset=0):
        self.num = 0

        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise exceptions.IncorrectMagicNumberError
        self.num, = struct.unpack_from('i', buffer, offset=offset + 4)

    def serialize(self):
        return struct.pack('Ii', self.MAGIC, self.num)

    @property
    def serialized_size(self):
        return struct.calcsize('Ii')

    def __repr__(self):
        return '%s#%x(num=%d)' % (type(self).__name__, self.MAGIC, self.num)

__add_object(TLGetFutureSalts)


class TLPing:
    MAGIC = 0x7abe77ec

    def __init__(self, buffer=None, offset=0):
        self.ping_id = 0

        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise exceptions.IncorrectMagicNumberError
        self.ping_id = struct.unpack_from('q', buffer, offset=offset + 4)

    def serialize(self):
        return struct.pack('Iq', self.MAGIC, self.ping_id)

    @property
    def serialized_size(self):
        return struct.calcsize('Iq')

    def __repr__(self):
        return '%s#%x(ping_id=%d)' % (type(self).__name__, self.MAGIC, self.ping_id)

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
            raise exceptions.IncorrectMagicNumberError
        self.ping_id, self.disconnect_delay = struct.unpack_from('qi', buffer, offset=offset + 4)

    def serialize(self):
        return struct.pack('Iqi', self.MAGIC, self.ping_id, self.disconnect_delay)

    @property
    def serialized_size(self):
        return struct.calcsize('Iqi')

    def __repr__(self):
        return '%s#%x(ping_id=%d, disconnect_delay=%d)' % (type(self).__name__, self.MAGIC, self.ping_id,
                                                           self.disconnect_delay)

__add_object(TLPingDelayDisconnect)


class TLDestroySession:
    MAGIC = 0xe7512126

    def __init__(self, buffer=None, offset=0, session_id=0):
        self.session_id = session_id

        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise exceptions.IncorrectMagicNumberError
        self.session_id, = struct.unpack_from('q', buffer, offset=offset + 4)

    def serialize(self):
        return struct.pack('Iq', self.MAGIC, self.session_id)

    @property
    def serialized_size(self):
        return struct.calcsize('Iq')

    def __repr__(self):
        return '%s#%x(session_id=%d)' % (type(self).__name__, self.MAGIC, self.session_id)

__add_object(TLDestroySession)


class TLGzipPacked:
    MAGIC = 0x3072cfa1

    def __init__(self, buffer=None, offset=0, packed_data=MTByteArray()):
        self.packed_data = packed_data

        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise exceptions.IncorrectMagicNumberError
        self.packed_data.deserialize(buffer, offset + 4)

    def serialize(self):
        packed_data_b = self.packed_data.serialize()
        return struct.pack('I%ds' % len(packed_data_b), self.MAGIC, packed_data_b)

    @property
    def serialized_size(self):
        return struct.calcsize('I%ds' % self.packed_data.serialized_size)

    def __repr__(self):
        return '%s#%x(...)' % (type(self).__name__, self.MAGIC)

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
            raise exceptions.IncorrectMagicNumberError
        self.code, = struct.unpack_from('i', buffer, offset=offset + 4)
        self.text.deserialize(buffer, offset=offset + 8)

    def serialize(self):
        text_b = self.text.serialize()
        return struct.pack('Ii%ds' % len(text_b), self.MAGIC, self.code, text_b)

    @property
    def serialized_size(self):
        return struct.calcsize('Ii%ds' % self.text.serialized_size)

    def __repr__(self):
        return '%s#%x(code=%d, text=%r)' % (type(self).__name__, self.MAGIC, self.code, self.text)

__add_object(TLError)


class TLInvokeAfterMsg:
    MAGIC = 0xcb9f372d

    def __init__(self, buffer=None, offset=0):
        self.msg_id = 0
        self.query = None

        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise exceptions.IncorrectMagicNumberError
        self.msg_id, = struct.unpack_from('q', buffer, offset=offset + 4)
        self.query = deserialize(buffer, offset + 8)

    def serialize(self):
        query_b = self.query.serialize()
        return struct.pack('Iq%ds' % len(query_b), self.MAGIC, self.msg_id)

    @property
    def serialized_size(self):
        return struct.calcsize('Iq%ds' % self.query.serialized_size)

    def __repr__(self):
        return '%s#%x(msg_id=%d, ...)' % (type(self).__name__, self.MAGIC, self.msg_id)

__add_object(TLInvokeAfterMsg)


class TLInvokeWithLayer:
    MAGIC = 0xda9b0d0d

    def __init__(self, buffer=None, offset=0):
        self.layer = 0
        self.query = None

        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise exceptions.IncorrectMagicNumberError
        self.layer, = struct.unpack_from('i', buffer, offset=offset + 4)
        self.query = self.deserialize(buffer, offset + 8)

    def serialize(self):
        query_b = self.query.serialize()
        return struct.pack('Ii%ds' % len(query_b), self.MAGIC, self.layer, query_b)

    @property
    def serialized_size(self):
        return struct.calcsize('Ii%ds' % self.query.serialized_size)

    def __repr__(self):
        return '%s#%x(layer=%d, ...)' % (type(self).__name__, self.MAGIC, self.layer)

__add_object(TLInvokeWithLayer)


class TLInitConnection:
    MAGIC = 0x69796de9

    def __init__(self, buffer=None, offset=0):
        self.api_id = 0
        self.device_model = MTByteArray()
        self.system_version = MTByteArray()
        self.app_version = MTByteArray()
        self.lang_code = MTByteArray()
        self.query = None

        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise exceptions.IncorrectMagicNumberError
        offset += 4

        self.api_id, = struct.unpack_from('i', buffer, offset=offset)
        offset += 4

        self.device_model.deserialize(buffer, offset)
        offset += self.device_model.serialized_size

        self.system_version.deserialize(buffer, offset)
        offset += self.system_version.serialized_size

        self.app_version.deserialize(buffer, offset)
        offset += self.app_version.serialized_size

        self.lang_code.deserialize(buffer, offset)
        offset += self.lang_code.serialized_size

        self.query = deserialize(buffer, offset)

    def serialize(self):
        device_model_b = self.device_model.serialize()
        system_version_b = self.system_version.serialize()
        app_version_b = self.app_version.serialize()
        lang_code_b = self.lang_code.serialize()
        query_b = self.query.serialize()

        return struct.pack('Ii%ds%ds%ds%ds%ds' % (len(device_model_b), len(system_version_b), len(app_version_b),
                                                  len(lang_code_b), len(query_b)),
                           self.api_id, device_model_b, system_version_b, app_version_b, lang_code_b, query_b)

    @property
    def serialized_size(self):
        return struct.calcsize('Ii%ds%ds%ds%ds%ds' % (self.device_model.serialized_size,
                                                      self.system_version.serialized_size,
                                                      self.app_version.serialized_size,
                                                      self.lang_code.serialized_size,
                                                      self.query.serialized_size))

    def __repr__(self):
        return '%s#%x(api_id=%d, device_model=%r, system_version=%r, app_version=%r, lang_code=%r, query=%r)' % \
               (type(self).__name__, self.MAGIC, self.api_id, self.device_model, self.system_version,
                self.app_version, self.lang_code, self.query)

__add_object(TLInitConnection)


class TLDcOption:
    MAGIC = 0x05d8c6cc

    def __init__(self, buffer=None, offset=0):
        self.flags = 0
        self.id = 0
        self.ip_address = MTByteArray()
        self.port = 0

        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise exceptions.IncorrectMagicNumberError
        self.flags, self.id = struct.unpack_from('ii', buffer, offset=offset + 4)
        self.ip_address.deserialize(buffer, offset + 12)
        self.port, = struct.unpack_from('i', buffer, offset + 12 + self.ip_address.serialized_size)

    def serialize(self):
        ip_address_b = self.ip_address.serialize()
        return struct.pack('Iii%dsi' % len(ip_address_b), self.flags, self.id, ip_address_b, self.port)

    @property
    def serialized_size(self):
        return struct.calcsize('Iii%dsi' % self.ip_address.serialized_size)

    def __repr__(self):
        return '%s#%x(flags=0x%x, id=%d, ip_address=%r, port=%d)' % (type(self).__name__, self.MAGIC, self.flags,
                                                                     self.id, self.ip_address, self.port)

__add_object(TLDcOption)


class TLAuthSendCode:
    MAGIC = 0x768d5f4d

    def __init__(self, phone_number=MTByteArray(), sms_type=0, api_id=0, api_hash=MTByteArray(),
                 lang_code=MTByteArray(b'en')):
        self.phone_number = phone_number
        self.sms_type = sms_type
        self.api_id = api_id
        self.api_hash = api_hash
        self.lang_code = lang_code

    def deserialize(self, buffer, offset=0):
        raise NotImplementedError

    def serialize(self):
        return (self.MAGIC.to_bytes(4, 'little') + self.phone_number.serialize() + self.sms_type.to_bytes(4, 'little') +
                self.api_id.to_bytes(4, 'little') + self.api_hash.serialize() + self.lang_code.serialize())
