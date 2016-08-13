import struct


# TODO rewrite this ugly function
def read_string(buffer, offset=0):
    orig_offset = offset

    l, = struct.unpack_from('B', buffer, offset=offset)
    offset += 1

    sl = 1
    if l >= 254:
        l1, l2, l3 = struct.unpack_from('3B', buffer, offset=offset)
        offset += 3

        l = l1 | l2 << 8 | l3 << 16
        sl = 4

    addition = (l + sl) % 4
    if addition != 0:
        addition = 4 - addition

    s, = struct.unpack_from('%ds' % l, buffer, offset=offset)
    offset += l + addition

    return s.decode('utf-8'), (offset - orig_offset)


def write_string(s):
    if len(s) < 254:
        len_buf = struct.pack('B', len(s))
    else:
        len_buf = struct.pack('3B', len(s) & 0xff, (len(s) >> 8) & 0xff, (len(s) >> 16) & 0xff)

    addition = (len(s) + len(len_buf)) % 4
    return len_buf + s + b'\0' * addition


class IncorrectMagicNumberError(Exception):
    pass


class UnsupportedObjectError(Exception):
    pass


class TLObject:
    objects = {}

    @staticmethod
    def deserialize(buffer, offset=0):
        magic, = struct.unpack_from('I', buffer, offset=offset)
        try:
            return TLObject.objects[magic](buffer, offset=offset)
        except KeyError:
            raise UnsupportedObjectError(hex(magic))

    @property
    def needs_layer(self):
        return False


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
        return 8 + len(self.values) * 8

    def __getitem__(self, key):
        return self.values[key]

    def __setitem__(self, key, value):
        self.values[key] = value

    def __repr__(self):
        return '<TLVector: %r>' % self.values


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
        return 4 + self.msg_ids.serialized_size

    def __repr__(self):
        return '<TLMsgsAck: msg_ids=%r>' % self.msg_ids


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
        size = 8
        for msg in self.messages:
            size += msg.serialized_size
        return size

    def __repr__(self):
        return '<TLMsgContainer: TLMessage * %d>' % len(self.messages)


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
        return 20 + self.bytes

    def __repr__(self):
        return '<TLMessage: msg_id=%d>' % self.msg_id


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
        return 4 + self.msg_ids.serialized_size

    def __repr__(self):
        return '<TLMsgResendReq: msg_ids=%r>' % self.msg_ids


TLObject.objects[TLMsgResendReq.MAGIC] = TLMsgResendReq


class TLRpcError:
    MAGIC = 0x2144ca19

    def __init__(self, buffer=None, offset=0):
        self.error_code = 0
        self.error_message = ''
        self.__str_size = 0
        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise IncorrectMagicNumberError
        self.error_code, = struct.unpack_from('i', buffer, offset=offset + 4)
        self.error_message, self.__str_size = read_string(buffer, offset=offset + 8)

    def serialize(self):
        s = write_string(self.error_message)
        return struct.pack('Ii%ds' % len(s), self.MAGIC, self.error_code, s)

    @property
    def serialized_size(self):
        return 8 + self.__str_size

    def __repr__(self):
        return '<TLRpcError: %d:%s>' % (self.error_code, self.error_message)

TLObject.objects[TLRpcError.MAGIC] = TLRpcError


class TLRpcReqError:
    MAGIC = 0x7ae432f5

    def __init__(self, buffer=None, offset=0):
        self.query_id = 0
        self.error_code = 0
        self.error_message = ''
        self.__str_size = 0
        if buffer is not None:
            self.deserialize(buffer, offset)

    def deserialize(self, buffer, offset=0):
        if (self.MAGIC,) != struct.unpack_from('I', buffer, offset=offset):
            raise IncorrectMagicNumberError
        self.query_id, self.error_code = struct.unpack_from('qi', buffer, offset=offset + 4)
        self.error_message, self.__str_size = read_string(buffer, offset=offset + 12)

    def serialize(self):
        s = write_string(self.error_message)
        return struct.pack('Iqi%ds' % len(s), self.MAGIC, self.query_id, self.error_code, s)

    @property
    def serialized_size(self):
        return 12 + self.__str_size

    def __repr__(self):
        return '<TLRpcError: %d:%s>' % (self.error_code, self.error_message)

TLObject.objects[TLRpcReqError.MAGIC] = TLRpcReqError
