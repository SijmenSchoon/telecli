import struct, math


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
