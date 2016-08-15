import struct
from . import generate_message_id


class UnencryptedMessage:
    def __init__(self, auth_key_id=0, message_id=generate_message_id(), message_data=None):
        self.auth_key_id = auth_key_id
        self.message_id = message_id
        self.message_data = message_data

    def deserialize(self, buffer, offset=0):
        print(buffer.hex())
        self.auth_key_id, self.message_id, message_len = struct.unpack_from('qqi', buffer, offset=offset)
        self.message_data, = struct.unpack_from('%ds' % message_len, buffer, offset=offset + 20)

    def serialize(self):
        return struct.pack('qqi%ds' % len(self.message_data),
                           self.auth_key_id, self.message_id, len(self.message_data), self.message_data)
