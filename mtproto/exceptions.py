class IncorrectMagicNumberError(Exception):
    pass


class NonceMismatchError(BaseException):
    pass


class SequenceNumberMismatchError(BaseException):
    pass


class HashMismatchError(BaseException):
    pass


class NotPrimeError(BaseException):
    pass


class HandshakeError(BaseException):
    pass


class InvalidGeneratorConstantError(BaseException):
    pass
