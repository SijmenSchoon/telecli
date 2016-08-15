class IncorrectMagicNumberError(Exception):
    pass


class NonceMismatchError(BaseException):
    pass


class SequenceNumberMismatchError(BaseException):
    pass


class CRCMismatchError(BaseException):
    pass
