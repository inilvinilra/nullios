class NulliosError(Exception):
    pass


class InvalidTargetError(NulliosError):
    pass


class StoreError(NulliosError):
    pass


class IpaError(NulliosError):
    pass


class AnalysisError(NulliosError):
    pass


class MissingDependencyError(NulliosError):
    pass
