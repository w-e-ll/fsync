# -*- coding: utf-8 -*-


class FSyncError(Exception):
    def __init__(self, message, location=None, line=None, yaml_obj=None):
        if hasattr(yaml_obj, '__yaml_line__'):
            line = yaml_obj.__yaml_line__
            location = yaml_obj.__yaml_location__
        if location or line:
            message += " --"
        if location is not None:
            message += " in %s" % location
        if line is not None:
            message += " at line %s" % line
        super(FSyncError, self).__init__(message)


class ConfigFileNotFound(FSyncError):
    pass


class ConfigError(FSyncError):
    pass


class InvalidEndpoint(FSyncError):
    pass


class ConnectionError(FSyncError):
    pass


class TransferError(FSyncError):
    def __init__(self, message, location=None, line=None, yaml_obj=None):
        super().__init__(message, location, line, yaml_obj)

    pass


class TransferInterrupted(FSyncError):
    pass


class StringInterpolationError(FSyncError):
    pass


class TaskNotFound(FSyncError):
    pass


class HookError(FSyncError):
    pass
