#!/usr/bin/env python
# -*- coding: utf-8 -*-

import bz2
import functools
import gzip
import logging
import os
import select
import time
import zipfile
from subprocess import Popen, PIPE


def is_readable_file(filename):
    try:
        with open(filename, 'r') as fp:
            fp.read(1)
        return True
    except Exception:
        return False


def expand_path(path):
    return os.path.realpath(os.path.expanduser(os.path.expandvars(path)))


def retry(ExceptionToCheck, tries=4, delay=3, backoff=2, logger=None):
    """Retry calling the decorated function using an exponential backoff.

    http://www.saltycrane.com/blog/2009/11/trying-out-retry-decorator-python/
    original from: http://wiki.python.org/moin/PythonDecoratorLibrary#Retry

    :param ExceptionToCheck: the exception to check. may be a tuple of
        exceptions to check
    :type ExceptionToCheck: Exception or tuple
    :param tries: number of times to try (not retry) before giving up
    :type tries: int
    :param delay: initial delay between retries in seconds
    :type delay: int
    :param backoff: backoff multiplier e.g. value of 2 will double the delay
        each retry
    :type backoff: int
    :param logger: logger to use. If None, print
    :type logger: logging.Logger instance
    """
    def deco_retry(f):

        @functools.wraps(f)
        def f_retry(*args, **kwargs):
            mtries, mdelay = tries, delay
            while mtries > 1:
                try:
                    return f(*args, **kwargs)
                except ExceptionToCheck as e:
                    msg = "%s, Retrying in %d seconds..." % (str(e), mdelay)
                    if logger:
                        logger.warning(msg)
                    else:
                        print(msg)
                    time.sleep(mdelay)
                    mtries -= 1
                    mdelay *= backoff
            return f(*args, **kwargs)

        return f_retry  # true decorator

    return deco_retry


def human_bytes(num, suffix='B'):
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)


def compress_file(src_path, dst_path, method):
    if method == 'gzip':
        with open(src_path, 'rb') as src, gzip.open(dst_path, 'wb') as dst:
            dst.writelines(src)
    elif method == 'bzip2':
        with open(src_path, 'rb') as src, bz2.BZ2File(dst_path, 'wb') as dst:
            dst.writelines(src)
    elif method == 'zip':
        with zipfile.ZipFile(dst_path, 'w', compression=zipfile.ZIP_DEFLATED) as dst:
            dst.write(src_path, arcname=os.path.basename(src_path))
    else:
        raise NotImplementedError("Unknown compression method '%s'." % method)


def add_custom_loglevel(level, name):
    """
    Monkey patch logging in order to add a custom log level
    """
    uname = name.upper()
    if hasattr(logging, uname):
        return False

    setattr(logging, uname, level)
    logging.addLevelName(level, uname)

    def log_method(self, message, *args, **kwargs):
        if self.isEnabledFor(level):
            self._log(level, message, args, **kwargs)

    log_method.__name__ = name
    setattr(logging.Logger, name, log_method)


def logged_call(cmd, logger, stdout_log_level=None, stderr_log_level=None,
                encoding='UTF-8', **kwargs):
    """
    Variant of subprocess.call that accepts a logger instead of stdout/stderr,
    and logs stdout messages via logger.debug and stderr messages via
    logger.error.

    Fixed version taken from: https://gist.github.com/bgreenlee/1402841
    """
    if stdout_log_level is None:
        add_custom_loglevel(21, 'stdout')
        stdout_log_level = logging.STDOUT

    if stderr_log_level is None:
        add_custom_loglevel(39, 'stderr')
        stderr_log_level = logging.STDERR

    if isinstance(logger, str):
        logger = logging.getLogger(logger)

    child = Popen(cmd, stdout=PIPE, stderr=PIPE, **kwargs)

    log_level = {
        child.stdout: stdout_log_level,
        child.stderr: stderr_log_level,
    }

    def check_io():
        ready_to_read = select.select([child.stdout, child.stderr], [], [], 10)[0]
        for io in ready_to_read:
            for line in io.readlines():
                if not (io == child.stderr and not line):
                    logger.log(log_level[io], line.decode(encoding)[:-1])

    # keep checking stdout/stderr until the child exits
    while child.poll() is None:
        check_io()

    rcode = child.wait()
    check_io()  # check again to catch anything after the process exits
    return rcode


def safe_eval(expr, context):
    # TODO: check expression's ast and filter out authorized nodes
    #       before sending to eval(), then remove __*__ key accesses
    #       Or do the restriction at bytecode level.
    #       But before, check if a lib already exists.
    env = dict(
        locals=None,
        globals=None,
        __name__=None,
        __file__=None,
        __builtins__=None,
    )
    return eval(expr, env, context)
