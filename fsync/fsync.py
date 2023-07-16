#!/usr/bin/env python
# -*- coding: utf-8 -*-

# std
import ast
import datetime
import fnmatch
import glob
import hashlib
import json
import logging
import logging.config
import os
import re
import shlex
import shutil
import socket
import sys
import string
import tempfile
import time
import urllib
import weakref
from argparse import ArgumentParser
from collections import OrderedDict
from collections.abc import Iterable
from getpass import getuser
from logging import getLogger
from os import stat_result
from urllib.parse import urlparse, urlunparse

# dep
import arrow
import crontab
import ftputil
import ftputil.session
import pysftp
import yaml

# internals
from .exceptions import (
    ConfigFileNotFound, ConfigError, InvalidEndpoint, TransferError,
    StringInterpolationError, ConnectionError, TransferInterrupted, TaskNotFound, FSyncError
)

from .hooks import trigger_event
from .utils import human_bytes
from .utils import retry, is_readable_file, expand_path, compress_file, logged_call, safe_eval


__all__ = [
    'FSync', 'Transfer', 'Endpoint', 'ConfigLoader', 'register_scheme',
    'string_interpolate', 'extract_variables',
]

dry_run = False
endpoint_scheme_registry = {}

URL_KEYS = ('scheme', 'username', 'password', 'hostname', 'port', 'path')
DEFAULT_LOGNAME = 'fsync'

# Checking each path for block and char devices has a cost, so we only check
# against a few hard coded special paths.
SPECIAL_PATHS = ('/dev/full', '/dev/null', '/dev/zero')

COMPRESS_EXTENSIONS = {
    'gzip': '.gz',
    'bzip2': '.bz2',
    'zip': '.zip',
}


def register_scheme(scheme):
    def wrapper(cls):
        endpoint_scheme_registry[scheme] = cls
        return cls
    return wrapper


def safe_filename(filename, repl='-'):
    """
    Returns a safe filename for unix and windows filesystems
    """
    return re.sub('[<>:"\*\?\|\\\/\0]', repl, filename)


def parse_url_string(url):
    if not re.match('^[a-z]+:\/\/', url):
        # Scheme-less urls are considered local filesystem path
        url_dict = dict((key, None) for key in URL_KEYS)
        url_dict.update(scheme='file', path=url)
    else:
        url_parsed = urlparse(url)
        url_dict = dict((k, getattr(url_parsed, k)) for k in URL_KEYS if hasattr(url_parsed, k))

        # Attributes to be hex decoded in order to comply with RFC#1738
        for attr in ('username', 'password'):
            if attr in url_dict and url_dict[attr] is not None:
                url_dict[attr] = urllib.parse.unquote(url_dict[attr])
    return url_dict


def extract_variables(pattern, a_string):
    """
    Extract pattern variables out of a string.

    Example:
        extract_variables("/var/<log_dir>/<service>.log", "/var/log/XOrg.log")
        {'log_dir': 'log', 'service': 'XOrg'}
    """
    var_names = re.findall('<([^>]+)>', pattern)
    escaped_pattern = escape_regex(pattern, '<>').replace(r"\*", '.*')
    reg_expr = re.sub('<[^>]+>', '(.*)', escaped_pattern)
    m = re.match(reg_expr, a_string)
    if (var_names and not m) or (m and len(m.groups()) != len(var_names)):
        msg = "Variable backtrack mismatch for '%s' using string '%s'."
        raise Exception(msg % (pattern, a_string))
    var_dict = {}
    if m:
        for i, val in enumerate(m.groups()):
            var_name = var_names[i]
            if var_name == 'env' or var_name.startswith('__'):
                raise Exception("Variable name '%s' is reserved." % var_name)
            var_dict[var_name] = val
    return var_dict


def escape_regex(pattern, additional=''):
    """
    Same function as `re.escape` but with the possibility to add authorized characters
    """
    s = list(pattern)
    alphanum = string.ascii_lowercase + string.ascii_uppercase + string.digits
    authorized = frozenset(''.join(alphanum + additional))
    for i, c in enumerate(pattern):
        if c not in authorized:
            if c == "\000":
                s[i] = "\\000"
            else:
                s[i] = "\\" + c
    return pattern[:0].join(s)


def string_interpolate(a_string, context, raise_if_not_found=True, max_recursion=100):
    """
    Interpolate strings by evaluating expressions in the format: ${expression}
    Loop while an ${expression} is found with a maximum of `max_recursion` in
    order to prevent circular reference.

    Example:
        string_interpolate(
          "/dest/${customer}/${d.year}-${d.month}.log",
          {'customer': 'Tango': 'd': datetime.now()}
        )
       "/dest/Tango/2015-03.log"
    """

    def replace(m):
        expr = m.groups()[0]
        try:
            val = str(safe_eval(expr, context))
            if val == m.group():
                raise StringInterpolationError("Circular self reference in '%s'" % a_string, yaml_obj=a_string)
            return val
        except Exception as e:
            if isinstance(e, NameError) and not raise_if_not_found:
                return m.group()
            raise StringInterpolationError("%s when evaluating string '%s'" % (e, a_string), yaml_obj=a_string)

    regex = '\$\{([^\}]*)\}'
    result = re.sub(regex, replace, a_string)

    if re.search(regex, result) and result != a_string:
        max_recursion -= 1
        if max_recursion <= 0:
            raise StringInterpolationError("Circular reference in '%s'" % a_string, yaml_obj=a_string)
        return string_interpolate(result, context, raise_if_not_found, max_recursion)
    if result == a_string:
        return a_string  # keep same instance for yaml config debugging
    return result


def object_interpolate(obj, context, raise_if_not_found=True):
    """
    Recursively interpolate object members.
    Strings strictly matching /\${.*}$/ will be evaluated and their type kept as is.
    """
    # TODO: implement recursion limit
    if isinstance(obj, list):
        for i, val in enumerate(obj):
            obj[i] = object_interpolate(val, context, raise_if_not_found=raise_if_not_found)
    elif isinstance(obj, dict):
        for key, val in obj.items():
            obj[key] = object_interpolate(val, context, raise_if_not_found=raise_if_not_found)
    elif isinstance(obj, str):
        if obj.startswith('${') and obj.endswith('}'):
            expr = obj[2:-1].strip()
            try:
                ast.parse(expr)  # ensure the expression is valid python code
                new_obj = safe_eval(expr, context)
            except Exception as e:
                if raise_if_not_found:
                    raise e
                new_obj = obj
        else:
            new_obj = string_interpolate(obj, context, raise_if_not_found=raise_if_not_found)
        if obj != new_obj:
            return object_interpolate(new_obj, context, raise_if_not_found=raise_if_not_found)
    return obj


class Env(dict):
    """
    Environment object used to keep yaml 'env' key
    """
    def __init__(self, *a, **kw):
        super(Env, self).__init__(*a, **kw)
        object.__setattr__(self, '__super__', super(Env, self))

    def __getattribute__(self, name):
        if super(Env, self).__contains__(name) and not name.startswith('__'):
            return self[name]
        else:
            return object.__getattribute__(self, name)

    def __setattr__(self, name, value):
        if isinstance(value, dict) and not isinstance(value, Env):
            value = Env(value)
        self[name] = value


class FileInfo:
    """
    This class holds information about a file, and it's endpoint.

    Instances if this class are exposed to the string interpolation
    of the destination file under the special variable __srcfile__
    """
    def __init__(self, path, stat, endpoint=None):
        # TODO: refactor FileInfo in order to be stat lazy
        self.size_human = None
        self.size = None
        self.date = None
        self.stat = None
        self.path = path
        self.dirname = os.path.dirname(path)
        self.basename = os.path.basename(path)
        self.barename, self.extension = os.path.splitext(self.basename)
        self.dotlessname = self.basename.split('.')[0]
        self.endpoint = endpoint
        self.set_stat(stat)

    def set_stat(self, stat):
        self.stat = stat
        self.date = arrow.Arrow.fromtimestamp(stat.st_mtime)
        self.size = stat.st_size
        self.size_human = human_bytes(stat.st_size)

    def __repr__(self):
        cls = self.__class__
        return "<%s.%s %s>" % (
            cls.__module__,
            cls.__name__,
            self.url
        )

    @property
    def url(self):
        return self.endpoint._url(path=self.path)

    def download(self, local_dest):
        self.endpoint.download(self.path, local_dest)

    def has_changed(self):
        new_stat = self.endpoint.lstat(self.path).stat
        if self.stat.st_size != new_stat.st_size:
            self.set_stat(new_stat)
            return True
        return False


class Endpoint:
    """
    A source or destination location used during synchronization transfers.
    (Abstract class)
    """
    is_remote = False

    class Options(dict):
        """Endpoint options object"""
        def __init__(self, **kw):
            dict.__init__(self, kw)
            self.hooks = None
            self.compress = None
            self.move = None
            self.delete = None
            self.__dict__.update(kw)

    def __init__(
            self, scheme, transfer, path=None, username=None,
            password=None, hostname=None, port=None, **opts
    ):
        self.transfer = weakref.proxy(transfer)
        self.log = weakref.proxy(transfer.log)
        self.context = transfer.context

        self.scheme = scheme
        self.username = username
        self.password = password
        self.hostname = hostname
        self.port = port
        if self.port is not None:
            self.port = int(self.port)
        self.path = path

        self.options = self.Options(
            overwrite=opts.pop('overwrite', None),
            overwrite_suffix=opts.pop('overwrite_suffix', None),
            delete=opts.pop('delete', False),
            move=opts.pop('move', ''),
            move_overwrite=opts.pop('move_overwrite', False),
            work_path=opts.pop('work_path', './.${__srcfile__.basename}.tmp'),
            hooks=opts.pop('hooks', None),
            compress=opts.pop('compress', None),
        )

        if self.options.delete and self.options.move:
            raise InvalidEndpoint("'move' and 'delete' options are mutually exclusive")

        valid_compress = COMPRESS_EXTENSIONS.keys()
        if self.options.compress and self.options.compress not in valid_compress:
            msg = "Invalid compression '%s'. Supported compression are %s."
            raise InvalidEndpoint(msg % (self.options.compress, ', '.join(valid_compress)))

        self._setup_done = False

        if opts:
            msg = "Unknown option '%s' for endpoint '%s'" % (next(iter(opts.keys())), self.url)
            raise InvalidEndpoint(msg)

    def __repr__(self):
        cls = self.__class__
        return "<%s.%s %s>" % (
            cls.__module__,
            cls.__name__,
            self.url
        )

    def _url(self, path=None, hide_password=True):
        if path is None:
            path = self.path
        if self.scheme == 'file':
            return path
        else:
            netloc = ''
            if self.username:
                netloc += urllib.parse.quote(self.username)
                if self.password:
                    netloc += ':%s' % ('*' * 8 if hide_password else urllib.parse.quote(self.password))
                netloc += '@'
            netloc += self.hostname
            if self.port:
                netloc += ':%s' % self.port
            return urlunparse((self.scheme, netloc, path, None, None, None))

    @property
    def url(self):
        return self._url()

    def trigger(self, event):
        return trigger_event(event, self.transfer, self.options.hooks)

    def eval(self, a_string, **kw):
        return string_interpolate(a_string, self.context, **kw)

    def get_scalar_path(self, path=None):
        """
        Get flattened path free from any pending string interpolation.
        """
        if path is None:
            path = self.path
        return self.eval(path)

    def get_destination_filepath(self, dst_path, filename):
        """
        Compute a safe destination path for a given path and filename.

        note: this function will create missing folders.
        """
        split_path = dst_path.split('/')
        if '.' in split_path[-1] and dst_path[-1] != '/':
            # We consider last path fragment to be a file if it contains a dot
            # and the path doesn't end with a slash
            dirname = '/'.join(split_path[:-1])
            filename = split_path[-1]
        else:
            dirname = dst_path
            filename = os.path.basename(filename)

        if dirname in SPECIAL_PATHS:
            return dirname

        self.makedirs(dirname)
        return os.path.join(dirname, filename)

    def get_incremental_suffix(self, path, suffix=None):
        """
        Return a safe pathname not existing on the endpoint's filesystem.
        Ensure uniqueness using an incremental suffix.
        """
        def inc(m):
            start, end = m.regs[1]
            incremented = int(m.groups()[0]) + 1
            return '%s%d%s' % (m.string[:start], incremented, m.string[end:])

        def add_suffix(a_path, a_suffix):
            a_suffix = safe_filename(a_suffix)
            s_path = os.path.split(a_path)
            new_file = '{1}{0}{2}'.format(a_suffix, *os.path.splitext(s_path[1]))
            return os.path.join(s_path[0], new_file)

        if not self.exists(path):
            return path
        elif suffix and suffix not in path:
            # We'll first try using the suffix without incrementation
            return self.get_incremental_suffix(add_suffix(path, suffix))

        new_path = re.sub('.+\.(\d+)(\.[^\.]+)?$', inc, path)
        if new_path == path:
            # We start the incremental name at 1
            new_path = add_suffix(path, '.1')

        return self.get_incremental_suffix(new_path)

    def list_files(self, path=None):
        flat_path = path or self.get_scalar_path()
        # Convert variable backtracks to the stars for globbing
        globe_xpr = re.sub('<[^>]+>', '*', flat_path)
        self.log.info("Listing files: %s" % self._url(globe_xpr))
        for f_path in self.glob(globe_xpr):
            # TODO: optimize here, no need to stat then lstat just after.
            #       check if stats structure is cross system for types:
            #       https://docs.python.org/2/library/stat.html
            yield self.lstat(f_path)

    def glob(self, pathname):
        """Cross scheme version of glob.iglob"""
        # TODO: Implement python's 3  glob's ** expando
        #       http://bugs.python.org/issue13968
        if self.scheme == 'file' and '/' not in pathname:
            # local endpoints can handle relative paths
            pathname = './%s' % pathname
        if not glob.has_magic(pathname):
            if self.lexists(pathname):
                yield pathname
            return
        dirname, basename = os.path.split(pathname)
        assert dirname, "This function does not handle relative paths"
        if dirname != pathname and glob.has_magic(dirname):
            dirs = self.glob(dirname)
        else:
            dirs = [dirname]
        if glob.has_magic(basename):
            glob_in_dir = self.glob1
        else:
            glob_in_dir = self.glob0
        for dirname in dirs:
            for name in glob_in_dir(dirname, basename):
                yield os.path.join(dirname, name)

    def glob1(self, dirname, pattern):
        try:
            names = self.listdir(dirname)
        except (os.error, IOError):
            return []
        if pattern[0] != '.':
            names = filter(lambda x: x[0] != '.', names)
        return fnmatch.filter(names, pattern)

    def glob0(self, dirname, basename):
        if basename == '':
            if self.isdir(dirname):
                return [basename]
        else:
            if self.lexists(os.path.join(dirname, basename)):
                return [basename]
        return []

    def get_path_info(self, path):
        raise NotImplementedError()

    def makedirs(self, path):
        # TODO: make an option out of this, when setting up we want this
        #       feature but once the setup is done we want to know if a
        #       folder is missing. Exceptions is dynamic names with dates
        #       or something
        raise NotImplementedError()

    def exists(self, path):
        raise NotImplementedError()

    def lexists(self, pathname):
        raise NotImplementedError()

    def isdir(self, dirname):
        raise NotImplementedError()

    def isfile(self, path):
        raise NotImplementedError()

    def listdir(self, dirname):
        raise NotImplementedError()

    def lstat(self, path):
        raise NotImplementedError()

    def download(self, src_path, tmp_file):
        raise NotImplementedError()

    def upload(self, tmp_file, dst_path):
        raise NotImplementedError()

    def remove(self, path):
        raise NotImplementedError()

    def move(self, src_file, dst_path):
        self.rename(src_file, self.normalize(src_file, dst_path))

    def rename(self, src_path, dst_path):
        raise NotImplementedError()

    def normalize(self, src_file, dst_path):
        src_dir = os.path.dirname(src_file)
        dst_abs = os.path.normpath(os.path.join(src_dir, dst_path))
        dst_final = self.get_destination_filepath(dst_abs, src_file)
        return dst_final

    def setup(self):
        self._setup_done = True

    def tear_down(self):
        pass

    def noop(self, *a, **kw):
        # Used by dry_run
        pass


class RemoteConnectionProxy:
    def __init__(self, endpoint):
        self._endpoint = weakref.proxy(endpoint)
        self._cache = {}

    def __getattribute__(self, attr):
        """
        Dynamically returns all connection's functions decorated with `retry`
        """
        def get(a):
            return object.__getattribute__(self, a)

        cache = get('_cache')
        if attr not in cache:
            endpoint = get('_endpoint')
            real_conn = endpoint._conn
            val = getattr(real_conn, attr)
            if callable(val):
                exceptions = endpoint.retry_on_exceptions
                if exceptions:
                    # TODO: make the retry configurable
                    wrapper = retry(exceptions, tries=2, delay=1, logger=endpoint.log)
                    val = wrapper(val)
            cache[attr] = val
        return cache[attr]


class RemoteEndpoint(Endpoint):
    """
    This remote endpoint baseclass can also act as a proxy if a
    proxy_table dict is setup properly. Those proxied methods
    will be retried according to `retry_on_exceptions`.
    """
    is_remote = True

    # Will hold the connection object
    _conn = None

    # Will hold the connection proxy
    conn = None

    # Proxy table can be a dict where keys are attribute names and values are callables
    proxy_table = None

    # Will retry the proxies' method if it raises on of the specified exceptions
    retry_on_exceptions = None

    def __getattribute__(self, attr):
        """
        Resolution order:
            - top level class (if method in table)
            - proxy_table     (if method in table)
            - object.__getattribute__
        """
        def get(a):
            return object.__getattribute__(self, a)
        table = get('proxy_table')
        if table is not None and attr in table:
            cls = get('__class__').__dict__
            if attr in cls:
                fn = get(attr)
            else:
                fn = table[attr]
            assert callable(fn), (
                "The proxy table of class '%s' returned a non callable "
                "for attr '%s'" % (get('__class__').__name__, attr)
            )
            return fn
        return get(attr)

    def tear_down(self):
        if self.conn is not None:
            self.conn.close()

    def setup_connection(self, conn):
        """
        This must be called with the connection object in order
        to prepare the connection proxy.
        """
        self._conn = conn
        self.conn = RemoteConnectionProxy(self)


@register_scheme('file')
class LocalEndpoint(Endpoint):
    def __init__(self, *a, **kw):
        super(LocalEndpoint, self).__init__(*a, **kw)
        if not self.path:
            raise InvalidEndpoint("No path specified")

    def get_scalar_path(self, path=None):
        if path is None:
            path = self.path
        path = os.path.expanduser(path)
        return super(LocalEndpoint, self).get_scalar_path(path)

    def makedirs(self, path):
        if not os.path.exists(path) and not dry_run:
            self.log.info("Creating directory '%s'" % self._url(path))
            os.makedirs(path)

    def exists(self, path):
        return os.path.exists(path)

    def lexists(self, pathname):
        return os.path.lexists(pathname)

    def isdir(self, dirname):
        return os.path.isdir(dirname)

    def isfile(self, path):
        return os.path.isfile(path)

    def listdir(self, dirname):
        return os.listdir(dirname)

    def lstat(self, path):
        stat = os.lstat(path)
        return FileInfo(path, stat, endpoint=self)

    def download(self, src_path, tmp_file):
        if not dry_run:
            try:
                os.link(src_path, tmp_file)
            except OSError:
                shutil.copy(src_path, tmp_file)

    def upload(self, tmp_file, dst_path):
        if not dry_run:
            try:
                # TODO: use a more elegant way to determine if two paths
                #       are on the same device.
                #       http://stackoverflow.com/questions/17210598
                os.link(tmp_file, dst_path)
            except OSError:
                shutil.copyfile(tmp_file, dst_path)

    def remove(self, path):
        if not dry_run:
            os.remove(path)

    def rename(self, src_path, dst_path):
        if not dry_run:
            shutil.move(src_path, dst_path)


@register_scheme('sftp')
class SFTPEndpoint(RemoteEndpoint):
    retry_on_exceptions = (
        EOFError,
        socket.gaierror,
        pysftp.ConnectionException,
        pysftp.paramiko.SSHException
    )

    def __init__(self, *a, **kw):
        self.private_key = kw.pop('private_key', None)
        if self.private_key is not None:
            self.private_key = expand_path(self.private_key)
        self.private_key_pass = kw.pop('private_key_pass', None)
        super(SFTPEndpoint, self).__init__(*a, **kw)

        if self.username is None:
            self.username = getuser()

    def get_connection(self, hostname, **sftp_options):
        if self.private_key and not is_readable_file(self.private_key):
            raise ConnectionError("Could not read SSH key '%s'" % self.private_key)
        kwargs = dict(
            username=self.username,
            password=self.password,
            port=self.port or 22,
            private_key=self.private_key,
            private_key_pass=self.private_key_pass,
        )
        kwargs.update(sftp_options)
        try:
            return pysftp.Connection(hostname, **kwargs)
        except pysftp.SSHException as e:
            try:
                p_keys = pysftp.paramiko.Agent().get_keys()
                # Use first key in ssh agent if any
                kwargs['private_key'] = p_keys[0]
                return pysftp.Connection(hostname, **kwargs)
            except Exception:
                msg = str(e)
                if msg == "not a valid DSA private key file":
                    # paramiko returns a misleading exception text in case of
                    # passphrase protected rsa key.
                    msg += " or wrong RSA passphrase."
                raise ConnectionError("Could not connect to %s. (%s)" % (self._url(path=''), msg))

    def lstat(self, path):
        obj = self.conn.lstat(path)
        # (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime)
        stat = stat_result(
            (obj.st_mode, None, None, None, obj.st_uid, obj.st_gid, obj.st_size, obj.st_atime, obj.st_mtime, None)
        )

        return FileInfo(path, stat, endpoint=self)

    def setup(self):
        if self._setup_done:
            return

        conn = self.get_connection(self.hostname)
        self.setup_connection(conn)
        self.proxy_table = {
            'makedirs': self.conn.makedirs,
            'exists': self.conn.exists,
            'lexists': self.conn.lexists,
            'isfile': self.conn.isfile,
            'isdir': self.conn.isdir,
            'listdir': self.conn.listdir,
            'download': self.conn.get,
            'upload': self.conn.put,
            'remove': self.conn.remove,
            'rename': self.conn.rename,
        }

        if dry_run:
            for fn in ('makedirs', 'download', 'upload', 'remove', 'rename'):
                self.proxy_table[fn] = self.noop

        super(SFTPEndpoint, self).setup()


@register_scheme('ftp')
class FTPEndpoint(RemoteEndpoint):
    retry_on_exceptions = (
        EOFError,
        ftputil.error.TemporaryError,
    )

    def lstat(self, path):
        obj = self.conn.lstat(path)
        stat = stat_result(obj)
        return FileInfo(path, stat, endpoint=self)

    def makedirs(self, path):
        # FTP protocol doesn't expose a filesystem stat command.
        # ftputil mocks the os.stat by parsing the `ls` command output.
        # Wouter pointed some cases where a mounted external device would
        # not be seen in the `ls` output while it's possible to `cd` in
        # this 'hidden' path, thus we will use that as an heuristic.
        current_path = self.conn.getcwd()
        try:
            self.conn.chdir(path)
        except ftputil.error.PermanentError:
            # Auto make_dirs on those 'invisible' path is not supported.
            self.log.info("Creating directory '%s'" % self._url(path))
            try:
                self.conn.makedirs(path)
            except ftputil.error.FTPError as e:
                raise TransferInterrupted("Could not create directory '%s': %s" %
                                          (self._url(path), e))
        self.conn.chdir(current_path)

    def exists(self, path):
        # As Wouter pointed out [1], ftputil `exists` method will return `False` in some cases
        # when the file actually exists.
        #
        try:
            return self.conn.path.exists(path) or self.conn.stat(path) is not None
        except ftputil.error.PermanentError:
            return False

    def setup(self):
        if self._setup_done:
            return
        ftp_opt = {
            'debug_level': 0
        }
        if self.port:
            ftp_opt['port'] = self.port
        session_class = ftputil.session.session_factory(**ftp_opt)
        try:
            conn = ftputil.FTPHost(
                self.hostname,
                self.username,
                self.password,
                session_factory=session_class,
            )
        except ftputil.error.FTPError as e:
            raise ConnectionError("%s for endpoint '%s'" % (e.strerror, self._url(path='')))
        self.setup_connection(conn)
        self.proxy_table = {
            'make_dirs': self.conn.makedirs,
            'exists': self.conn.path.exists,
            'lexists': self.exists,  # lexists not supported by ftplib
            'isfile': self.conn.path.isfile,
            'isdir': self.conn.path.isdir,
            'listdir': self.conn.listdir,
            'download': self.conn.download,
            'upload': self.conn.upload,
            'remove': self.conn.remove,
            'rename': self.conn.rename,
        }
        if dry_run:
            for fn in ('make_dirs', 'download', 'upload', 'remove', 'rename'):
                self.proxy_table[fn] = self.noop
        else:
            try:
                self.conn.listdir('.')  # checking the data-channel with an `ls`
            except ftputil.error.FTPError as e:
                raise TransferInterrupted(
                    "Could not get commands results from the FTP server's data channel: %s" % e)
        super(FTPEndpoint, self).setup()


class Transfer:
    """
    A file synchronization transfer holding its source(s) and destination(s)

    .. note::

        This object is historically named ``Transfer`` but it is referred as
        ``Task`` in the documentation. This is due to the fact that FSync is
        starting to grow more into a task handler that goes beyond the file
        transfer. The hooks brings advanced usage of FSync and a heavy
        refactoring should be made in order to morph FSync into a task runner.
    """
    def __init__(
            self, name=None, context=None, logger=None,
            loglevel=None, crontab=None, hooks=None, stop_on_error=True
    ):
        self.log = None
        self._tmp_dir = None
        self.total_to_transfer = 0
        self.transferred = 0
        self.warnings = 0
        self.errors = 0
        self.size = 0
        self.sources = []
        self.destinations = []
        self.name = name
        if context is None:
            context = {}
        context['task'] = self
        self.context = context
        self.set_logger(logger or DEFAULT_LOGNAME, loglevel)
        self.crontab = crontab
        self.hooks = hooks
        self.stop_on_error = stop_on_error
        self.start_date = arrow.now()

    @property
    def dry_run(self):
        return dry_run

    def set_logger(self, logger, loglevel=None):
        if isinstance(logger, str):
            self.log = getLogger(logger)
        elif isinstance(logger, logging.Logger):
            self.log = logger
        else:
            raise ValueError("Invalid value type '%s' for logger" % type(logger).__name__)
        if loglevel is not None:
            level = logging._levelToName.get(loglevel.upper())
            if level is not None:
                self.log.setLevel(level)

    def add_source(self, src):
        endpoint = self.get_endpoint(src)
        self.sources.append(endpoint)

    def add_destination(self, dst):
        endpoint = self.get_endpoint(dst)
        self.destinations.append(endpoint)

    def get_endpoint(self, params):
        """
        Get an Endpoint instance out of the given connection params

        :param params:
            The url of the endpoint or option dict
            The params as a dict can contain url parts, but it can also
            contain a mix of url as string ('url' key) + parts
            eg: { 'url': 'ftp://user@foobar/', 'password': 'psswd#$%^:@' }
        :type params: string or dict
        """
        if isinstance(params, str):
            params = dict(url=params)
        assert isinstance(params, dict)

        # Interpolate all keys with current context but do not raise exception if
        # variable is not found, we might have dynamic variables that will be bound later
        for key, val in params.items():
            if isinstance(val, str):
                params[key] = self.eval(params[key], raise_if_not_found=False)

        url_dict = parse_url_string(params.get('url', ''))
        url_dict.update(params)

        scheme = url_dict['scheme']
        cls = endpoint_scheme_registry.get(scheme)
        if cls is None:
            raise InvalidEndpoint("Unsupported scheme: '%s'" % scheme)

        url_dict.pop('url', None)
        url_dict.update(transfer=self)
        endpoint = cls(**url_dict)
        return endpoint

    def trigger(self, event):
        return trigger_event(event, self, self.hooks)

    def eval(self, e_string, **kw):
        return string_interpolate(e_string, self.context, **kw)

    def error(self, *a, **kw):
        self.errors += 1
        self.log.error(*a, **kw)
        if self.stop_on_error is True:
            self.interrupt("one error encountered. (use `stop_on_error: false`"
                           " to resume on transfer errors)")
        max_errors = int(self.stop_on_error)  # Using an awful Python wat
        if max_errors and self.errors > max_errors:
            self.interrupt("Too many errors for this transfer")

    def exception(self, *a, **kw):
        self.log.debug(*a, exc_info=True, **kw)
        self.error(*a, **kw)

    def warning(self, *a, **kw):
        self.warnings += 1
        self.log.warning(*a, **kw)

    def interrupt(self, msg):
        raise TransferInterrupted(msg)

    def start(self):
        if not self.sources:
            raise TransferError("No source specified")

        for hook in self.trigger('will_start_transfer'):
            if hook() is False:
                self.log.warning("Transfer prevented by hook: %s" % hook.__name__)
                return False

        self.log.info("Initiating transfer" + (' "%s"' % self.name if self.name else ''))

        # Create local temporary directory for the transfer
        self._tmp_dir = tempfile.mkdtemp(prefix='fsync-%s-' % time.time())
        self.log.debug("Created temporary directory '%s'." % self._tmp_dir)

        try:
            # Setup all source and destination endpoints at once
            for endpoint in (self.sources + self.destinations):
                endpoint.setup()

            src_files = self.get_all_sources_files()
            self.context.update(source_files=src_files)
            for src_file in src_files:
                if self.destinations:
                    self.total_to_transfer += 1
                # get the variables out of the source path (using current file)
                var_dict = extract_variables(src_file.endpoint.path, src_file.path)

                # enrich the context with extracted variables + sources
                self.context.update(
                    __srcfile__=src_file,  # deprecated. use `source_file` instead
                    source_file=src_file,
                    **var_dict)
                self.sync_file(src_file)

        except (TransferInterrupted, ConnectionError, StringInterpolationError) as e:
            self.errors += 1
            self.log.error("Transfer interrupted: %s" % str(e))
            return False
        except TransferError as e:
            self.exception(e)
        finally:
            self.tear_down()

        if not self.destinations:
            msg = "No destinations defined"
        elif self.total_to_transfer == 0:
            msg = "Nothing to transfer"
        else:
            msg = "Transferred %d of %d file(s) " % (self.transferred, self.total_to_transfer)
            if self.warnings + self.errors:
                msg += 'with %d warnings and %d errors.' % (self.warnings, self.errors)
            else:
                msg += 'successfully.'
        if self.total_to_transfer:
            msg += " (Total size: %s)" % human_bytes(self.size)
        self.log.info(msg)
        return True

    def tear_down(self):
        for hook in self.trigger('transfer_finished'):
            hook()

        self.log.debug("Removing temporary directory '%s'." % self._tmp_dir)
        shutil.rmtree(self._tmp_dir)

        # Endpoint tear down
        for endpoint in self.sources + self.destinations:
            endpoint.tear_down()

    def get_all_sources_files(self):
        all_sources_files = []
        # Iterate over the sources in order to gather the files to be transferred
        for source in self.sources:
            src_files = source.list_files()  # most probably a generator
            # Execute list_source_files hooks for the endpoint scope
            # The endpoint scope should be executed before the transfer scope
            for hook in source.trigger('list_source_files'):
                res = hook(src_files)
                if isinstance(res, Iterable):
                    # If the hook returns an iterable we use this one instead
                    src_files = res
            all_sources_files.extend(src_files)

        # Execute list_source_files hooks for the transfer scope
        # Indeed, one might want to set up a trigger on the transfer level for all
        # sources but in some case you need fine-grained hooks on a particular source.
        for hook in self.trigger('list_source_files'):
            res = hook(all_sources_files)
            if isinstance(res, Iterable):
                all_sources_files = res

        return all_sources_files

    def get_local_copy(self, file_info):
        tmp_file = os.path.join(self._tmp_dir, file_info.basename)
        self.log.debug("Downloading '%s' to temporary file '%s'" % (file_info.url, tmp_file))
        file_info.download(tmp_file)
        if not dry_run:
            # Post download size checkup
            local_size = os.stat(tmp_file).st_size
            if file_info.stat.st_size != local_size and local_size == 0:
                raise TransferError(
                    "Local '%s' is 0 byte length and remote %s bytes, disk might be full."
                    % (file_info.basename, file_info.stat.st_size)
                )
            if file_info.stat.st_size != local_size or file_info.has_changed():
                # TODO: + show full file size in error message
                #       + add retry in this case
                raise TransferError(
                    "Source filesize differs from local after download. [%+d bytes]"
                    % (file_info.stat.st_size - local_size)
                )
        return tmp_file

    def sync_file(self, src_file):
        """
        Synchronize a source file amongst all destination endpoints
        registered for the current transfer
        """
        try:
            tmp_file = self.get_local_copy(src_file)
        except Exception as e:
            self.exception("Error while transferring '%s': %s." % (src_file.url, e))
            return False

        success = True
        for dest in self.destinations:
            # Final destination of the file to transfer
            try:
                dst_path = self.get_destination_path(src_file, dest)
            except TransferError as e:
                self.error(e)
                success = False
                continue

            if dst_path is None:
                # The file should be skipped
                continue

            local_tmp_file = tmp_file
            if dest.options.compress and not dry_run:
                local_tmp_file = self.get_compressed_file(tmp_file, dest.options.compress)

            self.log.info("Transferring '%s' -> '%s' (%s)" % (
                src_file.url,
                dest._url(dst_path),
                src_file.size_human,
            ))

            self.atomic_transfer(local_tmp_file, dst_path, dest)

        if success:
            self.transferred += 1
            self.size += src_file.size
            self.post_transfer_actions(src_file)

        if not dry_run:
            for del_file in glob.glob(tmp_file + '*'):
                self.log.debug("Removing temporary file '%s'" % del_file)
                os.unlink(del_file)
        return success

    def get_destination_path(self, src_file, dest):
        """
        Returns the final destination path for a file or `None` if
        the file should be skipped. Will raise a TransferError in
        case of error.
        """
        dst_path = dest.get_destination_filepath(dest.get_scalar_path(), src_file.basename)

        if dest.options.compress:
            dst_path += COMPRESS_EXTENSIONS[dest.options.compress]

        if dest.exists(dst_path) and dst_path not in SPECIAL_PATHS:
            msg = "Destination '%s' already exists." % dst_path
            if dest.options.overwrite is None:
                # by default, fsync will consider duplicates as errors
                raise TransferError(msg + " Use `overwrite` to change behavior.")
            elif dest.options.overwrite == 'skip':
                # if overwrite option is 'skip' we just skip the file and the transfer
                # is considered successful, so the post actions will occur as normal
                self.warning(msg + " Skipped.")
                return None
            elif dest.options.overwrite:
                # if overwrite option is True, files are overwritten
                try:
                    dest.remove(dst_path)
                except Exception:
                    raise TransferError(msg + " Could not overwrite.")
                else:
                    self.log.info(msg + " Overwriting...")
            else:
                # if overwrite option is False, we generate a new filepath
                # using an incremental suffix
                suffix = None
                if dest.options.overwrite_suffix:
                    suffix = dest.eval(dest.options.overwrite_suffix)
                dst_path = dest.get_incremental_suffix(dst_path, suffix=suffix)
                dst_name = os.path.split(dst_path)[1]
                self.log.info(msg + " Transferring as '%s'." % dst_name)
        return dst_path

    def atomic_transfer(self, tmp_file, dst_path, dest):
        try:
            # The work_path is where we will do the final transfer then rename in
            # order to provide an atomic transfer. This might seem duplicate with the
            # temporary folder in the context of local destinations but keep in mind
            # we have to handle cases such as multiple local destinations with
            # different block devices/partitions for the temporary folder and the
            # destination folder !
            work_path_option = dest.get_scalar_path(dest.options.work_path)
            work_path = dest.normalize(os.path.dirname(dst_path) + os.path.sep, work_path_option)

            if dst_path in SPECIAL_PATHS:
                self.log.debug("Transferring to special path: '%s'" % dst_path)
                dest.upload(tmp_file, dst_path)
            else:
                dbg_msg = "Transferring to temporary destination: '%s'"
                self.log.debug(dbg_msg % work_path)
                dest.upload(tmp_file, work_path)
                dbg_msg = "Atomic rename from '%s' to '%s'."
                self.log.debug(dbg_msg % (dest._url(work_path), dest._url(dst_path)))
                # This final move ensures an atomic transfer (at least on POSIX systems)
                dest.rename(work_path, dst_path)
        except Exception as e:
            _msg = "Error while transferring '%s' to '%s'"
            msg = _msg % (tmp_file, dest._url(dst_path))
            if dst_path not in SPECIAL_PATHS:
                if isinstance(e, IOError) and dest.exists(dst_path):
                    # Here the file did not exist before the transfer, but it
                    # exists after the exception. We consider it's corrupted.
                    try:
                        dest.remove(dst_path)
                        msg += " Removing corrupted destination file."
                    except Exception:
                        pass
                if dest.exists(work_path):
                    # Always clean your room after playing with your toys.
                    dest.remove(work_path)
            self.exception("%s - %s" % (msg, e))
            return

        if not dry_run:
            dst_file = dest.lstat(dst_path)
            self.context.update(destination_file=dst_file)
            for hook in self.trigger('file_transferred'):
                # TODO: endpoint should have path_info() and FileInfo
                # should be lazy on stat
                hook(dst_file)

    @staticmethod
    def get_compressed_file(tmp_file, method):
        new_file = tmp_file + COMPRESS_EXTENSIONS[method]
        if not os.path.exists(new_file):
            compress_file(tmp_file, new_file, method)
        return new_file

    def post_transfer_actions(self, src_file):
        """
        Perform optional actions that should be done on the source
        files after a successful transfer.
        """
        src_endpoint = src_file.endpoint

        # Delete on successful transfer (if requested)
        if src_endpoint.options.delete:
            self.log.info("Deleting '%s' after successful transfer." % src_file.basename)
            try:
                src_endpoint.remove(src_file.path)
            except Exception as exc:
                self.exception("Could not delete '%s' after transfer. Exc: %s" % src_file.basename, exc)

        # Move on successful transfer (if requested)
        if src_endpoint.options.move:
            move_to = src_endpoint.get_scalar_path(src_endpoint.options.move)
            move_to_path = src_endpoint.normalize(src_file.path, move_to)
            if src_endpoint.exists(move_to_path) and not src_endpoint.options.move_overwrite:
                _msg = "Post transfer move destination '%s' already exists."
                self.log.warning(_msg % move_to_path)
                move_to = src_endpoint.get_incremental_suffix(move_to_path)
            self.log.info("Moving %s to %s after successful transfer." % (src_file.basename, move_to))
            try:
                src_endpoint.move(src_file.path, move_to)
            except Exception as exc:
                self.exception("Could not move %s to %s after transfer. Exc: %s"
                               % src_file.basename, move_to, exc)

    def subprocess(self, cmd, shell=False, encoding='UTF-8', logger=None):
        """
        Helper for subprocess launch. The arguments are evaluated and flattened
        if needed.

        :param cmd: command for the subprocess (string or list)
        :param shell: execute command through a shell
        :param encoding: charset encoding used by the program (default: UTF-8)
        :param logger: optional custom logger name
        """
        if logger is None:
            logger = self.log

        if isinstance(cmd, str):
            cmd = self.eval(cmd)
        else:
            cmd = list(cmd)
            command = []
            for part in cmd:
                r_part = object_interpolate(part, self.context)
                if isinstance(r_part, (list, tuple)):
                    command.extend(r_part)
                else:
                    command.append(r_part)
            cmd = command

        display_cmd = cmd
        if isinstance(display_cmd, list):
            display_cmd = ' '.join(cmd)

        if shell and isinstance(cmd, list):
            # Popen with shell=true will prepend ['bash', '-c']
            cmd = display_cmd

        if not shell and isinstance(cmd, str):
            try:
                cmd = shlex.split(cmd)
            except ValueError:
                raise ValueError("Command could not be parsed: %s" % cmd)

        if self.dry_run:
            self.log.info("Dry-run mode: pretend to execute command: %s" % display_cmd)
            return True

        self.log.info("Executing command '%s'" % display_cmd)

        try:
            start = datetime.datetime.now()
            error_code = logged_call(cmd, logger, shell=shell, encoding=encoding)
            delta = datetime.datetime.now() - start
        except OSError as e:
            self.log.error("Could not execute command: %s" % display_cmd)
            self.exception(e)
        else:
            if error_code == 0:
                self.log.info("Command completed successfully in %s." % delta)
                return True
            else:
                self.log.error("Command %s failed with error code %d !" % (cmd, error_code))
        return False


class ConfigLoader(yaml.Loader):
    """
    Custom yaml loader which uses OrderedDicts for maps.
    Adds __yaml_line__ and optional __yaml_location__ property to maps and seqs
    Also provides a helper in order to register yaml constructors.
    """
    location = None
    custom_types = {}

    def __init__(self, *args, **kwargs):
        yaml.Loader.__init__(self, *args, **kwargs)
        self.add_constructor(u'tag:yaml.org,2002:map', type(self).construct_yaml_map)
        self.add_constructor(u'tag:yaml.org,2002:seq', type(self).construct_yaml_seq)

    def construct_yaml_map(self, node):
        data = self.enrich_object(OrderedDict(), node, force=True)
        yield data
        value = self.construct_mapping(node)
        data.update(value)

    def construct_yaml_seq(self, node):
        data = self.enrich_object([], node, force=True)
        yield data
        data.extend(self.construct_sequence(node))

    def construct_mapping(self, node, deep=False):
        if isinstance(node, yaml.MappingNode):
            self.flatten_mapping(node)
        else:
            msg = 'expected a mapping node, but found %s' % node.id
            raise yaml.constructor.ConstructorError(None, None, msg, node.start_mark)

        mapping = OrderedDict()
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                hash(key)
            except TypeError as exc:
                raise yaml.constructor.ConstructorError(
                    'while constructing a mapping',
                    node.start_mark,
                    'found unacceptable key (%s)' % exc,
                    key_node.start_mark)
            value = self.construct_object(value_node, deep=deep)
            mapping[key] = value
        return mapping

    def enrich_object(self, obj, node, force=False):
        # black magic -- close your eyes
        if hasattr(obj, '__yaml_line__') or isinstance(obj, (type(None), bool)):
            return obj
        elif isinstance(obj, (str, int, float)) or force is True:
            t_obj = type(obj)
            if t_obj not in self.custom_types:
                self.custom_types[t_obj] = type(t_obj.__name__, (t_obj,), {})
            obj = self.custom_types[t_obj](obj)
            obj.__yaml_line__ = node.__yaml_line__
            obj.__yaml_location__ = node.__yaml_location__
        return obj

    def construct_object(self, node, deep=False):
        obj = super(ConfigLoader, self).construct_object(node, deep)
        return self.enrich_object(obj, node)

    def compose_node(self, parent, index):
        """
        Keep line numbers in nodes, borrowed from:
        http://stackoverflow.com/a/14355064/1968124
        """
        # the line number where the previous token has ended (plus empty lines)
        line = self.line
        node = yaml.composer.Composer.compose_node(self, parent, index)
        node.__yaml_line__ = line + 1
        node.__yaml_location__ = self.location
        return node

    @classmethod
    def register_constructors(cls, obj):
        """Register `yaml_` prefixed methods of a given object as yaml constructors"""
        for item in dir(obj):
            if item.startswith('yaml_'):
                fn = getattr(obj, item)
                if callable(fn):
                    cls.add_constructor('!%s' % item[5:], fn)

    @classmethod
    def load(cls, stream, location=None):
        loader = cls(stream)
        loader.location = location
        try:
            return loader.get_single_data()
        finally:
            loader.dispose()


class FSync:
    def __init__(self, context=None, logger=None):
        self.app_name = self.__class__.__name__
        self.log = logger or logging.getLogger(DEFAULT_LOGNAME)
        self._socket = self.get_abstract_socket()
        self.config_file = None
        self.transfers = []

        if context is None:
            context = {}
        start_date = arrow.now()
        context.update({
            'hostname': socket.gethostname(),   # hostname the script runs on
            '__start__': start_date,            # deprecated. use `start_date` instead.
            'start_date': start_date,           # application start date
            'arrow': arrow,                     # expose arrow library
            'env': {},                          # empty environment
        })
        assert isinstance(context['env'], dict), "'env' must be a dict"
        context['env'] = Env(context['env'])
        self.context = context
        ConfigLoader.register_constructors(self)

    def quick_transfer(self, source, destination):
        trans = Transfer(logger=self.log, context=self.context.copy())
        trans.add_source(source)
        trans.add_destination(destination)
        trans.start()

    def get_transfer_by_name(self, name):
        try:
            return next(iter(filter(lambda t: t.name == name, self.transfers)))
        except IndexError:
            raise TaskNotFound("Could not find a transfer with name '%s'" % name)

    @staticmethod
    def get_abstract_socket():
        """
        This abstract domain socket (Linux only) will be used to
        communicate between FSync processes and also to prevent multiple
        instances of main processes (thus no need of BaseApp's pid/lock
        in this project.)
        """
        assert sys.platform.startswith('linux')
        return socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    def is_running(self, scope=''):
        """
        Check if an instance of FSync is currently running.
        `scope` allows to mutex the execution within a given scope (automatically
        prepended with the application name and configuration filename(s) used)
        """
        # TODO: message process to get uptime, kill after timeout ?
        #       switching to daemon mode allows threads to use same logfiles...
        fsync_endpoint = self.app_name + str(self.config_file) + scope
        _hash = hashlib.sha1(fsync_endpoint.encode('utf-8')).hexdigest()
        try:
            self._socket.bind('\0' + _hash)
        except socket.error:
            self.log.warning("Another FSync is running. Quitting...")
            return True
        else:
            return False

    def run(self):
        if not self.is_running():
            for i, transfer in enumerate(self.transfers):
                all_ok = transfer.start()
                if not all_ok:
                    if (i + 1) < len(self.transfers):
                        self.log.error("An error prevented further transfer processing")
                    break

    def run_task(self, task_name):
        if not self.is_running(task_name):
            transfer = self.get_transfer_by_name(task_name)
            transfer.start()

    @staticmethod
    def sanitize_hooks(hooks):
        if hooks is not None:
            if isinstance(hooks, dict):
                hooks = [{k: v} for k, v in hooks.items()]
            for n, hook in enumerate(hooks):
                if isinstance(hook, str):
                    hooks[n] = {hook: None}
                elif not isinstance(hook, dict) or len(hook.keys()) > 1:
                    msg = "The `hooks` directive should be a list of single key dictionaries!"
                    raise ConfigError(msg, yaml_obj=hook)
        return hooks

    def load_config_from_yaml_string(self, s, location=None, custom_env=None):  # noqa
        # TODO: make a config parser class
        doc = ConfigLoader.load(s, location=location)
        self.log.debug("Loaded yaml document '%s'" % json.dumps(doc, indent=4))

        env = doc.pop('env', {})
        if not isinstance(env, dict):
            raise ConfigError("'env' must be a dictionary", yaml_obj=env)

        # Processing custom environments
        for key in doc:
            if key.startswith('env.'):
                i_env = doc.pop(key)
                if key.split('.').pop() == custom_env:
                    self.log.info("Merging '%s' into main environment" % key)
                    self.merge_environment(env, i_env)

        self.context['env'].__super__.update(env)

        basedir = doc.pop('basedir', env.get('basedir'))
        for old_name in ('cwd', '__cwd__'):
            if old_name in env:
                basedir = env[old_name]
                self.log.warning("env.%s is deprecated in favor of env.basedir" % old_name)

        if basedir is not None:
            try:
                os.chdir(basedir)
                self.log.info("Changed current directory to '%s'." % os.path.realpath(os.curdir))
            except Exception as e:
                raise ConfigError("Could not change directory to '%s' (%s)" % basedir, e)

        if '__hooks__' in env:
            self.log.warning("`env.__hooks__` key is deprecated. You should move this "
                             "in a `hooksdef` key located in the root of the conf file.")
            doc['hooksdef'] = env['__hooks__']
        if 'hooks' in doc:
            self.log.warning("`hooks` key is deprecated in the root of the config file. "
                             "Please rename this to `hooksdef`.")
            doc['hooksdef'] = doc.pop('hooks')

        hooks_def = doc.pop('hooksdef', None)
        if hooks_def:
            self.load_hooks_definition(hooks_def.strip())

        logging_config = doc.pop('logging', None)
        fsync = doc.pop('fsync', None)  # TODO: rename the `fsync` key as `tasks` ?
        if not isinstance(fsync, dict):
            raise ConfigError("No 'fsync' dictionary defined")

        if doc:
            # At that point, every usable key has been consumed and all
            # the remaining keys are contextually invalid
            extra_key = next(iter(doc.keys()))
            raise ConfigError("Unknown key '%s'" % extra_key, yaml_obj=extra_key)

        fsync = object_interpolate(fsync, self.context, raise_if_not_found=False)

        for name, task in fsync.items():
            if not isinstance(task, dict):
                raise ConfigError("Task '%s' is not a dict" % name, yaml_obj=task)
            logger = task.pop('logger', 'fsync.%s' % name)
            loglevel = task.pop('loglevel', 'info')
            crontab = task.pop('crontab', None)
            stop_on_error = task.pop('stop_on_error', True)
            hooks = self.sanitize_hooks(task.pop('hooks', None))

            try:
                assert 'source' in task, "Undefined source for task '%s'" % name
                trans = Transfer(
                    name=name,
                    logger=logger,
                    loglevel=loglevel,
                    context=self.context.copy(),
                    crontab=crontab,
                    hooks=hooks,
                    stop_on_error=stop_on_error)
            except Exception as e:
                raise ConfigError(str(e), yaml_obj=task)

            for key in ('source', 'destination'):
                items = task.pop(key, None)
                if not items:
                    continue
                if not isinstance(items, list):
                    items = [items]
                for item in items:
                    if isinstance(item, dict) and 'hooks' in item:
                        item['hooks'] = self.sanitize_hooks(item['hooks'])
                    try:
                        if key == 'source':
                            trans.add_source(item)
                        else:
                            trans.add_destination(item)
                    except (StringInterpolationError, InvalidEndpoint, ConnectionError) as e:
                        tb = sys.exc_info()[2]
                        exc = ConfigError(str(e), yaml_obj=item)
                        raise exc.__class__(exc).with_traceback(tb)
            self.transfers.append(trans)

        if isinstance(logging_config, dict):
            self.configure_logging(logging_config)
        elif isinstance(logging_config, str):
            self.configure_auto_logging(logging_config)

    def load_config_from_file(self, f_name, custom_env=None):
        f_name = expand_path(f_name)
        self.config_file = f_name
        config_dir = os.path.dirname(f_name)
        try:
            os.chdir(config_dir)
            with open(f_name) as f:
                content = f.read()
        except IOError:
            raise ConfigFileNotFound("Could not find configuration file '%s'" % f_name)
        self.log.info("Loading configuration file '%s'" % f_name)
        self.load_config_from_yaml_string(content, location=f_name, custom_env=custom_env)

    def merge_environment(self, env, add_env):
        for key, val in add_env.items():
            if isinstance(val, dict):
                # TODO: decide if nested dicts are supported in environment, in
                #       such case add support for an in-depth merge
                raise NotImplementedError("Nested dicts envs not (yet?) implemented")
            env[key] = val

    @staticmethod
    def load_hooks_definition(hooks_def):
        context = {}
        # TODO: try except with config line location
        if '\n' not in hooks_def and hooks_def.endswith('.py'):
            with open(hooks_def) as infile:
                exec(infile.read(), context, context)
        else:
            # TODO: save in temp file with config file offset in order to keep
            #       errors file number reporting
            exec(hooks_def, context, context)

    @staticmethod
    def configure_logging(config):
        if not isinstance(config, dict):
            raise ConfigError("'logging' config must be a dictionary")
        config.setdefault('version', 1)
        config.setdefault('disable_existing_loggers', False)

        if dry_run and 'handlers' in config:
            # In dry_run mode we will set all the handler's to StreamHandlers
            keep = ('level', 'formatter', 'filter')
            for handler in config['handlers'].values():
                for key in handler.keys():
                    if key not in keep:
                        handler.pop(key)
                handler['class'] = 'logging.StreamHandler'
                handler['stream'] = 'ext://sys.stdout'

        logging.config.dictConfig(config)

    def configure_auto_logging(self, path):
        logging.getLogger('paramiko').setLevel(logging.ERROR)

        formatter = logging.Formatter(
            fmt='%(asctime)s - %(name)s - %(levelname)-7s - %(message)s',
            datefmt='%Y/%m/%d %H:%M:%S',
        )

        root = logging.getLogger()
        for handler in root.handlers:
            handler.setFormatter(formatter)
        root.setLevel(logging.INFO)

        if dry_run:
            return

        if not os.path.isdir(path):
            self.log.info("Creating logging directory '%s'" % path)
            os.makedirs(path)

        panic = logging.FileHandler(filename=os.path.join(path, '__panic__.log'))
        panic.setFormatter(formatter)
        panic.setLevel(logging.ERROR)
        root.handlers.append(panic)

        for transfer in self.transfers:
            # TODO: set level according to command line
            logger = logging.getLogger(transfer.log.name)
            handler = logging.handlers.RotatingFileHandler(
                filename=os.path.join(path, '%s.log' % transfer.name),
                maxBytes=10485760,
                backupCount=20,
                encoding='utf8'
            )
            handler.setFormatter(formatter)
            logger.handlers.extend([handler, panic])

    def setup_crontab(self, custom_env=None):
        cfg = self.config_file
        cron = crontab.CronTab(user=True)
        cmd = os.path.realpath(sys.argv[0])
        if os.path.basename(cmd) != 'fsync' or __name__ != 'fsync.fsync':
            msg = "The crontab option should be launched from the `fsync` entry point"
            raise FSyncError(msg)
        command = "%s -c '%s' %%s &> /dev/null" % (cmd, cfg)
        for job in cron:
            if job.is_enabled() and cfg in job.command and self.app_name in job.comment:
                self.log.info("Deleting crontab [%s]" % job)
                job.delete()
        for transfer in self.transfers:
            if transfer.crontab:
                task = '--task %s' % transfer.name
                if custom_env:
                    task += ' --env=%s' % custom_env
                job = cron.new(command=command % task, comment=self.app_name)
                job.setall(transfer.crontab)
                self.log.info("Adding crontab [%s]", job)
        try:
            s_crontab = self.context['env']['crontab']
        except KeyError:
            pass
        else:
            job = cron.new(command=command % '', comment=self.app_name)
            job.setall(s_crontab)
            self.log.info("Adding global crontab [%s]" % job)
        if not dry_run:
            cron.write()

    @staticmethod
    def yaml_os_environ(node):
        """
        Returns the given key out of the os environment
        """
        if node.value not in os.environ:
            msg = "Environment variable '%s' not found."
            raise ConfigError(msg % node.value)

        return os.environ[node.value]

    @staticmethod
    def yaml_include(node):
        f_name = expand_path(node.value)
        try:
            with open(f_name) as f:
                return ConfigLoader.load(f.read(), location=f_name)
        except IOError:
            raise ConfigError(
                "Could not include file '%s'" % f_name,
                line=node.__yaml_line__,
                location=node.__yaml_location__)

    @staticmethod
    def yaml_get_environ(node):
        return os.environ.get(node.value)

    @staticmethod
    def yaml_expand_path(node):
        return expand_path(node.value)


def get_cli_options():
    parser = ArgumentParser(
        description="Synchronize files from one or more source endpoint(s)"
                    "to one or more destination endpoint(s)",
        epilog="In case of problems contact the SMI-Team."
    )
    parser.add_argument("--log-level", action="store",
                        help="Log level (Default: INFO)", default=logging.INFO)
    parser.add_argument('-c', '--config', required=False,
                        help='Specify a config file')
    parser.add_argument('-e', '--env', required=False,
                        help='Specify an alternate environment for the given config file')
    parser.add_argument('-l', '--list', required=False, action='store_true',
                        help='List defined tasks (implies config file)')
    parser.add_argument('-t', '--task', required=False,
                        help='Specify a single task to run (implies config file)')
    parser.add_argument('--crontab', required=False, action='store_true',
                        help='Setup crontab according to task probed in config file')
    parser.add_argument('-n', '--dry-run', required=False, action='store_true',
                        help='Perform a trial run without writing on remote filesystems')
    parser.add_argument("source", nargs='?')
    parser.add_argument("destination", nargs='?')

    options = parser.parse_args()

    if options.log_level not in logging._levelToName:
        parser.error("Wrong value for --log-level")

    if options.config and not os.path.isfile(options.config):
        parser.error("Could not find config file '%s'" % options.config)

    endpoints = bool(options.source and options.destination)
    has_config_file = bool(options.config)
    if options.env and not has_config_file:
        parser.error("You should specify the config file this custom environment refers to.")
    if not has_config_file and not endpoints:
        parser.print_help()
        sys.exit(0)
    elif not(has_config_file ^ endpoints):
        # python2's argparse allows mutual exclusive items but not groups of items
        parser.error("You should specify a config file or a set of endpoints, not both.")

    if (options.task or options.crontab or options.list) and not has_config_file:
        parser.error("Using --task, --crontab or --list implies usage of --config option")
    return options


def cli():
    options = get_cli_options()
    logging.basicConfig(level=options.log_level)

    global dry_run
    dry_run = options.dry_run

    fsync = FSync()
    if options.config:
        try:
            fsync.load_config_from_file(options.config, custom_env=options.env)
            if options.task:
                fsync.run_task(options.task)
            elif options.list:
                for transfer in fsync.transfers:
                    line = transfer.name
                    if transfer.crontab:
                        line += " (%s)" % transfer.crontab
                    print(line)
            elif options.crontab:
                fsync.setup_crontab(custom_env=options.env)
            else:
                fsync.run()
        except KeyboardInterrupt:
            fsync.log.error("Program interrupted by user")
            sys.exit(130)
        except (ConfigError, TaskNotFound, TransferInterrupted) as e:
            fsync.log.error(e)
            sys.exit(1)
    else:
        fsync.quick_transfer(options.source, options.destination)


if __name__ == '__main__':
    cli()
