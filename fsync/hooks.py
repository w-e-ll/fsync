#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import tempfile
import time
from collections import defaultdict
from copy import deepcopy
from functools import wraps
from logging import getLogger

from .exceptions import TransferInterrupted, HookError
from .utils import human_bytes, safe_eval

# from .exceptions import HookError  # TODO: alarming stuff


log = getLogger('fsync')
_registry = defaultdict(dict)


HUMAN_SIZE_UNITS = {
    'B': 1,
    'K': 1024,
    'M': 1024 * 1024,
    'G': 1024 * 1024 * 1024,
}


def register(event):
    def wrapper(fn):
        # TODO: add an override argument to register, should not override func_name
        #       except when override=True
        log.debug("Registering hook '%s' for event '%s'." % (fn.__name__, event))
        _registry[event][fn.__name__] = fn
        return fn
    return wrapper


def trigger_event(event, transfer, hooks_conf):
    """
    Get hooks that are registered for a particular event and wrap them
    in a function that will take cake of the exception handling.
    """
    if not hooks_conf:
        return

    registered_hooks = _registry.get(event, [])

    for hook_conf in hooks_conf:
        hook_name, hook_kwargs = next(iter(hook_conf.items()))
        hook_kwargs = deepcopy(hook_kwargs)

        if hook_name in registered_hooks:
            if hook_kwargs is None:
                hook_kwargs = {}
            else:
                for k, v in hook_kwargs.items():
                    # Interpolate hook string kwargs
                    # TODO: currently does not support nested structure
                    if isinstance(v, str):
                        hook_kwargs[k] = transfer.eval(v)
            fn = registered_hooks[hook_name]

            @wraps(fn)
            def hook(*args):
                try:
                    transfer.log.debug("Triggering hook '%s' for event '%s'" % (hook_name, event))
                    # Actual execution of hook is here
                    f_args = [transfer]
                    f_args.extend(args)
                    transfer.log.debug("Hook '%s' will be triggered with *args=(%r) and **kwargs=(%r)"
                                       % (hook_name, f_args, hook_kwargs))
                    return fn(*f_args, **hook_kwargs)
                except Exception as e:
                    if isinstance(e, (AssertionError, TransferInterrupted, HookError)):
                        transfer.log.debug(e, exc_info=True)
                    else:
                        transfer.log.info(e, exc_info=True)
                    raise TransferInterrupted("Hook '%s' raised a %r" % (hook_name, e), yaml_obj=hook_conf)

            yield hook


@register('list_source_files')
def print_files(_transfer, _files, debug=False):
    """
    A simple hook for debugging purpose
    """
    _files = list(_files)
    for f in _files:
        print(f)
    return _files


@register('list_source_files')
def sort_by_attribute(_transfer, _files, attribute, reverse=False, ignore_case=False):
    """
    This hook registered for the `file_transferred` event allows to sort
    the files by using any `FileInfo` attribute.

    :param _transfer: current transfer object
    :param _files: generator or list of files listed by the endpoint
    :param attribute: the attribute to use for the sort (see `FileInfo`)
    :param reverse: reversed sort if True
    :param ignore_case: ignore_case when sorting for string attributes
    """
    def fn(fi):
        r = getattr(fi, attribute)
        if ignore_case and isinstance(r, str):
            r = r.lower()
        return r
    return sorted(_files, key=fn, reverse=reverse)


@register('list_source_files')
def sort_by_filename(_transfer, _files, start=None, end=None, regex=None, reverse=False, ignore_case=False):
    """
    This hook registered for the `file_transferred` event allows to sort
    the files by filename or filename fragments.

    :param _transfer: current transfer object
    :param _files: generator or list of files listed by the endpoint
    :param start: will sort using a fragment starting at this position
    :param end: will sort using a fragment ending at this position
    :param regex: will sort using a regex match
    :param reverse: reversed sort if True
    :param ignore_case: ignore_case when sorting for string attributes
    """
    def fn(fi):
        if start is None and end is None and regex is None:
            r = fi.basename
        elif regex is not None:
            raise NotImplementedError()
        elif start is None:
            r = fi.basename[:end]
        elif end is None:
            r = fi.basename[start:]
        else:
            r = fi.basename[start:end]
        if ignore_case:
            r = r.lower()
        return r
    return sorted(_files, key=fn, reverse=reverse)


@register('list_source_files')
def force_file_range(_transfer, _files, minimum, maximum):
    """
    This hook is registered for the `list_source_files` event and will
    trigger an AssertionError if the number of files is not in the range
    defined by the minimum and maximum arguments.

    Note: in order to get the number of files we explicitly consume the
          file-list generator thus creating a lag before the transfer actually
          starts.

    :param _transfer: current transfer object
    :param _files: generator or list of files listed by the endpoint
    :param minimum: minimum number of files that should be present
    :param maximum: maximum number of files that should be present
    :returns: the list of files consumed by the original `files` generator
    :raises AssertionError: if number of files is out of range
    """
    _files = list(_files)  # we consume the possible generator received
    n_files = len(_files)
    if minimum == maximum != n_files:
        raise AssertionError("We were expecting exactly %s files. Got %s instead." % (minimum, n_files))
    elif n_files < minimum:
        raise AssertionError("We were expecting at least %s files. Got %s instead." % (minimum, n_files))
    elif n_files > maximum:
        raise AssertionError("We were expecting at most %s files. Got %s instead." % (minimum, n_files))
    return _files


@register('list_source_files')
def limit(_transfer, _files, max_age=None, max_files=None, max_size=None, delete=False):
    """
    This hook registered for the `list_source_files` event allows to limit the file
    selection to transfer.

    :param _transfer: current transfer object
    :param _files: generator or list of files listed by the endpoint
    :param max_files: maximum number of files to transfer
    :param max_size: maximum transfer size (can be expressed in
                     Bytes/Megabytes/Gigabytes (eg: 200M)
    :param max_age: the maximum age of the files to be sent, expressed in seconds
    :param delete: delete files that are not retained
    :returns: the list of files consumed by the original `files` generator
    """
    _files = list(_files)  # consume the potential generator received
    res = []
    if max_size:
        try:
            max_size = int(max_size)
        except ValueError:
            max_size = int(max_size[:-1]) * HUMAN_SIZE_UNITS[max_size[-1]]

    files = size = 0
    for f in _files:
        next_size = size + f.size
        keep = True

        if max_size and next_size > max_size:
            _transfer.log.info("%s size limit reached" % human_bytes(max_size))
            break

        size = next_size
        files += 1

        if max_files and files == max_files:
            _transfer.log.info("%d files limit reached" % max_files)
            break
        if max_age is not None:
            max_age = int(safe_eval(str(max_age), _transfer.context))
            if max_age and time.time() - f.stat.st_mtime > max_age:
                log.debug('Maximum age = %s' % max_age)
                keep = False

        if keep:
            res.append(f)
        else:
            if delete:
                _transfer.log.info("Removing %s", f.path)
                f.endpoint.remove(f.path)

    return res


@register('will_start_transfer')
def check_free_space(_transfer, interrupt=True, **paths):
    """
    This hook registered for the `will_start_transfer` event allows to
    check the available local disk space before starting the transfer.

    FSync will not auto-detect the task's destination path because string
    interpolation might render that impossible (not even talking about
    0 and multiple destinations cases) thus you have to explicitly provide
    the path.

    :param _transfer: current transfer object
    :param interrupt: if True, will interrupt the program in case a minimum
                      disk space is not reached, otherwise continue to next transfer.
    :param paths: a dictionary where keys are paths and values are the minimum
                  disk space required on that path for the transfer to start, this
                  can be expressed in Bytes/Megabytes/Gigabytes (eg: 200M) or
                  in percentage (eg: 5%)
    :returns: True if the transfer can start, False otherwise
    """
    do_transfer = True
    for path, minimum in paths.items():
        min_bytes = min_percent = None
        try:
            min_bytes = int(minimum)
        except ValueError:
            value = float(minimum[:-1])
            unit = minimum[-1]
            if unit == '%':
                min_percent = value
            else:
                min_bytes = value * HUMAN_SIZE_UNITS[unit]

        stat = os.statvfs(path)
        avail = stat.f_frsize * stat.f_bavail
        full = stat.f_frsize * stat.f_blocks
        if min_percent:
            min_bytes = full / 100 * min_percent
        if avail < min_bytes:
            msg = (
                "Minimum disk space of %s not fulfilled for path '%s'. "
                "(Remaining %s of %s)" % (minimum, path, human_bytes(avail), human_bytes(full)))
            if interrupt:
                # In this case, the program will be interrupted, following transfers won't be processed
                _transfer.interrupt(msg)
            _transfer.log.error(msg)
            do_transfer = False
    return do_transfer


@register('file_transferred')
def hard_link(_transfer, dst_file, path, overwrite=True):
    """
    This hook registered for the `file_transferred` event allows to
    hard link a local destination file just after it has been transfered.

    If a file already exists with the same link path it will be overwritten
    (except if `overwrite` is False).

    :param _transfer: current transfer object
    :param dst_file: destination file that just has been transfered
    :param path: hard link path
    :param overwrite: overwrite in case hard link path already exists
    :raises AssertionError: if the hard link creation failed
    """
    if dst_file.endpoint.is_remote:
        raise NotImplementedError("hard_link hook cannot operate on non remote endpoints")

    if overwrite and os.path.exists(path):
        _transfer.log.info("Unlinking existing path '%s'" % path)
        os.unlink(path)
    _transfer.log.info("Hard linking '%s' -> '%s'" % (dst_file.path, path))
    os.link(dst_file.path, path)


@register('will_start_transfer')
def create_test_files(task):
    """
    WIP: This creates test file for the TODO test suite
    """
    tmp = tempfile.NamedTemporaryFile(delete=False, mode="w")
    tmp.write("Hello, I'm a test file. What's your name ?")
    tmp.close()
    for source in task.sources:
        task.log.info("Generating test files for '%s'..." % source.url)
        files = []
        for n in range(1, 10):
            dst_path = source.path.replace('*', 'test-%02d' % n)
            dirname = os.path.dirname(dst_path)
            filename = os.path.basename(dst_path)
            final_dst = source.get_destination_filepath(dirname, filename)
            if final_dst not in files:
                files.append(final_dst)
                source.upload(tmp.name, final_dst)
    os.unlink(tmp.name)


@register('will_start_transfer')
def pre_command(_transfer, cmd=None, shell=None, encoding='UTF-8', logger=None):
    """
    This hook will launch a subprocess before the transfer starts

    :param _transfer: current transfer object
    :param cmd: command to execute (string or list)
    :param shell: command to execute through shell (string or list)
    :param encoding: charset encoding used by the program (default: UTF-8)
    :param logger: optional custom logger name
    """
    if not bool(cmd) ^ bool(shell):
        raise HookError("You must provide a `cmd` OR a `shell` argument")
    cmd = cmd or shell
    shell = bool(shell)
    _transfer.subprocess(cmd, shell=shell, encoding=encoding, logger=logger)


@register('transfer_finished')
def post_command(_transfer, cmd=None, shell=False, encoding='UTF-8', logger=None, condition=None):
    """
    This hook will launch a subprocess after the transfer is done if no error was found.

    :param _transfer: current transfer object
    :param cmd: command to execute (string or list)
    :param shell: command to execute through shell (string or list)
    :param encoding: charset encoding used by the program (default: UTF-8)
    :param logger: optional custom logger name
    :param condition: optional boolean expression stating if the command
                      should be executed or not
    """
    if _transfer.errors and condition is None:
        _transfer.log.info("By-passing post_command because %d error(s) were found" % _transfer.errors)
        return
    if condition is not None:
        if not safe_eval(str(condition), _transfer.context):
            _transfer.log.info("By-passing post_command due to condition `%s`" % condition)
            return
    if not bool(cmd) ^ bool(shell):
        raise HookError("You must provide a `cmd` OR a `shell` argument")
    cmd = cmd or shell
    shell = bool(shell)
    _transfer.subprocess(cmd, shell=shell, encoding=encoding, logger=logger)
