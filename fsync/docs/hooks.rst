.. _hooks:

Hooks
=====

Transferring files happens in several stages. For each of these stages, the "system" fires an event. |br|
Hooks are implementations of functionality that can be triggered for those events, hooks are indeed callbacks for these events.

The default implementation of fsync comes with a series of predefined hooks.
The set of bundled functionality should be sufficient to cover most use-cases. One can however, for a given configuration, for a specific case, build additional hooks to be used in
his specific case, and simply include it in the config for the project.

Events
++++++

These are the events fired by the system and a description of signature of the corresponding hooks.

Callbacks are always called with at least two arguments:
The Task object
The name of the event
In addition, they are also called with the configuration settings as specified in the fsync yaml configuration file.
The signature for a callback therefore typically looks like the following:

def callback(taskobject,event,[eventspecific_parameters],config_settings):
    ...

Some events will add additional positional parameters, represented here by [eventspecific_parameters]. For details, see below

map_to_target
-------------
Map to target is called to determine the target path, which can be handy when local-folders have to be mapped different or same remote-folders.
The callback is called for each file, with two positional parameters: the FileInfo object representing the source file, and the standard remote-path of the destination.

will_start_transfer
-------------------
This event is fired when a task starts running. It can be used,e.g., to setup an environment.
This callback is not called with any event-specific parameters

transfer_finished
-----------------
Fired when a transfer finishes, can typically be used to clean up an environment. It is called without any eventspecific positional parameters

list_source_files
-----------------
This is called when files to be sent have been listed by the source-endpoint.
This event is fired when the list of source files has been determined. It is given one event_specific parameter, an iterable containing the FileInfoObjects representing the files to be listed. It expects, as return value, a new iterable with files to be sent. This can be used to filter files, walk down directory trees ...
The returned generator can yield None-values: nothing will be sent for None-values

The corresponding hook is given an iterator of fsync.FileInfo objects and is expected to return an iterable of FileInfo or None (returning None will cause the system to skip the file)

file_transferred
----------------
This event is fired when a file has been transferred. The corresponding callback is called with one file, a FileInfo object representing the destination file.
It can be used to perform additional actions on the remote file, such as changing the permissions.

archive
-------
This event is fired when a file has successfully been transferred to all destinations


Available hooks
+++++++++++++++
The system comes, standard with a series of callbacks that can be used right away.

print_files
-----------
hook_name
    print_files
event
    list_source_files
description
    As the name implies, this hook simply prints the source files

RDirLister
----------
hook_name
    RDirLister
event
     list_source_files
description
    Recursively lists contents of directories, returning only the full path of files, not the directories
    This can simplify configuration, if you don't want to specify all subdirectories

sort_by_attribute
-----------------
hook_name
    sort_by_attribute
event
    list_source_files
scope
    source
description
    Sort the files by any of the attributes in the FileInfo-objecs representing the files
     - path
     - dirname
     - basename
     - date
     - size
Configuration parameters
     - attribute (string)
     - reverse (boolean)
     - ignore_case (boolean)


sort_by_filename
----------------
hook_name
    sort_by_filename
scope
    source
event
    list_source_files
description
    Sort by filename or by a substring of the filename
Configuration parameters
   - start: (int) Position in the filename to start looking at
   - end: (int) Position in the filename to end looking at
   - reverse: (boolean)
   - ignore_case (boolean)


force_file_range
----------------
hook_name
    force_file_range
event
    list_source_files
scope
    source
description
    Trigger an error if the number of files is not within the specified range
Configuration parameters
  - minimum (int)
  - maximum (int)

limit
-----
hook_name
    limit
event
    list_source_files
scope
    source
description
    Limit the file selection to be transferred
Configuration Parameters
  - max_files: Maximum number of files to be transferred
  - max_size: Maximum sized
  - max_age: Maximum age
  - delete: Delete files that are too old on the source_system

check_free_space
----------------
hook_name
    check_free_space
event
    will_start_transfer
scope
    task
Description
    This hook registered for the `will_start_transfer` event allows to
    check the available local disk space before starting the transfer.
Configuration parameters
  - interrupt (boolean) if True, will interrupt the program in case a minimum disk space is not reached, otherwise continue to next transfer
  - paths: a dictionary where keys are paths and values are the minimum disk space required on that path for the transfer to start, this
           can be expressed in Bytes/Megabytes/Gigabytes (eg: 200M) or in percentage (eg: 5%)

changepermissions
-----------------
hook_name
    changepermissions
event
    file_transferred
scope
    destination
    Change the permissions of a remote file when it is transferred
Configuration parameters:
    - perms
        The permissions to be granted, in octal notation.
        E.g: to specify 755, you will have to specify it as 0755.
        Omitting the leading zero will yield incorrect results


pre_command
-----------
hook_name
    pre_command
event
    will_start_transfer
scope
    task
Description
    This hook will launch a subprocess before the transfer starts
Configuration parameters
   - cmd: command to execute (string or list)
   - shell: command to execute through shell (string or list)
   - encoding: charset encoding used by the program (default: UTF-8)
   - logger: optional custom logger name


post_command
------------
hook_name
    post_command
event
    transfer_finished
scope
    task
description
    This hook will launch a subprocess after the transfer is done if no error was found.
Configuration parameters
    - cmd: command to execute (string or list)
    - shell: command to execute through shell (string or list)
    - encoding: charset encoding used by the program (default: UTF-8)
    - logger: optional custom logger name
    - condition: optional boolean expression stating if the command should be executed or not


MoveArchiver
------------
hook_name
    MoveArchiver
event
    archive
scope
    source
Description
    This hook aims to replace the old implementation of archiving, moving files
    It looks for hooks configured for the event archive_filename, and if none such configured hook is found, it reverts to the old
    behaviour and configuration

RegexFMapper
------------
hook_name
    RegexFMapper
event
    - map_to_target
    - archive_filename
scope
    destination
Description
    Map source to target using regular expressions
Configuration parameters
    - pattern: pattern to look for
    - sub: the replacement

    Pattern and sub are used literally in a python re.sub-call. Please consult the documenation for python re-module to know what can be used here


NoopDirMapper
-------------
hook_name
    NoopDirMapper
scope
    destination
event
    - map_to_target
    - archive_filename
description
    This is the first in a series of directory mappers. Except that it doesn't map. As such, it is actually optional
    Eg: when the base-sourcedirectory is /local/base/path, the base-targetdirectory is /remote/base/path, a file /local/base/path/sub/file.txt, will be mapped
    to the target /remote/base/path/file.txt, in other words, the subdirectory "sub" is removed

IdentityDirMapper
-----------------
hook_name
    IdentityDirMapper
scope
    destination
event
    - map_to_target
    - archive_filename
description
    This mapper maps local subdirectories to identical remote directories
    Eg: when the base-sourcedirectory is /local/base/path, the base-targetdirectory is /remote/base/path, a file /local/base/path/sub/file.txt, will be mapped
    to the target /remote/base/path/sub/file.txt, in other words, the subdirectory "sub" is retained

YAMLTargetDirMapper
-------------------
hook_name
    YAMLTargetDirMapper
scope
    destination
event
    - map_to_target
    - archive_filename
Description
    This mapper maps local subdirectories to remote directories based on a mapping specification. The mapping can be either specified as a yaml-format mapping file, or
    inline in the configuration for the hook.
Configuration parameters
    yamlmapfile
        the filename of the YAML file containing the mapping
        The Yaml file should specify a dict, with one rootkey, the name of the rootkey doesn't matter, and under this
        rootkey, there should be a list of dicts, with the keys 'PATH' and 'REMOTE_PATH', other keys are silently ignored
        The YAML file will be automatically reloaded when it detects a change

        Eg:
        ::
             DEST_IP_TADIG:
                - PATH: cust1
                  REMOTE_PATH: mapped2_cust1
                  VAL: WTF_CUST1
                - PATH: cust2
                  REMOTE_PATH: mapped2_cust2
                  VAL: WTF_CUST2
    mapping
        Inline mapping specification, a series of key value pair

        Eg:

        ::
            fsync:
                mytask:
                  ....
                destination:
                  hooks:
                    YAMLTargetDirMapper:
                        mapping:
                            cust1: mapped_cust1
                            cust2: mapped_cust2



Please note that all the directory-mappers need some additional information, an additional configuration parameter for the source.
They need to be able to determine the 'basedirectory', relative to which filenames should be evaluated

Please note that the directory mappers can be used for multiple events, being map_to_target and archive_filename.
You can specify what event to use it for, with the configuration key:  __restrictevent__ (see examples below)




Creating custom hooks
---------------------

If the available hooks are not enough, you can opt to create custom hooks for your project.
The implementation should go in a python file that is supposed to be found alongside the configuration file for your project.
The configuration file should have a rootkey, called hooksdef, whose value is the filename of your implementation.
To know how this works,your best shot would be to look at the fsync/hooks.py file in the fsync distribution
Please be carefull, the names of your self implemented hooks should not conflict with existing hooks

Configuration
-------------

