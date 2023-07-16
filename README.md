About
=====

What is FSync?
---------------

FSync is a file transfer tool tailored for data transfers amongst networks.
The philosophy of the tool is to keep things simple while providing means to
handle corner cases with the help of advanced features.


Project layout
--------------

Here's the directory structure of the FSync project::

    ├── fsync         # fsync module
    │   ├── deploy.py      # deployment helper
    │   ├── exceptions.py  # fsync exceptions
    │   ├── fsync.py       # main program
    │   ├── hooks.py       # hooks engine + default hooks definition
    │   └── utils.py       # some utility functions
    │
    ├── docs               # documentation
    │
    ├── etc                # configuration samples
    │
    ├── Makefile           # allows to launch tests and build the doc
    └── tests              # fsync tests


Usage
-----

::

    $ fsync --help

    usage: fsync [-h] [--log-level LOG_LEVEL] [-c CONFIG] [-e ENV] [-l]
                      [-t TASK] [--crontab] [-n]
                      [source] [destination]

    Synchronize files from one or more source endpoint(s)to one or more
    destination endpoint(s)

    positional arguments:
      source
      destination

    optional arguments:
      -h, --help            show this help message and exit
      --log-level LOG_LEVEL
                            Log level (Default: INFO)
      -c CONFIG, --config CONFIG
                            Specify a config file
      -e ENV, --env ENV     Specify an alternate environment for the given config
                            file
      -l, --list            List defined tasks (implies config file)
      -t TASK, --task TASK  Specify a single task to run (implies config file)
      --crontab             Setup crontab according to task probed in config file
      -n, --dry-run         Perform a trial run without writing on remote
                            filesystems

Although FSync was designed to be configuration file driven, it can be used a
as a python library or as a basic transfer proxy::

    $ fsync sftp://source-server/var/log/* sftp://dest-server/backups/


Now admittedly the previous example is not really useful as the goal of fsync
is certainly not to compete with rsync but rather is to provide a generic tool
for file transfers required by various projects.

A typical usage of fsync will likely looks like this::

    $ fsync -c etc/my-project-fsync.yml --task=pull_files_from_ipbb
