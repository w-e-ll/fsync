Configuration
=============

Simple example
--------------

Here's a basic FSync configuration file::

    # basic_config.yml
    fsync:
        pull_files_from_ipbb:
            source: sftp://remote-server/apps/projects/my-project/var/tcls/*
            destination: /DWB/my_project

An FSync configuration file must always contain an ``fsync`` key in the root of
the document. This key can contain one or more :ref:`tasks` (which are most
likely a file transfer job in the context of FSync) but could also be advanced
operations that make use of the advanced :ref:`hooks` directive.

Here's how to execute a particular task in a given config file::

    $ fsync -c basic_config.yml --task=pull_files_from_ipbb

.. seealso::

    Besides the mandatory ``fsync`` key, there are some optional root keys that
    you can use to alter the behaviour of FSYnc, those are described in the
    :ref:`global_options` section.

.. _tasks:

Tasks
-----

Tasks structure
~~~~~~~~~~~~~~~

A task can be composed of the following directives:

``source``
++++++++++

The source is the only **mandatory** directive of a task and can contain one or
more :ref:`endpoints` that will specify the source files to be used. If the
content of the ``source`` directive is a list, then FSync consider it consists
of a multiple endpoints source ::

    fsync:
        my_task:
            source:
                - sftp://remote-server/apps/projects/my-project/var/tcls/*
                - /local/files/*
                - ftp://winserver/files/*


``destination``
+++++++++++++++

The destination can also contain one or more :ref:`endpoints` and will specify
where the source files should be transferred to::

    fsync:
        pull_files_from_ipbb:
            source: sftp://remote-server/apps/projects/my-project/var/tcls/*
            destination: /DWB/my_project

.. note::

    It may seem weird that the destination is optional, but the reason is that
    when it is omitted, you can still apply some operations on the sources with
    the help of hooks. This is described in the :ref:`advanced` section.

.. danger::

    FSync also support multiple endpoints destination but you should use this
    feature with extreme care because, by design, this feature will let the
    flow in an inconstant state when a transfer error occurs in the middle of
    the destination dispatching. Some hooks might also be incompatible with
    multiple endpoints destinations.


``logger``
++++++++++

By default, the name of the :class:`logging.Logger` used by a task is set to
``fsync.${ task.name }``.  This information can be changed using the logger
directive::

    fsync:
        my_task:
            source: [...]
            destination: [...]
            logger: my_custom_logger_name

``loglevel``
++++++++++++

The default log level is ``info`` but you can set it to another level through
this directive::

    fsync:
        my_task:
            source: [...]
            destination: [...]
            loglevel: debug

.. note ::

    If you need more flexibility for the logging of your tasks, please read
    the :ref:`logging` section.


``crontab``
+++++++++++


This directive is used in conjunction with the ``--crontab`` cli switch:

.. option:: --crontab

   Setup crontab according to task probed in config file

When FSync is launched with this switch (and a mandatory configuration file
specified with the ``--config`` option), it will check all the tasks which
contains the ``crontab`` directive and update the crontab entries
accordingly::

    # crontab_example.yml
    fsync:
        my_scheduled_task:
            source: [...]
            destination: [...]
            crontab: "*/5 * * * *"  # run the task every 5 minutes

Let the previous config file, the following command::

    $ fsync -c crontab_example.yml --crontab

will add the following line to the current user's cron jobs::

    */5 * * * * /full-path-to/fsync -c /full-path-to/crontab_example.yml --task my_scheduled_task &> /dev/null # FSync

``stop_on_error``
+++++++++++++++++

By default FSync consider any error to be a valid cause for the interruption
of a file transfer task. Most of the flows are meant to be atomic, this
is why this default behaviour was chosen.

The ``stop_on_error`` options allows you to prevent this behaviour by setting
it to ``false``. If you want to allow a certain amount of errors to occur
before interrupting the flow, you can assign a number to this option::

    fsync:
        my_non_atomic_task:
            source: [...]
            destination: [...]
            stop_on_error: false  # I don't care if one file is not transferred
                                  # It will be retried next time fsync run.

        my_task_prone_to_errors:
            source: [...]
            destination: [...]
            stop_on_error: 10     # If more than 10 errors occurs, interrupt
                                  # this transfer


.. warning::

    Please, keep in mind that in the yaml format you should express ``false``
    and ``true`` in lowercase! If you use python's ``False`` or ``True``, yaml
    will interpret them as strings ``"True"`` and ``"False"``.


``hooks``
+++++++++

A task can be configured to use one or more hooks, but as the hooks can be
also applied to endpoints, this feature is described in it's own section
:ref:`hooks`


Tasks Order
~~~~~~~~~~~

As stated before, an FSync configuration can contain more than one task.
More tasks can be defined as elements of the ``fsync`` root dictionary.
The order of the tasks will be preserved as FSync uses a custom yaml parser
which instantiates a :py:class:`collections.OrderedDict` for every dictionary.

This means that when FSync is launched with a config file (``-c`` switch) but
without specifying a task to be executed (no ``--task`` switch), then it will by default
ensure you that all the tasks specified in the configuration file will be
serially executed in the same order as defined in the file. FSync will also stop when one of the tasks fails.

.. code-block:: yaml

    fsync:
        step_one:
            [...]
        step_two:
            [...]
        step_three:
            [...]



.. _endpoints:

Endpoints
---------

An endpoint is a way to express a source of file(s) to work with or a final
destination for a file transfer.

Endpoints formats
~~~~~~~~~~~~~~~~~

As a string
+++++++++++

The simplest way to express an endpoint is to use a string, the format is::

    [ <SCHEME>://[ <USER> [ :<PASSWORD> ] @ ] <SERVER> ] / <PATH>

The default scheme is ``file://``, so if the scheme part is skipped altogether
then we default to a local path.

Some examples::

    fsync:
        fetch_backup:
            source: sftp://nsa.gov/archives/last_backup.tgz
            destination: /DWH/to_restore/

        why_so_sirius:
            source:
                - sftp://agr@localhost:8022/tmp/var/log/sirius_uat.log
                - ftp://marvin:IhaveAcow5@8.8.8.8/tmp/var/log/sirius_prod.log
                - /var/log/sirius.log
            destination: /DWH/sirius

As a dictionary
+++++++++++++++

If needed, a string endpoint can be decomposed into a dictionary. This is
needed if you want to use extra options that can't be expressed in the string
format (such as ``compress``, ``hooks``, ... described later) or it might just
be handy if you want more flexibility in your config in order to use
:ref:`yaml_anchors`.

Let's decompose the previous example into dictionary endpoints in order to add
some extra options::

    fsync:
        fetch_backup:
            source:
                scheme: sftp
                hostname: nsa.gov
                path: /archives/last_backup.tgz
                [...extra options...]
            destination:
                path: /DWH/to_restore/
                [...extra options...]

        why_so_sirius:
            source:
                - scheme: sftp
                  username: agr
                  hostname: localhost
                  port: 8022
                  path: /tmp/var/log/sirius_uat.log
                  [...extra options...]

                - scheme: ftp
                  username: marvin
                  password: IhaveAcow5
                  hostname: 8.8.8.8
                  path: /tmp/var/log/sirius_prod.log
                  [...extra options...]

                - path: /var/log/sirius.log
                  [...extra options...]
            destination:
                path: /DWH/sirius
                [...extra options...]

Of course, using dictionaries is more verbose but most of the time you will
use that format when you want to do more advanced configuration such as
:ref:`yaml_anchors`.

Hopefully, using extra options does not mean that the configuration should be
*that* verbose. Thanks to the ``url`` key, you can use the string format while
still being able to add extra options or even enrich the endpoint::

    fsync:
        fetch_backup:
            source:
                url: sftp://nsa.gov/archives/last_backup.tgz
                [...extra options...]
            destination:
                url: /DWH/to_restore/
                [...extra options...]

        why_so_sirius:
            source:
                - url: sftp://agr@localhost:8022/tmp/var/log/sirius_uat.log
                  [...extra options...]

                - url: ftp://8.8.8.8/tmp/var/log/sirius_prod.log
                  username: marvin      # Here's an example how you can enrich
                  password: IhaveAcow5  # the endpoint
                  [...extra options...]

                - url: /var/log/sirius.log
                  [...extra options...]
            destination:
                url: /DWH/sirius
                [...extra options...]

Globbing
~~~~~~~~

When using an endpoint as a source, you can use the star expando character
(``*``) in order to do file globing::

    fsync:
        get_all:
            source:
                - sftp://csv_factory.bc/*.csv
                - sftp://csv_factory.bc/flow/output_*_2017-07-*.csv

.. warning::

    The implementation of the glob is the same as the python's
    :py:func:`glob.glob` hence it does not take dot files by default, if you
    want to target those files you have to explicitly use ``.*``.


Extra options
~~~~~~~~~~~~~

Endpoints can use extra options in order to fine tune the file transfer
behavior. Those options can only be used in the dictionary form of an endpoint
and are simply represented as key/value items of an endpoint::

    fsync:
        source:
            url: sftp://csv_factory.bc/*.csv
            option_1: value_1
            option_2: value_2
            [...]

Some options might be restricted to either source or destination endpoints.
Here's a list of those extra options:

``overwrite``
+++++++++++++

[applies to destinations only]

By default FSync won't overwrite a file that already exist on a given
destination. In such a case, by default, FSync will consider this event as an
error. This is why you have to opt-in in order to customize this behavior by
using the ``overwrite`` option and assign it one of it's 3 possible values:

    - ``skip``
        skip the transfer to this destination, the file won't be transferred and
        no error will be triggered (only a warning).

    - ``true``
        the file will be overwritten

    - ``false``
        the file will be transferred as a new name obtained using incremental
        suffix: it will append ``.X`` between the basename and the extension of
        the filename, where ``X`` is starting at 1 and will be incremented as
        long as the filename exists on the destination)



``overwrite_suffix``
++++++++++++++++++++

[applies to destinations only]
[can use :ref:`string_interpolation`]

This option can be used in conjunction with the ``overwrite`` option defined
here before. It has no effect if ``overwrite`` is not set to ``false``.
When generating a new name for the file that has been detected as already
existing on the destination, FSync will use the value provided and insert it
between the basename and the extension of the file. Here's an example::

    fsync:
        source: sftp://csv_factory.bc/*.csv
        destination:
            url: /tmp/
            overwrite: false
            overwrite_suffix: _copy

So let's say that the file ``numplan.csv`` already exists on the destination,
with the ``overwrite_suffix`` option we used it will be transferred as
``numplan_copy.csv``.

Of course, if ``numplan_copy.csv`` itself already exists, then FSync will
switch to the default incremental suffix, hence it will continue testing
filename like this:

    - ``numplan_copy.1.csv``
    - ``numplan_copy.2.csv``
    - ``numplan_copy.3.csv``
    - ...


``delete``
++++++++++

[applies to sources only]

This option tells FSync to delete a source file after it has been successfully
transferred. ``delete`` takes a boolean value and defaults to ``false``.

.. note::

    Note that in case of multiple endpoints destination, a transfer failure in
    one of the destination causes an unsuccessful transfer, hence the file
    won't be deleted even if it was successfully transferred on other
    destinations. Again, multiple endpoint destination is not recommended.


``move``
++++++++

[applies to sources only]
[can use :ref:`string_interpolation`]

This option tells FSync to move a source file after it has been successfully
transferred. ``move`` takes a path to where the file should be moved after the
transfer. If not absolute (beginning with a ``/``) the given path is relative
to the current source file. Some examples::

    fsync:
        move_example:
            source:
                - url: sftp://server/one/two/file.csv
                  move: ../             # moved to sftp://server/one/file.csv
                - url: /logs/file.log
                  move: ./archives/     # moved to /logs/archives/file.log
                                        # /logs/archives folder will be created if needed.
                - url: /foo/bar.txt
                  move: /baz/new_bar.txt

.. note::

    When moving a file, FSync checks if the new destination exists and in such
    a case will use incremental suffix in order to generate a filename that
    does not exist. In case you prefer the file to be overwritten you can use
    the following option ``move_overwrite``

.. warning::

    The ``move`` and ``delete`` options are mutually exclusive.


``move_overwrite``
++++++++++++++++++

[applies to sources only]

When the ``move`` option is used and the move location already exists, FSync
will generate a new name so it won't overwrite the file. I you want the file
to be overwritten, just set the ``move_overwrite`` option to ``true``.


``work_path``
+++++++++++++

[applies to destinations only]
[can use :ref:`string_interpolation`]

In order to ensure atomic file transfer, FSync transfers the file to a
temporary filename first and then moves it to the final destination path once
the transfer is finished. This last move is an atomic operation on unixes file
systems.

By default the ``work_path`` is set to ``./.${__srcfile__.basename}.tmp'``.
See the :ref:`string_interpolation` section to decrypt its meaning.


``hooks``
+++++++++

An endpoint can be configured to use one or more hooks, but as the hooks can be
also applied to tasks, this feature is described in it's own :ref:`hooks`
section.


``compress``
++++++++++++

[applies to destinations only]
[can use :ref:`string_interpolation`]

FSync can compress the source files before sending them to a destination. You
can use this feature by setting the ``compress`` option to one of the
supported compressions methods:

    - gzip
    - bzip2
    - zip

Once compressed, the final destination filename will be appended with the
extension appropriate to the compression method::

    fsync:
        compress_example:
            source: /var/log/*.log
            destination:
                - url: sftp://backup.bc/logs/myfile.log
                  compress: gzip    # -> myfile.log.gz
                - url: sftp://backup.bc/logs/myfile.log
                  compress: bzip2   # -> myfile.log..bz2
                - url: sftp://backup.bc/logs/myfile.log
                  compress: zip     # -> myfile.log..zip

.. _string_interpolation:

String interpolation
--------------------

FSync allows you to use python expressions in the config through the following
syntax: ``${ expression }``. Those expressions are evaluated using a context
dictionary which is updated thorough the file transfer process.

Here's a list of keys available in the context and a hint about *when* they are
available:


``env``
~~~~~~~

This key will hold the optional user defined environment found in the
configuration file. This key is always available and it's value is an empty
dictionary in case no :ref:`environment` is set in the configuration file::

    env:
        username: agr
        host: amigrave.com

    fsync:
        get-music:
            source: sftp://${ env.username }@${ env.host }/upload/*.mp3
                    # The source will be evaluated to the following url:
                    # sftp://agr@amigrave.com/upload/*.mp3
            destination: /tmp/music/

.. note::

    Please check the :ref:`environment` section for more information about
    it's usage.


``hostname``
~~~~~~~~~~~~

The ``hostname`` key is set to the host name of the machine the script is
running on. This key is always available::

    fsync:
        copy-files:
            source: /var/log/*
            destination:
                path: /tmp/logs/
                overwrite: false
                overwrite_suffix: ${ hostname }


``start_date``
~~~~~~~~~~~~~~

This key is set to the start datetime when fsync is run. The date will be an
instance of the :py:class:`arrow.Arrow`. This key is always available::

    fsync:
        today-files:
            source: /var/log/today/*
            destination: /tmp/logs/${ start_date.format('YYYYMMDD') }/
        yesterday-files:
            source: /var/log/yesterday/*
            destination: /tmp/logs/${ start_date.replace(days=-1).format('YYYYMMDD') }/

.. note::

    For more information about :py:class:`arrow.Arrow` please consult `it's
    official api <http://crsmithdev.com/arrow/#arrow.arrow.Arrow>`_


``arrow``
~~~~~~~~~

This key will hold the ``arrow`` module itself in case you need to create
dates yourself. This key is always available.


``task``
~~~~~~~~

The ``task`` key holds an instance of the current running task, this key is
available as soon as the task is created. Please check the
:py:class:`fsync.Transfer` for more information about its properties::

    fsync:
        my-super-cool-task:
            source: /var/log/*
            destination:
                path: /tmp/tasks/${ task.name.upper() }/
                      # In this case, the effective destination will be
                      # /tmp/tasks/MY-SUPER-COOL-TASK/


``source_files``
~~~~~~~~~~~~~~~~

The ``source_files`` key will hold a list of :py:class:`fsync.FileInfo`
instances corresponding to the files that have been listed amongst the
provided sources.

This key is available when the current task has triggered the
``will_start_transfer`` event (see :ref:`hooks` for more information) and
when it has listed all the source files for all destinations. This means that
this variable can't be used in a ``will_start_transfer`` hook argument and
neither in a ``source`` directive.


``source_file``
~~~~~~~~~~~~~~~

The ``source_file`` key will hold the :py:class:`fsync.FileInfo` instance
of the current source file being transferred.

This key is available in the loop over the ``source_files`` list hence, it can
only be used in the ``destination`` directive and the ``file_transferred``
hook.


``destination_file``
~~~~~~~~~~~~~~~~~~~~

The ``destination_file`` key will hold the :py:class:`fsync.FileInfo`
instance of the current destination file to which we transfer a source file.

This key is available in the loop over the ``destination`` nested in the loop
over the ``source_files`` list, thus it can only be used in the
``file_transferred`` hook.


.. _global_options:

Global options
--------------

.. _basedir:

Basedir
~~~~~~~

By default, the current working directory is set to the configuration file
directory. This means that all relative path used in the ``source`` and
``destination`` directives will be relative to the configuration file
location.

The ``basedir`` key allows you to set the current working directory FSync
should use and it's value can be relative, absolute or can use user expandable
path such as ``~/foobar``.

Let's say your project use a such structure::

    ├── etc
    │   └── fsync.yml
    └── var
        └── fsync
            ├── incoming
            └── outgoing

By default, without basedir, the relative paths will be relative to the config
file, it means that if you want to use the ``incoming`` path you should refer
to it like this ``../var/fsync/incoming``.

With ``basedir`` you can set the current working directory to whatever you
want, meaning that you will define how relative path are resolved::

    basedir: ../  # Set the cwd to the parent directory
                  # `basedir` is a root key hence at the same level as `fsync`

    fsync:
        source: var/fsync/incoming/
        destination: var/fsync/outgoing/

or you can even go deeper if you want::


    basedir: ../var/fsync
    fsync:
        source: incoming/
        destination: outgoing/


.. _environment:

Environment
~~~~~~~~~~~

The environment is an optional ``env`` key holding a dictionary that can be
define in the config. This dictionary value will be available as an ``env``
key during :ref:`string_interpolation`::

    env:
        username: agr
        host: amigrave.com

    fsync:
        get-music:
            source: sftp://${ env.username }@${ env.host }/upload/*.mp3
                    # The source will be evaluated to the following url:
                    # sftp://agr@amigrave.com/upload/*.mp3
            destination: /tmp/music/


Alternate environments
++++++++++++++++++++++

It is also possible to use alternate environments which allows you to specify
different configuration values for different deployments (eg: production,
user testing, development, ...). This is achieved by using additional ``env``
keys with a dot (``.``) followed by an arbitrary identifier for your
environment::

    # alternate_environments.yml
    env:
        # This is the default environment. In my case I decided that it
        # would be the development/local environment
        file_sources: sftp://localhost/var/log/*

    env.uat:
        # Here I define the data source for the user testing deployment
        file_sources: sftp://uat_user:pass@csv_uat_server

    env.prod:
        # And for the production I have many sources
        file_sources:
            - sftp://prod_user:pass@csv_prod_server/var/log/*
            - sftp://prod:pass@prod_server/var/log/*
            - sftp://server3/var/log/*

    fsync:
        get_files:
            source: ${ file_sources }
            destination: /apps/incoming


By default, FSync only uses the ``env`` key for the environment and ignores
the other ``env.*`` keys. But if you use the ``--env=<identifier>`` CLI
argument, the alternate environment specified trough it's identifier will be
merged in the main environment::

    $ fsync --config=alternate_environments.yml --env=prod

The previous command will merge the ``env.prod`` environment to the main
argument.

.. _logging :

Logging
~~~~~~~

The ``logging`` optional key allows you to configure the logging behaviour of
the FSync application.

A string means that you will use the auto logging feature.

Note: If this autologging feature does not suits your need, you can manually specify your logging
      configuration with the same `logging` key but using a dictionary as a value.
      You can also include another file using the `!include` constructor eg:
        logging: !include logging.yml
