fluesterfix
===========

A simple tool for sharing secrets which will self-destruct on retrieval.


Installation
------------

You need:

-   Python 3
-   Flask
-   PyNaCl
-   shred, usually from GNU coreutils

You don’t need a database. However, this program expects to operate on a
file system that guarantees POSIX semantics.


Running
-------

For development and testing, just run the script:

    $ ./fluesterfix/__init__.py

For anything else, set up a WSGI environment. A Python package can be
installed using `pip install -e .`.

Use the following environment variables:

-   `$FLUESTERFIX_DATA`: The directory where data will be stored. Must
    exist prior to running the program. Should be created by sysadmin
    with correct permissions. Defaults to `/tmp` for quick tests.

The program does not automatically remove secrets which have never been
retrieved. You might want to install a cron job on your system to remove
old directories in `$FLUESTERFIX_DATA` based on their mtime.
