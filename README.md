fluesterfix
===========

A simple tool for sharing secrets which will self-destruct on retrieval.


Installation
------------

You need:

-   Python 3
-   Flask
-   PyNaCl

You don’t need a database. However, this program expects to operate on a
file system that guarantees POSIX semantics.


Running
-------

For development and testing, just provide a key and run the script:

    $ export FLUESTERFIX_KEY=$(printf 'a%.s' $(seq 32) | base64)
    $ ./fluesterfix/__init__.py

For anything else, set up a WSGI environment. A Python package can be
installed using `pip install -e .`.

Use the following environment variables:

    - `$FLUESTERFIX_KEY`: 32 bytes that will be used to encrypt secrets as
      long as they’re stored on disk. Base64 encoded to allow you to
      pass truly random values. **Required.**
    - `$FLUESTERFIX_DATA`: The directory where data will be stored. Must
      exist prior to running the program. Should be created by sysadmin
      with correct permissions. Defaults to `/tmp` for quick tests.

The program does not automatically remove secrets which have never been
retrieved. You might want to install a cron job on your system to remove
old directories in `$FLUESTERFIX_DATA` based on their mtime.
