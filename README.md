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
-   `$FLUESTERFIX_CSS`: URL to custom CSS to use.
-   `$FLUESTERFIX_LOGO`: URL to custom logo to use.
-   `$FLUESTERFIX_LOGO_DARK`: URL to custom logo in dark mode to use.
-   `$FLUESTERFIX_LABEL`: Custom alternative name for logo.

The program does not automatically remove secrets which have never been
retrieved. You might want to install a cron job on your system to remove
old directories in `$FLUESTERFIX_DATA` based on their mtime.


API
---

Post a JSON object to `/new` to create a new secret programmatically,
this object must contain a `string` typed member called `data` holding
your secret:

    $ curl -X POST https://my.ff/new -H 'Content-Type: application/json' \
        --data '{ "data": "this is my secret" }'
    {"secret_link":"https://my.ff/get/foo/bar","status":"ok"}

As you can see, you’ll get a JSON response containing the secret link.

On errors, `status` will be the string `error` and there will be an
additional field called `msg` that indicates what went wrong:

    $ curl -X POST https://my.ff/new -H 'Content-Type: application/json' \
        --data '{ "data": "" }'
    {"msg":"empty secret","status":"error"}
