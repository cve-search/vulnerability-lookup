Installation
============

This section covers the installation steps of the sofware.

System dependencies
-------------------

You need Poetry installed, see the `install guide <https://python-poetry.org/docs/>`_.



Prerequisites
-------------

You need to have redis cloned and installed in the same directory you clone this template in:
this repository and and `redis` must be in the same directory, and **not** `redis` cloned in
this directory. See
`this guide <https://www.lookyloo.eu/docs/main/install-lookyloo.html#_install_redis>`_.

Redis
`````

`Redis <https://redis.io/>`_: An open source (BSD licensed), in-memory data structure store,
used as a database, cache and message broker.

.. note::

    Redis should be installed from the source, and the repository must be
    in one directory up as the one you will be cloning vulnerability-lookup into.

In order to compile and test redis, you will need a few packages:

.. code-block:: bash

    sudo apt-get update
    sudo apt install build-essential tcl


.. code-block:: bash

    git clone https://github.com/redis/redis.git
    cd redis
    git checkout 7.2
    make
    # Optionally, you can run the tests:
    make test
    cd ..


Kvrocks
```````

`Kvrocks <https://github.com/apache/incubator-kvrocks>`_ is a distributed key value
NoSQL database that uses RocksDB as storage engine and is compatible with Redis protocol.
Kvrocks intends to decrease the cost of memory and increase the capability while compared to Redis.

.. note::

    Kvrocks should be installed from the source, and the repository must
    be in one directory up as the one you will be cloning vulnerability-lookup into.

In order to compile kvrocks, you will need a few packages:

.. code-block:: bash

    sudo apt-get update
    sudo apt install git gcc g++ make cmake autoconf automake libtool python3 libssl-dev


.. code-block:: bash

    git clone --recursive https://github.com/apache/kvrocks.git
    cd kvrocks
    git checkout v2.9.0
    ./x.py build
    cd ..



Clone the source code
---------------------

Clone Vulnerability Lookup with the submodules.

.. code-block:: bash

    git clone --recursive https://github.com/cve-search/vulnerability-lookup.git



Installation
------------

From the directory you just cloned, run:

.. code-block:: bash

    poetry install


Initialize the `.env` file:

.. code-block:: bash

    echo VULNERABILITYLOOKUP_HOME="`pwd`" >> .env


.. note::

    `VULNERABILITYLOOKUP_HOME` is the name you set in `vulnerability-lookup/default/__init__.py`

Initialize the submodules (as the repositories are quite large, it can take sometime):

.. code-block:: bash

    git submodule update --init



Configuration
-------------

Generic configuration
`````````````````````

Copy the config file:

.. code-block:: bash

    cp config/generic.json.sample config/generic.json

And configure it accordingly to your needs.

Modules
```````

Copy the module file:

.. code-block:: bash

    cp config/modules.cfg.sample config/modules.cfg

And configure the feeder configuration such as the:

- `NVD API key <https://nvd.nist.gov/developers/request-an-api-key>`_.
- `VARIoT API key <https://www.variotdbs.pl/api/register>`_.

.. code-block:: bash

    cp config/logging.json.sample config/logging.json

Import CSAF sources
```````````````````

1. Build the `support tools <https://github.com/csaf-poc/csaf_distribution?tab=readme-ov-file#build-from-sources>`_.
2. Make sure the downloader exists:

.. code-block:: bash

    $ (git::main) ./bin-linux-amd64/csaf_downloader -h
    Usage:
    csaf_downloader [OPTIONS] domain...

    Application Options:
    -d, --directory=DIR                             DIRectory to store the downloaded files in
        --insecure                                  Do not check TLS certificates from provider
        --ignore_sigcheck                           Ignore signature check results, just warn on mismatch
        --client_cert=CERT-FILE                     TLS client certificate file (PEM encoded data)
        --client_key=KEY-FILE                       TLS client private key file (PEM encoded data)
        --client_passphrase=PASSPHRASE              Optional passphrase for the client cert (limited, experimental, see doc)
        --version                                   Display version of the binary
    -n, --no_store                                  Do not store files
    -r, --rate=                                     The average upper limit of https operations per second (defaults to unlimited)
    -w, --worker=NUM                                NUMber of concurrent downloads (default: 2)
    -t, --time_range=RANGE                          RANGE of time from which advisories to download
    -f, --folder=FOLDER                             Download into a given subFOLDER
    -i, --ignore_pattern=PATTERN                    Do not download files if their URLs match any of the given PATTERNs
    -H, --header=                                   One or more extra HTTP header fields
        --validator=URL                             URL to validate documents remotely
        --validator_cache=FILE                      FILE to cache remote validations
        --validator_preset=PRESETS                  One or more PRESETS to validate remotely (default: [mandatory])
    -m, --validation_mode=MODE[strict|unsafe]       MODE how strict the validation is (default: strict)
        --forward_url=URL                           URL of HTTP endpoint to forward downloads to
        --forward_header=                           One or more extra HTTP header fields used by forwarding
        --forward_queue=LENGTH                      Maximal queue LENGTH before forwarder (default: 5)
        --forward_insecure                          Do not check TLS certificates from forward endpoint
        --log_file=FILE                             FILE to log downloading to (default: downloader.log)
        --log_level=LEVEL[debug|info|warn|error]    LEVEL of logging details (default: info)
    -c, --config=TOML-FILE                          Path to config TOML file

    Help Options:
    -h, --help                                      Show this help message


3. Add the **full** path to the downloader in `config/generic.json` key `csaf_downloader_path`



User accounts
`````````````

Initialize the database used for the management of user accounts, comments and bundles.
``user_accounts`` must be set to ``true`` in the ``config/generic.json``
configuration file.

Create a PostgreSQL user and a database:

.. code-block:: bash

    $ sudo apt install postgresql
    $ sudo -u postgres createuser <username>
    $ sudo -u postgres createdb <database>

    $ sudo -u postgres psql
    psql (15.7 (Debian 15.7-0+deb12u1))
    Type "help" for help.
    postgres=# alter user "<username>" with encrypted password '<password>';
    ALTER ROLE
    postgres=# grant all privileges on database <database> to "<username>";
    GRANT
    postgres=# ALTER DATABASE <database> OWNER TO <username>;
    ALTER DATABASE


Initialize the database:

.. code-block:: bash

    $ poetry run flask --app website.app db_init # initializes the databse
    $ poetry run flask --app website.app db stamp head # add alembic_version table to the database and point to the most recent version


After creating the database, you can proceed to create the first admin user:

.. code-block:: bash

    $ poetry run flask --app website.app create_admin --login admin --email admin@example.org --password adminPassword


Usage
-----

Start the tool (as usual, from the directory):

.. code-block:: bash

    poetry run start

You can stop it with:

.. code-block:: bash

    poetry run stop

With the default configuration, you can access the web interface on http://0.0.0.0:10001,
where you will find the API and can start playing with it.

Update the tool:

.. code-block:: bash

    poetry run update


Launching the website with systemd
----------------------------------

.. note::

    This is an alternative method. The website will be automatically launched with the ``start`` command.

Create a file ``/etc/systemd/system/vulnerability-lookup-web.service`` with the following contents:

.. code-block:: ini

    [Unit]
    Description=Vulnerability Lookup webservice
    After=network.target

    [Service]
    User=<system user used to install Vulnerability Lookup>
    Group=<group of the user used to install Vulnerability Lookup>
    WorkingDirectory=<path to the directory where you cloned the repository>
    Environment=PATH="<path-of-the-virtualenv>/bin/:/usr/bin"
    ExecStart=/bin/bash -c "run_backend --start ; start_website"
    ExecStop=/bin/bash -c "run_backend --stop"

    [Install]
    WantedBy=multi-user.target


.. code-block:: bash

    $ sudo systemctl daemon-reload
    $ sudo systemctl enable vulnerability-lookup-web.service
    $ sudo systemctl start vulnerability-lookup-web.service
    $ systemctl status vulnerability-lookup-web.service
