# keepassc and python-keepass

This provides command line and Python (both 2 and 3) interfaces for operating on
files in KeePass format v3 (used by [KeePass](http://keepass.info/)
1.x, and [KeePassX](http://www.keepassx.org/)).  Note, this is not the
format used by the KeePass application version 2.x.

## Notes of caution

Before using this code, understand the its (known) security
and correctness limitations:

 * Unlike the KeePass/KeePassX GUI applications this code makes no
   attempt to secure its memory.  Input files read in are stored in
   memory fully decrypted.

 * It is quite easy to display the stored passwords in plain text,
   although the defaults try to avoid this.

 * Specifying the master key on the command line will leave traces in
   your shells history and in the process list.

 * While input files are treated as read-only, keep backups of any
   files written by KeePass/KeePassX until you are assured that files
   written by this code are usable.

 * Key files are not currently supported.

## Prerequisites and Installation

You will need to install the python-crypto package (providing the
"Crypto" module).  On a well behaved system do:

```shell
sudo apt-get install python-crypto
```

If installing into a [virtualenv](http://www.virtualenv.org) this prerequisite will be installed for you:

```shell
virtualenv /path/to/venv
source /path/to/venv/bin/activate
cd python-keepass
python setup.py install
```


## Command line

The command line interface is run like:

```shell
keepassc [general_options] [command command_options] ...
```

Multiple commands can be specified and will be executed in order.
They operate on an in-memory instance of the database file.  An
example, 

```shell
keepass open -m secret file.kdb \
        dump -p -f '%(username)s password is: %(password)s' \
        save -m newsecret backup.kdb
```

Online help:

```shell
keepass -h      # short usage
keepass help    # full usage
```

## Python Modules

### Low level file access

```python
from keepass import kpdb
db = kpdb.Database(filename,masterkey)
print db   # warning: displayed passwords in plaintext!
```

# References and Credits

## PyCrypto help

 * Main page is found through <http://pycrypto.org/>.  The documentation there is a start, but not enough.
 * This blog post is useful for the basics: <http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto/>

## The giants on whose shoulders this works stands

First, thanks to the original authors, contributors and community
behind KeePass and KeePassX. I am merely a user of KeePassX.

A big credit is due to rudi & shirou (same hacker?) for the following:

 * <http://d.hatena.ne.jp/rudi/20101003/1286111011>
 * <http://github.com/shirou/kptool>

Looking through KeePass/KeePassX source made my head swim.  Only after
reviewing their work could I get started.

## License

This package is Free Software licensed to you under the GPL v2 or
later at your discretion. See the [LICENSE.txt](LICENSE.txt) file for details.
