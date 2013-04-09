keepassc and python-keepass

This provides command line and Python interfaces for reading
KeePass files (used by KeePass 1.x, and KeePassX).

* Notes of caution

Before using this code, understand its (known) security
and correctness limitations:

 * Unlike the KeePass/KeePassX GUI applications this code makes no
   attempt to secure its memory.  Input files read in are stored in
   memory fully decrypted.

 * It is quite easy to display the stored passwords in plain text,
   although the defaults try to avoid this.

 * Key files are not currently supported

* Prerequisites 

You will need to install the python-crypto package (providing the
"Crypto" module).  On a well behaved system do:

#+begin_src shell
sudo apt-get install python-crypto
#+end_src

* Command line

The command line interface is run like:

#+begin_src shell
keepassc <command> [command_options] ...
#+end_src

Examples:

#+begin_src shell
keepass dump file.kdb
keepass search hello file.kdb
#+end_src

Online help:

#+begin_src shell
keepass --help
#+end_src

* Python Modules

** Low level file access

#+begin_src python
from keepass import kpdb
db = kpdb.Database(filename,masterkey)
print db   # warning: displayed passwords in plaintext!
#+end_src

* References and Credits

** PyCrypto help

 * Main page is found through http://pycrypto.org/.  The documentation there is a start, but not enough.
 * This blog post is useful for the basics: http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto/

** The giants on whose shoulders this works stands

First, thanks to the original authors, contributors and community
behind KeePass and KeePassX.  Not, I am meerly a user of KeePassX.

A big credit is due to rudi & shirou (same hacker?) for the following:

 * http://d.hatena.ne.jp/rudi/20101003/1286111011

 * http://github.com/shirou/kptool

Looking through KeePass/KeePassX source made my head swim.  Only after
reviewing their work could I get started.
