keepassc and python-keepass

This provides command line and Python interfaces for operating on
files in KeePass format v3 (used by KeePass 1.x, and KeePassX).

* Notes of caution

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
keepassc [general_options] [command command_options] ...
#+end_src

Multiple commands can be specified and will be executed in order.
They operate on an in-memory instance of the database file.  An
example, 

#+begin_src shell
keepass open -m secret file.kdb \
        dump -p -f '%(username)s password is: %(password)s' \
        save -m newsecret backup.kdb
#+end_src

Online help:

#+begin_src shell
keepass -h      # short usage
keepass help    # full usage
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
