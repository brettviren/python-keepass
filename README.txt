keepassc

a command line interface for reading
KeePass files (used by KeePass and KeePassX v2.x).

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

#+begin_src shell
sudo pip install libkeepass
#+end_src

* Command line

The command line interface is run like:

#+begin_src shell
keepassc <command> [command_options] ...
#+end_src

Examples:

#+begin_src shell
keepassc dump file.kdbx
keepassc search hello file.kdbx
#+end_src

Online help:

#+begin_src shell
keepassc --help
#+end_src
