CRyptographic Administration SHell -- crash
===========================================


Build
-----

You need to have a quite current version of _openssl_ instelled.
The, just

    $ make

for Linux, and

    $ make -f Makefile.bsd

for BSD etc. For embedded systems please see at the end of this document.
_crash_ was successfully tested on Linux (openSUSE 10.3, 11.1, 12.3, 13.1),
FreeBSD 7.2, OpenSolaris and OSX 10.8. It probably runs on a lot of other Linux
and BSD's but I was not able to test it there yet.

To generate server and authentication keys:

    $ make keys

or see further instructions in this document. If you want to use _ephemeral keying_
(aka [PFS](http://en.wikipedia.org/wiki/Perfect_Forward_Secrecy)),
invoke

    $ ./newdh

before `make`_ in order to generate DH parameters before the build.


Run
---

_crash_ does not need any config or option files to run. Its easy and
straight forward to use. Anything can be enabled/disabled/featured by
runtime switches:

```
stealth@linux ~> ./crashd -h
./crashd: invalid option -- h

Usage:  ./crashd [-U] [-q] [-a] [-6] [-w] [-H host] [-p port] [-A authorized keys]
                 [-k server key-file] [-c server X509 certificate]
                 [-t trigger-file] [-m trigger message] [-e] [-g good IPs]

                 -a -- always login (if authenticated), even with a /bin/false default shell
                 -U -- run as user (e.g. turn off setuid() calls) if invoked as such
                 -e -- extract key and certfile from the binary itself (no -k/-c needed)
                 -q -- quiet mode, turns off logging and utmp entries
                 -6 -- use IPv6 rather than IPv4
                 -w -- wrap around PID's so crashd appears in system PID space
                 -H -- host/IP to connect to; if omitted it uses passive connect (default)
                 -p -- port to connect/listen to; default is 2222
                 -P -- local port used in active connects (default is no bind)
                 -g -- file containing list of good IP/IP6's in D/DoS case (default off)
                 -A -- authorized-key files for users if starts with '/'; subdir in users ~
                       containing authorized_keys file otherwise; 'self' means to use
                       blob-extraction (see -e); default is .crash
                 -k -- servers key file; default is ./serverkey.pem
                 -c -- X509 certificate-file that belongs to serverkey (-k); default is ./pubkey.x509
                 -t -- watch a triggerfile for certain message (-m) before connect/listen
                 -m -- wait with connect/listen until message in file (-t) is seen

```

Most of it is pretty self-explaining. _crashd_ can run as user. `-U` makes
it skipping apropriate _setuid()_ calls, effectively being able to run as user.
It only accepts logins to that user then by checking login name's UID against
current EUID.
Both, _crashc_ and _crashd_ can use active and passive connect. Whenever
a host-argument `-H` is given, it uses active connect to this host
and the belonging port `-p`. If `-H` is given, it also accepts
`-P` which specifies the local port it has to bind to before
doing active connect.
If `-w` is used it forks itself as __[nfsd]__ and tries to wrap around its
PID to be somewhere around the system daemons. This can take a while!

Key setup
---------

The easiest way is to just

    $ make keys

But you can also do it by hand. To generate a X509 certificate containing the server key:

    $ umask 066
    $ openssl genrsa -out serverkey.pem 4096
    $ openssl req -new -x509 -nodes -sha1 -key serverkey.pem -out pubkey.x509

To extract the public key in a form _crashc_ can use it as a hostkey for comparison:

    $ openssl x509 -in pubkey.x509 -pubkey -noout > HK_127.0.0.1

So you have `HK_127.0.0.1` as the known-hosts keyfile for this host.
As an alternative, you can use _crashc_ with `-v` upon connect to
extract the pubkey. But note that this might already be a key presented to
you during an attack. So only do that if you know that the connection is
not tampered with (e.g. single user on localhost).

The values you enter for __Country-Name__, __Email__, __CN__ etc. do not matter
since _crashc_ is not validating the X509. Rather it compares the public
key it obtained from the server with the key it has in its local
key-store belonging to that server (similar to _SSH_). That way,
_crashc_ cannot fall into the common X509 traps like a lot
of web browsers do.
The server key is not encrypted since _crashd_ is usually started
via init scripts. Rather, the key file must have proper permissions
so only apropriate users can read it (mode 0600). You can, if you like,
also encrypt the server key but then you have to enter a passphrase
whenever _crashd_ is started.

To generate a public/private RSA keypair for your authentication:

    $ openssl genrsa -out privkey.pem -aes256 4096
    $ openssl rsa -in privkey.pem -pubout -out pubkey.pem

Copy `pubkey.pem` to `~/.crash/authorized_keys` on the remote box, and
use `privkey.pem` for the `crashc -i` argument.

Auth-Key sizes larger than __7500 bit__ must not be used;
the tokens do not fit into the auth handshake otherwise.

_crashc_ is using the `.crash/` subdir by default to check for
already seen server keys. If you connect to a host via `-H $host -p $port`
then a keyfile of form `.crash/HK_$host:$port` is looked up unless
you specify a path to a known keyfile.

CGI
---

_crashd_ automatically detects whether it has been invoked as a CGI by
a webserver by checking __$QUERY_STRING__ environment variable. It parses
and converts the query-string into arguments it understands. It
does not translate %2F etc characters! They should not be needed,
since spaces, '(' and other weird characters do not make sense when
calling crashd. Arguments that dont have a parameter such as -U
have to be given "=1" argument to enable it, such as in:

```
http://127.0.0.1/cgi-bin/crashd?-K=/path/to/serverkey.pem&    \
      -C=/path/to/pubkey.x509&-p=1234&-A=/tmp/.crash/authorized_keys&-U=1&-a=1
```

which invokes _crashd_ on the host 127.0.0.1 as user (probably "wwwrun" or whatever
the webserver is running as).
For pentesting or embedded/emergency systems, crashd has the `-e` option.
If `-e` is used, it extracts the server key-file and the X509 certificate
from the ELF binary file, which have to be appended first:

    $ cat serverkey.pem>>crashd
    $ cat pubkey.x509>>crashd

If you give `-A self` instead of a valid authentication directory or file,
it also extracts the user-key used for authentication from its binary.
It has to be appended in the same manner as above. This is useful in pentests
where you cannot upload arbitrary amount of files or do not know the
exact pathname of the upload storage:

    $ curl 'http://127.0.0.1/cgi-bin/crashd?-A=self&-U=1&-e=1&-a=1'

`-a` is needed since most likely the _wwwrun_ user has a _/bin/false_ shell,
which `-a` ignores.
_crashd_ is using _mkstemp()_ to store the key files temporarily, with
mode 0444 (world readable!) since it needs to access authentication
files as user. So be warned that, if you have users, they may read
the private key used during SSL handshake. After all, its just an
emergency mode!!! Stripping the _crashd _binary is not possible after
appending the keys, or they will get lost.
Back-connect etc. also work in CGI mode as well.
If using that, client should use `-K` switch to tell client which key to use
to authenticate the server.



cross-build for speedport/fritzbox DSL routers
----------------------------------------------

In Germany, these devices are quite common and support open build
environment/SDK since the firmware is based on Linux and available
in source. Download/unpack the SDK/tarball and the MIPS toolchain. I assume you
are familar with building router images for these devices. The openssl
package for the speedport __W-500V__ I tested has version 0.9.7 and I had
to build it by hand before, so the references to the _libssl.a_
inside crash Makefile are valid. On the system I tested (500V)
I had to make it static, since dynamic openssl library requires _libdl_
which was not on the device. Building a firmware image often
calls strip on the user binaries, so take care it doesnt
strip off the embedded keys if using `-e`.


Then, inside  `userapps/opensource/` directory, unpack the crash tarball,
edit the `Makefile` to match "true" at the first _ifeq()_ and then you are able
to just "make crashd" to build crashd for the DSL router.

You can now put it into the firmware image, make it loaded at boot and you
are able to admin your DSL box from remote via full protected crypto shell
and without stupid web interface.


Here's how I connect to a 500V DSL modem running crashd inside:

```
stealth@linux ~> ./crashc -l root -H 192.168.2.1 -K .crash/HK_127.0.0.1\:2222 -v  \
                          -i privkey.pem -c '/bin/sh -i'
crash: starting crypted administration shell
crash: connecting to 192.168.2.1:2222 ...
Enter PEM pass phrase:
crash:{
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA4PKEDfrj1v1RlK307j1o
JX9aUuadp3KjGqs2gpoxYTuYf8oBh+1qhwbsH5wC1oQ4HerlIAfLFfUL0+yjy1BO
jNW/4sCo3QSxByRC9DORmfADrxJYkWjyC+cgdXCRaudYBLsz4oIDbg6B8Gtzma8c
ifFPUuSfEoLMRlQOSBIr15WzjS9/wIJfU+D0maJAFRySvVhcRQEbQZ5uuhLnmf4R
zEEiVV+HU79AfhuaKjs1gnTCZwj/dUmsD2zNjHuU6bZpjiQlQdkXLKe2wTvvYFQL
pbmx/XEapoW+tes9pbGgkFIs0jQLz/xYB07luUy46teVAVyB70R7l/WDyFpocPwW
seLNINDUKTvN6vo4UJD9tg1xhClim+P8Jnkyh5X5MqSdXwYC4N/FQsGs223jtxY2
XvQNPBR06d8HJu66GCDSTy7jKKARQ3c3Odq87JDOquUntR1pg26Dj3lOHWVQpuof
7jZ6vLyivpnh4JcdBgGTkzC+Ua0VE1tlokl58+FjhkIbeijD6FK+xcUNaylRo9YM
TrHjBnCi9FIb85WfBo1pj+basKAM85+BkFX3sLC+HR62CL1qJKue7qDBMJbK4INx
ZvoDpdJyBRZXLx+lGisasT3zgNDjJAjSWYn5bY1FfTMBZbvhZyN2/5Uxe85VicUV
8NS0w2TCghjgA0B+hiln1mMCAwEAAQ==
-----END PUBLIC KEY-----
crash:}
Using fallback suid method
Using fallback suid method


BusyBox v1.00 (2008.06.03-09:17+0000) Built-in shell (msh)
Enter 'help' for a list of built-in commands.

# ps aux
 [...]
  206 root       1712 S   httpd
  210 root        232 S   smdog 
  520 root       1160 S   /bin/crashd -A /var/pubkey.pem 
  546 root       1464 S   /bin/crashd -A /var/pubkey.pem 
  561 root        352 S   /bin/sh -c /bin/sh -i 
  562 root        396 S   /bin/sh -i 
  715 root        340 R   ps aux 
#
```

Keep in mind that on embedded systems, UNIX98 pty's are often not available and
there are only a limited number of BSD pty's (2 or so) so you cant login a hundred
times simultaneously.


DoS mitigation
--------------

_crashd_ includes some sort of D/DoS protection. Only one connection per second
is allowed per IP, except if the IP is listed (or the network it belongs to)
in a good-IP file given with -g at startup.
Per default no good IPs are assigned. Network-address-goodness only works with
IPv4 yet. A simple good-IP file may look like this:


    # sample good-IP file
    192.168.3.1
    192.168.2.0
    10.0.0.0
    fe80:216::1234
    # end of file

Together with the interval timer for hanging un-authenticated
connections this allows to have no more than 12 'hanging'
crashd's at the same time, still allowing you to login
if you are listed in good-IPs and your underlying TCP/IP stack
is not already trashed.


