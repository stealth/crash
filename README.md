CRypted Admin SHell
===================

<p align="center">
<img src="https://github.com/stealth/crash/blob/master/logo.jpg" />
</p>

* IPv6 ready
* lightweight, straight forward and extensible protocol using TLS 1.2+
  as transport layer
* man-in-the-middle safe due to its authentication mechanism
  which involves the servers host key into the auth process
* built-in traffic analysis mitigation for timing and packet sizes
* not relying on any system auth frameworks such as PAM
* can be entirely run as user, no need to setup config files
* passive/active connects on both ends with most flexible
  local/remote port binding possibilites
* easy to port to embedded systems such as routers
* quiet/hidden mode for secret administration and take-back
  functionality for owned boxes
* trigger-mode via syslog, mail or other files if requested
* emergency mode to extract all necessary key files from the running binary
* may be started as a CGI with all above functionality, command
  switches passed via query-string
* integrated tcp-wrapper-like D/DoS protection
* intentionally not passing local $ENV to remote to avoid info leaks
* supports Perfect Forward Secrecy via DH Kex
* can forward TCP *and* UDP sockets to remote
* SOCKS4 and SOCKS5 support to forward browser sessions to remote


Build
-----

You need to have a reasonable version of *OpenSSL* installed. Inside the cloned git repo:

```
$ make -C src
```

On BSD systems you need to install *GNU make* and type `gmake` instead.

If you have a particular *OpenSSL* or *LibreSSL* setup, check the `Makefile` and
set the apropriate `$SSL` variable. *crash* builds also nicely with *LibreSSL* and *BoringSSL*.

For embedded systems, please see at the end of this document.

For Android, edit the `Makefile.android` or `Makefile.android.aarch64` to reflect
your NDK and *BoringSSL* install and use these.

*crash* was successfully tested on *Linux, FreeBSD, NetBSD, OpenSolaris, OSX and Android*.

After that, to generate the required server and authentication keys:

```
$ make -C src keys
```

or see further instructions in this document. If you want to use _ephemeral keying_
(aka [PFS](http://en.wikipedia.org/wiki/Perfect_Forward_Secrecy)), invoke

```
$ cd src; ./newdh
```

before `make` in order to generate DH parameters before the build.


Run
---

*crash* does not need any config or option files to run. Its easy and
straight forward to use. Anything can be enabled/disabled by
runtime switches:

```
stealth@linux ~> ./crashd -h

crypted admin shell (C) 2021 Sebastian Krahmer https://github.com/stealth/crash

./crashd: invalid option -- 'h'

Usage:	./crashd [-U] [-q] [-a] [-6] [-w] [-H host] [-p port] [-A auth keys]
	 [-k server key-file] [-c server X509 certificate] [-P port]
	 [-t trigger-file] [-m trigger message] [-e] [-g good IPs]

	 -a -- always login if authenticated, despite false/nologin shells
	 -U -- run as user (e.g. turn off setuid() calls) if invoked as such
	 -e -- extract key and certfile from the binary itself (no -k/-c needed)
	 -q -- quiet mode, turns off logging and utmp entries
	 -6 -- use IPv6 rather than IPv4
	 -w -- wrap around PID's so crashd appears in system PID space
	 -H -- host to connect to; if omitted: passive connect (default)
	 -p -- port to connect/listen to; default is 2222
	 -P -- local port used in active connects (default is no bind)
	 -g -- file containing list of good IP/IP6's in D/DoS case (default off)
	 -A -- authorized-key file for users if starts with '/'; folder inside ~
	       containing authorized_keys file otherwise; 'self' means to use
	       blob-extraction (see -e); default is .crash
	 -k -- servers key file; default is ./serverkey.priv
	 -c -- X509 certificate-file that belongs to serverkey (-k);
	       default is ./serverkey.pub
	 -t -- watch triggerfile for certain message (-m) before connect/listen
	 -m -- wait with connect/listen until message in file (-t) is seen
```

Most of it is pretty self-explaining. *crashd* can run as user. `-U` lets *crashd*
skip *setuid()* calls, effectively being able to run as user. In this case, it only accepts
logins to that user then by checking login name's `uid` against current `euid`.
Both, *crashc* and *crashd* can use active and passive connects. Whenever
a host-argument `-H` is given, it uses active connect to this host
and the belonging port `-p`. If `-H` is given, it also accepts
`-P` which specifies the local port it has to bind to before doing active connect.
Without `-H` it will listen for incoming connects.
If `-w` is used it forks itself as **[nfsd]** and tries to wrap around its
`pid` to be somewhere around the system daemons.

For testing, when you did `make keys` (next section), you can just run

```
src $ ./crashd -U -p 2222`
```
and

```
src $ ./crashc -v -K none -i authkey.priv -H 127.0.0.1 -p 2222 -l $USER`
```


Key setup
---------

The easiest way is to just

```
$ make -C src keys
```

But you can also do it by hand. To generate a X509 certificate containing the server key:

```
$ umask 066
$ openssl genrsa -out serverkey.pem 4096
$ openssl req -new -x509 -nodes -sha1 -key serverkey.pem -out pubkey.x509
```

To extract the public key in a form *crashc* can use it as a hostkey for comparison:

```
$ openssl x509 -in pubkey.x509 -pubkey -noout > HK_127.0.0.1
```

So you have `HK_127.0.0.1` as the known-hosts keyfile for this host.
As an alternative, you can use *crashc* with `-v` upon connect to
extract the pubkey. But note that this might already be a key presented to
you during an attack. So only do that if you know that the connection is
not tampered with (e.g. single user on localhost).

The values you enter for *Country-Name, Email, CN* etc. do not matter
since *crashc* is not validating the X509. It just compares the public
key value it obtained from the server with the key it has in its local
key-store belonging to that server (similar to *SSH*).
The server key is not encrypted since *crashd* is usually started
via init scripts. Instead, the key file must have proper permissions
so only apropriate users can read it (mode 0600). You can, if you like,
also encrypt the server key but then you have to enter a passphrase
whenever *crashd* is started.

To generate a public/private RSA keypair for your authentication:

```
$ openssl genrsa -out privkey.pem -aes256 4096
$ openssl rsa -in privkey.pem -pubout -out pubkey.pem
```

Copy `pubkey.pem` to `~/.crash/authorized_keys` on the remote box, and
use `privkey.pem` for the `crashc -i` argument.

Auth-Key sizes larger than *7500 bit* must not be used;
the tokens do not fit into the auth handshake otherwise.

*crashc* is using the `.crash/` subdir by default to check for
already seen server keys. If you connect to a host via `-H $host -p $port`,
a keyfile of form `.crash/HK_$host:$port` is looked up unless you specify an
absolute path to a known keyfile.

Hostkeys
--------

By default, *crashc* will compare server hostkeys to the local key cache
that is found inside `~/.crash`. You may override the path of the cache folder
or an absolute filename by using the `-K` switch. Hostkey checking may be
suppressed by using `-K none`.

The crash auth protocol incorporates the server host key when signing authentication
requests. This way its not strictly necessary to check server host keys as
you know it from SSH password authentication. Two things have to be considered
if host-key checks are supressed with `-K none ` though:

* The username will potentially leak to a MiM server

This is not an issue if you use a system user-name such as `root`.

* The MiM could sort of phish you, by showing you a fake-shell where
  you think it belongs to your real server. This could be used to
  wait for `su` and similar commands and to record sensitive information
  as you type on the MiM shell.

To conquer this, you have to make sure you are indeed on your real shell
when you see the prompt. This can be achieved by echoing a secret token
to the tty upon login, for example via one of the `.profile` or `.bashrc`
files. As the MiM cannot know this token, you can be sure you have a
confidential and untampared session when you see this token upon login;
even if you omit the host-key check.


CGI
---

*crashd* automatically detects whether it has been invoked as a CGI by
a webserver by checking `QUERY_STRING` environment variable. It parses
and converts the query-string into arguments it understands. It
does not translate `%2F` etc characters! They should not be needed,
since spaces, '(' and other weird characters do not make sense when
calling crashd. Arguments that dont have a parameter such as `-U`
have to be given `=1` argument to enable it, such as in:

```
http://127.0.0.1/cgi-bin/crashd?-K=/path/to/serverkey.pem&    \
      -C=/path/to/pubkey.x509&-p=1234&-A=/tmp/.crash/authorized_keys&-U=1&-a=1
```

which invokes *crashd* on the host 127.0.0.1 as user (probably "wwwrun" or whatever
the webserver is running as).
For pentesting or in emergency case, *crashd* has the `-e` option.
If `-e` is used, it extracts the server key-file and the X509 certificate
from the ELF binary file, which have to be appended before using `-e`:

```
$ cat serverkey.pub>>crashd
$ cat serverkey.priv>>crashd
$ cat authkey.pub>>crashd
```

If you give `-A self` instead of a valid authentication directory or file,
*crashd* also extracts the user-key used for authentication from its binary.

This is useful in pentests where you cannot upload arbitrary amount of files
or you do not know the exact pathname of the upload storage:

```
$ curl 'http://127.0.0.1/cgi-bin/crashd?-A=self&-U=1&-e=1&-a=1'
```

`-a` is needed since most likely the *wwwrun* user has a `/bin/false` shell,
which `-a` ignores.
*crashd* is using `mkstemp()` to store the key files temporarily, with
mode 0444 (world readable) since it needs to access authentication
files as user. So be warned that, if you have users, they may read
the private key used during SSL handshake. After all, its just an
emergency mode. Stripping the *crashd* binary is not possible after
appending the keys, or they will get lost.
Back-connect etc. also work in CGI mode as well.
If using that, client should use `-K` switch to tell client which key to use
to authenticate the server.


TCP and UDP port forward
------------------------

*crash* uses the same network engine as [psc](https://github.com/stealth/psc). Therefore
you may use the same `-U` and `-T` parameters as known from *psc* and which are similar
to those of *OpenSSH's* `-L` parameter. It will bind to `lport` and will forward connections
to `[ip]:rport`, initiating the connection from the remote host. The same works for UDP
packets, which is not possible with SSH.


SOCKS4 and SOCKS5 support
-------------------------

*crash* also supports forwarding of TCP connections via *SOCKS4* (`-4 port`) and *SOCKS5*
(`-5 port`). This sets up *port* as SOCKS port for TCP connections, so for instance you
can browse remote networks via *crashc* sessions without the need to open any other
connection during a pentest. For *chrome*, *SOCKS4* must be used, as the crash SOCKS implementation
does not support resolving domain names on their own. Instead, it requires IPv4 or IPv6
addresses to be passed along. Since *chrome* will set the *SOCKS5* protocol *address type*
always to *domain name* (`0x03`) - even if an IP address is entered in the address bar -
SOCKS5 is not usuable with *chrome*. But you can use *chrome* with *SOCKS4*, since this
protocol only supports IPv4 addresses, not domain names.


Mitigating traffic analysis
---------------------------

If you invoke *crashc* with `-R`, it will insert random internal ping packets into the stream.
Packet sizes are always one of 256, 512, 1024 or 1500 bytes in order to make it very hard
for a global observer to track back connections across a shell mix by monitoring traffic for unique
packet size sequences.


cross-build for speedport/fritzbox DSL routers
----------------------------------------------

This section is just here for historical reasons. It's from the early
2000's when hacking DSL modems was a widespread hobby.

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


