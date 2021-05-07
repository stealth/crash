CRypted Admin SHell
===================

<p align="center">
<img src="https://github.com/stealth/crash/blob/master/logo.jpg" />
</p>

An SSH alternative featuring:

* IPv6 ready
* lightweight, straight forward and extensible protocol using TLS 1.2+
  as transport layer
* man-in-the-middle safe due to its authentication mechanism
  which involves the servers host key into the auth process
* built-in traffic blinding against timing and packet-size infoleak attacks
* not relying on any system auth frameworks such as PAM
* can be entirely run as user, no need to setup config files
* passive/active connects on both ends with most flexible
  local/remote port binding possibilities
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
* SNI hiding mode

Build
-----

You need to have a reasonable version of *OpenSSL* installed. Inside the cloned git repo:

```
$ make -C src
```

On BSD systems you need to install *GNU make* and type `gmake` instead.

If you have a particular *OpenSSL* or *LibreSSL* setup, check the `Makefile` and
set the appropriate `$SSL` variable. *crash* builds also nicely with *LibreSSL* and *BoringSSL*.

For embedded systems, please see at the end of this document.

For Android, edit the `Makefile.android` or `Makefile.android.aarch64` to reflect
your NDK and *BoringSSL* install and use these. The build was tested with `android-ndk-r17b`.

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
	 [-k server key-file] [-c server X509 certificate] [-P port] [-S SNI]
	 [-t trigger-file] [-m trigger message] [-e] [-g good IPs]

	 -a -- always login if authenticated, despite false/nologin shells
	 -U -- run as user (e.g. turn off setuid() calls) if invoked as such
	 -e -- extract key and certfile from the binary itself (no -k/-c needed)
	 -q -- quiet mode, turns off logging and utmp entries
	 -6 -- use IPv6 rather than IPv4
	 -w -- wrap around PID to appear in system PID space (must be last arg!)
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
         -S -- SNI to hide behind
```

Most of it is pretty self-explaining. *crashd* can run as user. `-U` lets *crashd*
skip *setuid()* calls, effectively being able to run as user. In this case, it only accepts
logins to that user then by checking login name's `uid` against current `euid`.
Both, *crashc* and *crashd* can use active and passive connects. Whenever
a host-argument `-H` is given, it uses active connect to this host
and the belonging port `-p`. If `-H` is given, it also accepts
`-P` which specifies the local port it has to bind to before doing active connect.
Without `-H` it will listen for incoming connects. This way, from TCP view client
and server role may be reversed, while still having `crashd` as the shell server.
If `-w` is used it forks itself as **[nfsd]** and tries to wrap around its
`pid` to be somewhere around the system daemons. As `-w` is overwriting main()'s `argv` array,
it must appear last in the option list, otherwise option processing will not work
correctly.

For testing, when you did `make keys` (next section), you can just run

```
src $ ./crashd -U -p 2222
```
and

```
src $ ./crashc -v -K none -i authkey.priv -H 127.0.0.1 -p 2222 -l $USER
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
$ openssl genrsa -out serverkey.priv 4096
$ openssl req -new -x509 -nodes -sha1 -key serverkey.priv -out serverkey.pub
```

To extract the public key in a form *crashc* can use it as a hostkey for comparison:

```
$ openssl x509 -in serverkey.pub -pubkey -noout > HK_127.0.0.1
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
so only appropriate users can read it (mode 0600). You can, if you like,
also encrypt the server key but then you have to enter a pass-phrase
whenever *crashd* is started.

To generate a public/private RSA keypair for your authentication:

```
$ openssl genrsa -out authkey.priv -aes256 4096
$ openssl rsa -in authkey.priv -pubout -out authkey.pub
```

Copy `authkey.pub` to `~/.crash/authorized_keys` on the remote box, and
use `authkey.priv` for the `crashc -i` argument. Note, that upon authentication
you will be asked for the pass-phrase to unlock your private key that is
stored locally. The pass-phrase will not travel the network.

Auth-Key sizes larger than *7500 bit* must not be used;
the tokens do not fit into the auth handshake otherwise.

*crashc* is using the `.crash/` subdir by default to check for
already seen server keys. If you connect to a host via `-H $host -p $port`,
a keyfile of form `.crash/HK_$host:$port` is looked up unless you specify an
absolute path to a known keyfile.

Hostkeys
--------

By default, *crashc* will compare server hostkeys to the local key cache
that is found inside the `.crash/` subdir of CWD. You may override the path of the cache
folder by using the `-K` switch. For example by using `-K ~/.crash/`, you use the folder
inside your home directory. If the pathname does not end with a slash, it is treated as
a filename instead of a directory. If a cache directory is used instead of an
filename, each hostkey is expected to be found inside the folder as of the name `HK_$HOST:$PORT`
where `$HOST` is the `-H` argument and `$PORT` the `-p` argument. If using `-v`
the server hostkey will be printed on stdout and may be pasted to the cache folder
into the `HK_$HOST:$PORT` file.

Hostkey checking may be suppressed by using `-K none`.

The crash auth protocol incorporates the server host key when signing authentication
requests. This way its not strictly necessary to check server host keys as
you know it from SSH password authentication. Two things have to be considered
if host-key checks are suppressed with `-K none ` though:

* The user-name will potentially leak to a MiM server

This is not an issue if you use a system user-name such as `root`.

* The MiM could sort of phish you, by showing you a fake-shell where
  you think it belongs to your real server. This could be used to
  wait for `su` and similar commands and to record sensitive information
  as you type on the MiM shell.

To conquer this, you have to make sure you are indeed on your real shell
when you see the prompt. This can be achieved by echoing a secret token
to the tty upon login, for example via one of the `.profile` or `.bashrc`
files. As the MiM cannot know this token, you can be sure you have a
confidential and untampered session when you see this token upon login;
even if you omit the host-key check.


CGI
---

*crashd* automatically detects whether it has been invoked as a CGI by
a web-server by checking `QUERY_STRING` environment variable. It parses
and converts the query-string into arguments it understands. It
does not translate `%2F` etc characters! They should not be needed,
since spaces, '(' and other weird characters do not make sense when
calling crashd. Arguments that don't have a parameter such as `-U`
have to be given `=1` argument to enable it, such as in:

```
http://127.0.0.1/cgi-bin/crashd?-K=/path/to/serverkey.pem&    \
      -C=/path/to/pubkey.x509&-p=1234&-A=/tmp/.crash/authorized_keys&-U=1&-a=1
```

which invokes *crashd* on the host 127.0.0.1 as user (probably "wwwrun" or whatever
the web-server is running as).
For pen-testing or in emergency case, *crashd* has the `-e` option.
If `-e` is used, it extracts the server key-file and the X509 certificate
from the ELF binary file, which have to be appended before using `-e`:

```
$ cat serverkey.pub>>crashd
$ cat serverkey.priv>>crashd
$ cat authkey.pub>>crashd
```

If you give `-A self` instead of a valid authentication directory or file,
*crashd* also extracts the user-key used for authentication from its binary.

This is useful in pen-tests where you cannot upload arbitrary amount of files
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
connection during a pen-test. For *chrome*, *SOCKS4* must be used, as the crash SOCKS implementation
does not support resolving domain names on their own. Instead, it requires IPv4 or IPv6
addresses to be passed along. Since *chrome* will set the *SOCKS5* protocol *address type*
always to *domain name* (`0x03`) - even if an IP address is entered in the address bar -
SOCKS5 is not usable with *chrome*. But you can use *chrome* with *SOCKS4*, since this
protocol only supports IPv4 addresses, not domain names.


Mitigating traffic analysis
---------------------------

Traffic analysis mitigation has two goals. First, to make it hard to find out actual typing
sequences and potential info leaks about whats being typed inside an encrypted, interactive
channel. Second, to make it hard for a (semi-)global observer to track connections streams
across packet mixes or hubs.

Completely mitigating traffic analysis for a capable (global) observer is very hard.
It would require many crash users so to sink all individual packets in a swarm and
make it impossible to find patterns that could be used to track individual users across
packet mixes. It would also require a fixed packet size for *all* packets as well as a
constant delay between the sends to make all connections look equal. Even then, theres
still the problem of the overall amount of traffic sent that may be measured and used
to track individuals. As having constant size and delays would make the connection
feel slow or even unusable, *crash* lets you choose between traffic policies which are
controlled by `-R <value>`. *Value* is an integer with the following meaning:

* 0: disable all padding of payloads and don't inject random traffic. The pure feeling!
* 1: pad payload to the next 256, 512, 1024 or 1420 byte boundary, no injects (default)
* 2: pad payload to the next 256, 512, 1024 or 1420 byte boundary, random injects client side
* 3: pad payload to the next 256, 512, 1024 or 1420 byte boundary, random injects with server
  responses
* 4: pad payload to 1420 byte boundary, no injects
* 5: pad payload to 1420 byte boundary, random injects client side
* 6: pad payload to 1420 byte boundary, random injects with server responses

1420 is an often seen TCP MSS. The values were chosen in a way so that sent data fits most
likely into a single packet. Note however that these are the packet sizes (plus the TLS record size)
as it is passed to the TCP stack. TCP will decide itself how it will send the segements. There is
no way to enforce 'TCP packet sizes', but this does not matter as the deps to the actual payload
size is already blurred.

If you live in a country with restrictive egress filtering, it may be helpful to test how long
connections can survive. Note that due to `-4` and `-U` which allows to proxy TCP *and* UDP (DNS)
to a remote site, *crash* may be used as a [shadowsocks](https://shadowsocks.org) alternative that requires
basically no setup and just needs a user-shell behind egress.

If you think that all of this is paranoia, go get some product sheets for devices that
detect and classify SSH traffic by behavioral analysis.


Hiding by SNI
-------------

By default, the `crashd` whill show a banner upon connect to tell the peer major and minor version
numbers. Censorship countries might block addresses wich show banners they dislike. To combat this,
*crash* allows for a TLS-only mode that is indistinguishable from a HTTPS session. Just start
`crashd` with `-S` and give a semi-secret name (Server Name Indicator, SNI). Only clients that also
use the correct `-S` parameter will reach the gate for authentication at all. Other TLS sessions
will just be rejected. *Note that the SNI travels the network in plain-text and that `-S` is not meant
for authentication.* The only reason for SNI hiding is to hide the *crash* banner from probing/crawling.
You may also use SNI proxies such as [sshttp](https://github.com/stealth/sshttp) to hide *crash* even
deeper and to forward all non-correct SNI connects to some web-site. This way you may hide your server
behind neutral web-sites from agressively probing/blocking censors.


File up/download
----------------

Although there is nothing like `sftp` for *crash*, it may be used for file up/downloads.

In order to upload a file:
```
~ $ crashc -H host -i authkey.priv -l root -c 'dd of=/path/on/remote status=progress' < local.file
```

Or to download a file:
```
~ $ crashc -H host -i authkey.priv -l root -c 'dd if=/path/on/remote status=progress' > local.file
```

Note that in the download case you must not specify the `-v` switch since this would add
the verbose output to the `local.file`. For `-c` commands, *crash* will forward `stdout` and
`stderr` separated to the local tty's fd 1 and 2, so above commands add a nice progress bar
during the xfer.


cross-build for speedport/fritzbox DSL routers
----------------------------------------------

This section is just here for historical reasons. It's from the early
2000's when hacking DSL modems was a widespread hobby.

In Germany, these devices are quite common and support open build
environment/SDK since the firmware is based on Linux and available
in source. Download/unpack the SDK/tar-ball and the MIPS tool-chain. I assume you
are familiar with building router images for these devices. The openssl
package for the speedport **W-500V** I tested has version 0.9.7 and I had
to build it by hand before, so the references to the *libssl.a*
inside crash Makefile are valid. On the system I tested (500V)
I had to make it static, since dynamic openssl library requires *libdl*
which was not on the device. Building a firmware image often
calls strip on the user binaries, so take care it doesn't
strip off the embedded keys if using `-e`.


Then, inside  `userapps/opensource/` directory, unpack the crash tar-ball,
edit the `Makefile` to match "true" at the first `ifeq()` and then you are able
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


