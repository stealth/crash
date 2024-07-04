CRypted Admin SHell
===================

<p align="center">
<img src="https://github.com/stealth/crash/blob/master/logo.jpg" />
</p>

An SSH alternative featuring:

* IPv6 ready
* lightweight, straight forward and extensible protocol using TLS 1.3
  or optionally DTLS 1.2 as transport layer
* man-in-the-middle safe due to its authentication mechanism
  which involves the servers host key into the auth process
* built-in traffic blinding against timing and packet-size info-leak attacks
* not relying on any system auth frameworks such as PAM
* can be entirely run as user, no need to setup config files
* passive/active connects on both ends with most flexible
  local/remote address+port binding possibilities
* built-in SOCKS5 client side support when doing active connects
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
* messenger proxy support
* proxying based on SNI
* SNI hiding mode
* Disguise Filters to mask as different kind of software to global observers
* can use UDP transport mode with DTLS and added reliability and flow-control
  layer
* transparent roaming support with DTLS client sessions
* suspend/resume support with DTLS client sessions


If you came here for censorship circumvention - once everything is done and working - go to
[proxywars contrib](https://github.com/stealth/crash/blob/master/contrib/proxywars.md)
to learn about how to create WA/TG messenger proxy setups in censorship environments.


Build
-----

Build requires *OpenSSL* version >= `1.1` or `3.0` or compatible *LibreSSL* (`3.6.1` tested).
Inside the cloned git repo:

```
$ make -C src
```

On BSD systems you need to install *GNU make* and type `gmake` instead.

If you have a particular *OpenSSL* or *LibreSSL* setup, check the `Makefile` and
set the appropriate `$SSL` variable. *crash* builds also nicely with *LibreSSL* and *BoringSSL*.

For Android, edit the `Makefile.android` or `Makefile.android.aarch64` to reflect
your NDK and *BoringSSL* install and use these. The build was tested with `android-ndk-r17b`.

On OSX you want to install *OpenSSL* via `brew install openssl@1.1` or by hand before `make`.

On Windows you need to install [cygwin](https://cygwin.com/install.html) and select
the appropriate `gcc, gcc-g++, perl, openssl (1.1.1), libssl (1.1.1), libssl-devel (1.1.1), make`
and `git` packages before the build in order to clone and `make` this repo. Make sure
your openssl versions for the tool itself, the runtime libs and devel package are all
the same.

*crash* was successfully tested on *Linux, FreeBSD, NetBSD, OpenSolaris, OSX and Android*.

After that, to generate the required server and authentication keys:

```
$ make -C src keys
```

or see further instructions in this document. If you want to use _ephemeral keying_
(aka [PFS](https://en.wikipedia.org/wiki/Perfect_Forward_Secrecy)), invoke

```
$ cd src; ./newdh
```

before `make` in order to generate DH parameters before the build. Thats not strictly necessary
as of TLS 1.3, since the Kex will most likely chose one of the ECDH variants, but if you customize
your setup, it is recommended to generate your own DH params.


Legacy builds
-------------

If `make` detects that TLSv1.3 is not available on the system or `TLS_COMPAT_DOWNGRADE` is
defined, the binaries are built with TLSv1.2 only. This is to allow using it on legacy
systems when no other options are available. Obviosuly, the built binaries are not
compatible to normal builds, but include full support of all other features.


OpenSSL3 builds
---------------

The *OpenSSL 3* API is quite different from the *OpenSSL-1.1* API. In order to make
use of *OpenSSL 3*, you have to edit `Makefile` and `newdh` to reflect your path setup
for your *OpenSSL* install. Invoking `newdh` is mandatory, unlike for the 1.1 builds. After
that you just do `make` and everything should be the same as with 1.1.

*proudly sponsored by:*
<p align="center">
<a href="https://github.com/c-skills/welcome">
<img src="https://github.com/c-skills/welcome/blob/master/logo.jpg"/>
</a>
</p>


Run
---

*crash* does not need any config or option files to run. Its easy and
straight forward to use. Anything can be enabled/disabled by
runtime switches:

```
stealth@linux ~> ./crashd -h


crypted admin shell (C) 2023 Sebastian Krahmer https://github.com/stealth/crash


Usage:	./crashd [-U] [-q] [-a] [-6] [-D] [-H host] [-p port] [-A auth keys]
	 [-k server key-file] [-c server X509 cert] [-L [ip]:port] [-S SNI]
	 [-t trigger-file] [-m trigger message] [-e] [-g good IPs] [-N] [-R]
	 [-x socks5://[ip]:port] [-w]

	 -a -- always login if authenticated, despite false/nologin shells
	 -U -- run as user (e.g. turn off setuid() calls) if invoked as such
	 -e -- extract key and certfile from the binary itself (no -k/-c needed)
	 -q -- quiet mode, turns off logging and utmp entries
	 -6 -- use IPv6 rather than IPv4
	 -w -- setproctitle to `[kthreadd]` (must be last arg!)
	 -H -- host to connect to; if omitted: passive connect (default)
	 -p -- port to connect to when active connect; default is 2222
	 -L -- local [ip]:port used for binding ([0.0.0.0]:2222)
	 -g -- file containing list of good IP/IP6's in D/DoS case (default off)
	 -A -- authorized-key file for users if starts with '/'; folder inside ~
	       containing authorized_keys file otherwise; 'self' means to use
	       blob-extraction (see -e); default is .crash
	 -k -- servers key file; default is ./serverkey.priv
	 -c -- X509 certificate-file that belongs to serverkey (-k);
	       default is ./serverkey.pub
	 -t -- watch triggerfile for certain message (-m) before connect/listen
	 -m -- wait with connect/listen until message in file (-t) is seen
	 -N -- disable TCP/UDP port forwarding
	 -D -- use DTLS transport (requires -S)
	 -x -- use this SOCKS5 proxy when using active connect
	 -R -- allow clients to roam sessions
	 -S -- SNI to hide behind
```

Most of it is pretty self-explaining. *crashd* can run as user. `-U` lets *crashd*
skip `setuid()` calls, effectively being able to run as user. In this case, it only accepts
logins to that user then by checking login name's `uid` against current `euid`.
Both, *crashc* and *crashd* can use active and passive connects. Whenever
a host-argument `-H` is given, it uses active connect to this host
and the belonging port `-p`. It also accepts `-L` which specifies the local address and port it has
to bind to, either before doing active connect (`-H`) or passively (no `-H` given).
This way - from TCP point view - client and server role may be reversed, while still having
*crashd* as the shell server.
If `-w` is used it forks itself as **[kthreadd]** and tries to wrap around its
`pid` to be somewhere around the system daemons. As `-w` is overwriting main()'s `argv` array,
it must appear last in the option list, otherwise option processing will not work
correctly. You can set the process name as `TITLE` def inside the `Makefile`.

For testing, when you did `make keys` (next section), you can just run

```
src $ ./crashd -U -L [127.0.0.1]:2222
```
(or omit `-L` paramater to bind to the default port on any address) and

```
src $ ./crashc -v -K none -i authkey.priv -H 127.0.0.1 -p 2222 -l $USER
```


Key setup
---------

Unless you want to use SNI-hiding (see section below), you can type straight ahead:

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

Unless you use SNI hiding (see section below), the values you enter for *Country-Name,
Email, CN* etc. do not matter since *crashc* is not validating the X509. It just
compares the public key value it obtained from the server with the key it has in its
local key-store belonging to that server (similar to *SSH*).
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
the server hostkey will be printed on `stderr` and may be pasted to the cache folder
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


Term setup
----------

As *crashc* is not transfering env vars to the remote side for a reason, keep in mind
that certain stuff is unset, such as `$TERM`. I.e. if you want to run an editor on the remote
shell and started *crashc* from within an xterm, you have to `TERM=xterm vi file` in order
to have a useful editing session. Likewise for other programs that you expect to work and
require specific environment setup.

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

For pen-testing or for emergency case, *crashd* has the `-e` option.
If `-e` is used, it extracts the server key-file and the X509 certificate
from the ELF binary file, which have to be appended before using `-e`:

```
$ cat serverkey.priv>>crashd
$ cat serverkey.pub>>crashd
$ cat authkey.pub>>crashd
```

The order of appended keys is important.

If you give `-A self` instead of a valid authentication directory or file,
*crashd* also extracts the user-key used for authentication from its binary.
The keys are extracted from the binary at runtime and stored in temp files
of pattern `/tmp/sshXXXXXX` (`/data/local/tmp/sshXXXXXX` on Android).
Make sure to erase them securely upon last login, since they contain private keying
material.

This is useful in pen-tests where you cannot upload arbitrary amount of files
or you do not know the exact pathname of the upload storage:

```
$ curl 'http://127.0.0.1/cgi-bin/crashd?-A=self&-U=1&-e=1&-a=1'
```

`-a` is needed since most likely the *wwwrun* user has a `/bin/false` shell,
which `-a` ignores.
*crashd* is using `mkstemp()` to store the key files temporarily (just see above), with
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

If you are interested in messenger proxy setups in copland countries, you can check `contrib`
folder.


SOCKS4 and SOCKS5 support
-------------------------

*crash* also supports forwarding of TCP connections via *SOCKS4* (`-4 port`) and *SOCKS5*
(`-5 port`). This sets up *port* as SOCKS port for TCP connections, so for instance you
can browse remote networks via *crashc* sessions without the need to open any other
connection during a pentest. If you pass `-N` to *crashc*, it enables DNS name resolution
on the remote side, so you can also use chrome with it. But be warned: There is a privacy
problem with browsers that try to resolve a sequence of DNS names upon startup that
is not under your control. Also, if your remote side has a broken DNS setup, your typing
shell may block for several seconds if DNS reply packets are missing. There are no good
async resolver functions which are embeddable and portable so I had to rely on
`getaddrinfo()` in the single thread at the price of possible blockings for several seconds
if DNS problems exist. Thats why name resolving has to be enabled explicitly. *crashd*
tries to minimize this potential problem with DNS lookup caches though, so in most
situation it should just work painlessly.
If you pass `-X IP-address` (must come before any other proxy argument), you can bind your local proxy
to an address different from `127.0.0.1`, so you can share the proxy in your local network.

There is also a client side SOCKS5 support available when using *crashc* with `-x`.


Proxying based on SNI
---------------------

In some circumstances you might want to change the endpoint of the proxy session based
on a SNI that you receive in the TLS `ClientHello`. For convenience, *crashc* integrates
support for that by using `-Y lport:SNI:[ip]:rport` which listens on `lport` and forwards the
given `SNI` to `ip:rport`. A fallback of `default` SNI can be given so that any non-matches or
missing SNIs will be forwarded to that destination.


DTLS transport
--------------

*crash* allows to use all of its trickery above also on a DTLS 1.2 transport layer based
on UDP. I have added basic flow control and reliability, so you can even xfer files and use
port forwarding as with TLS 1.3. The reason for adding DTLS is that some countries have
TCP egress filters that only allow incoming connections. It is harder for censors to tell
which UDP packets establish an outgoing connection, as there is nothing like a "connection"
with UDP. With DTLS sessions, which are established by the `-D` switch on both sides, a SNI
is mandatory.
When forwarding UDP ports on DTLS sessions, make sure you will not send UDP payloads larger than
1320 bytes across the sockets, as it is necessary in UDP case to keep enough room for headers
and record layer without the need to fragment the packet, as DTLS honors packet boundaries
(there is nothing like a stream as in TCP, just datagrams).
DTLS mode is still experimental (although working stable) and will switch to DTLS 1.3 as soon
as it is implemented widely (DTLS 1.3 RFC was just finished 2022).


Suspend/Resume/Roaming
----------------------

This is an experimental feature, although working stable.

When using DTLS sessions and *crashd* is started with `-R`, you will get the following:

* transparent roaming of the client sessions - including existing SOCKS connections - which
  allows to switch underlying physical layer, VPN, Interface, NAT or IP address without
  even noticing it
* *crashc* may be terminated via `SIGTERM`, so it will dump the session to a ticket
  file (`-t`) which can later be resumed from by passing the correct dst IP:port and ticket
  but w/o the need to authenticate again (no `-i`) - with full roaming support

In the 2nd case, **the ticket file will not be encrypted**, so make sure you never leak it.
This allows you to switch off your laptop and continue working from elsewhere or even
share the ticket to another admin who then continues your session.

One thing is special with regards to bound server ports when using roaming: Due to
UDP internals, the next open session for a followup "connect" will be on the next
free port in the range of `[port, port + 1000]` and not on the same port as when using TCP.
This needs to be as with roaming we cannot actually call `connect()` to virtually create a
connected tuple, as the next session packet can arrive from anywhere - not just from the
originating IP as happens with TCP. So when you start the server with `-p 2222` and one
roaming session already exists, the next one needs to "connect" to port `2223`. If the
session at port `2222` is finished (not suspended, but really finished), port `2222`
will become available again to the next client.

Suspend/Resume does not work yet with *LibreSSL* builds, but roaming does.


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
constant delay between the sends to make all connections look equal. Even then, there's
still the problem of the overall amount of traffic sent that may be measured and used
to track individuals. As having constant size and delays would make the connection
feel slow or even unusable, *crash* lets you choose between traffic policies which are
controlled by `-R <value>`. *Value* is an integer with the following meaning:

* 0: disable all padding of payloads and don't inject random traffic. The pure feeling!
* 1: pad payload to the next 256, 512, 1024 or 1320 byte boundary, no injects (default)
* 2: pad payload to the next 256, 512, 1024 or 1320 byte boundary, random injects client side
* 3: pad payload to the next 256, 512, 1024 or 1320 byte boundary, random injects with server
  responses
* 4: pad payload to 1320 byte boundary, no injects
* 5: pad payload to 1320 byte boundary, random injects client side
* 6: pad payload to 1320 byte boundary, random injects with server responses

1320 is crashds internally used MSS. The values were chosen in a way so that sent data fits most
likely into a single packet. Note however that these are the packet sizes (plus the TLS record size)
as it is passed to the TCP stack. TCP will decide itself how it will send the segments. There is
no way to enforce 'TCP packet sizes', but this does not matter as the deps to the actual payload
size is already blurred.

In DTLS mode there are always ping packets in order to implement synchronization and flow control.

If you live in a country with restrictive egress filtering, it may be helpful to test how long
connections can survive. Note that due to `-4` and `-U` which allows to proxy TCP *and* UDP (DNS)
to a remote site, *crash* may be used as a [shadowsocks](https://shadowsocks.org) alternative that requires
basically no setup and just needs a user-shell behind egress.

If you think that all of this is paranoia, go get some product sheets for devices that
detect and classify SSH traffic by behavioral analysis.


Hiding by SNI
-------------

By default, the *crashd* will show a banner upon connect to tell the peer major and minor version
numbers. Censorship countries might block addresses which show banners they dislike. To combat this,
*crash* allows for a TLS-only mode that is indistinguishable from a HTTPS session. Just start
*crashd* with `-S` and give a semi-secret name (Server Name Indicator, SNI). Only clients that also
use the correct `-S` parameter will reach the gate for authentication at all. Other TLS sessions
will just be rejected. *Note that the SNI travels the network in plain-text and that `-S` is not meant
for authentication.* The only reason for SNI hiding is to hide the *crash* banner from probing/crawling.
You may also use SNI proxies such as [sshttp](https://github.com/stealth/sshttp) to hide *crash* even
deeper and to forward all non-correct SNI connects to some web-site. This way you may hide your server
behind neutral web-sites from aggressively probing/blocking censors.

In order for probing to not reveal that you are running *crash* by checking the X509 certificate
details, you should use reasonable values for *Country Name*, *City* etc. when asked for it during
the `make keys` process. For instance it would make no sense to setup a pro-regime web-site
to hide behind and enter anti-regime values for the X509 specific naming.

Inside the `contrib` folder you will find a nginx config file that you can integrate into
your setup along with comments how you would create a connect from outside to your nginx server
in order to have a *crash* session based on a SNI that you chose.


Disguise Filters
----------------

Taking the feature of SNI hiding one step further. Some countries use network data gathered at
their border routers to scan destination machines and check whether the content or software there
could pose a threat to their leaders. It is therefore not good to always tell anyone openly
that a *crashd* is running on a certain port, even if the peer shows up with the right SNI,
as the SNI could have been sniffed by a global observer. Entering *Disguise Filters*.

Upon connect, you have to show up with a correct (pre-)secret in order to start a *crash* session.
This can't be known by an observer as its hidden inside the TLS stream (unlike the SNI). If
the secret is not correct, *crashd* disguises as another - innocent looking - software.

Currently, there is only one Disguise Filter, `redirect1`, which masks as a web server
sending a redirect of your choice. Disguise Filters always also require `-S`:


```
$ ./crashd -L [0.0.0.0]:4433 -c serverkey.pub -k serverkey.priv \
   -G redirect1:mydirtysecret:https://www.ccc.de -S localhost
```

So only those who know can start a shell session:

```
$ ./crashc -H 127.0.0.1 -p 4433 -l stealth -i authkey.priv -S localhost -G mydirtysecret
```

All others, e.g. `curl https://localhost:4433 -k -v -L` will be redirected to `https://www.ccc.de`.

(where `localhost` was just chosen for testing to make curl have the right SNI)
When a Disguise Filter is triggered, you will see it in the logs. This also allows admins to
have shell servers reachable from outside which just map to the legit web server when not
prompted with the correct (pre-) secret.
For sure; for a disguise to work against censors with a large dick, your story has to be
perfect, i.e. the CNs etc. of the certificate have to look legit, even better signed by
a legit CA and the redirect has to look reasonable.


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


DoS mitigation
--------------

*crashd* includes some sort of D/DoS protection. Only one connection per second
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


