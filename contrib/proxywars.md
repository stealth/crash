# WA / Telegram proxy setup

How to get messenger connectivity if your internet is dead in copland. This covers
*Telegram* and *Whatsapp* messenger.

## Outside

All methods described here require a VPS or server instance running outside the censored network.
In the ideal case this has been setup before blocking rules were tightened. It may also require
help from outside by volunteers. If only the target IP space of your messenger provider, e.g.
the Meta network is blocked, you can directly jump to the `Proxy setup` section. If there is
more blocking, the next sections describe techniques to bypass these.


## TCP blocking

If just outgoing TCP connections are blocked, try using `-D` for DTLS that runs on UDP. You can also
try reverse connect by *crash* server from outside into the censored network by setting up cron scripts
or similar on the VPS that periodically connects to you. This is the case that works for Iran.


## SNI blocking

Some censorship white-list connections to regime websites by checking the SNI of the outgoing
connection. You can use [sniprobe](https://github.com/c-skills/sniprobe) to find out which.
Then you can try connecting to your VPS by setting up your instances and using `-S` with that SNI.

You can go one step further as to setup a regime friendly website that praises the leader to
fool them to have connections from inside allowed to this outside host. On this innocent looking
website you run a SNI proxy such as [sshttp](https://github.com/stealth/sshttp) that multiplexes
another SNI of your choice to a *crash* instance running behind the https port of that website.
Censorship equipment sees all connections looking like a https session to a pro regime website.

You can read more on the SNI case by [our THC friends](https://blog.thc.org/the-iran-firewall-a-preliminary-report).


## ICMP or DNS tunneling

If nothing of above works, you may try to resolve DNS or ping your VPS. If that works, you can setup
a ICMP or DNS tunnel via [fraud-bridge](https://github.com/stealth/fraud-bridge). You can reach
your VPS via `1.2.3.5` then.


## Proxy setup

## Whatsapp

There is an [official WA docu](https://github.com/WhatsApp/proxy) that uses a bit overblown docker setup with `haproxy`.
To boil it down - if you read all the configs - the messenger app is just expecting a simple port forward from the proxy
to `g.whatsapp.net:5222`. Meta seems to use DNS based load balancing so you may get different addresses
than me, but for me it resolves to `185.60.217.54` or `2a03:2880:f21c:81c6:face:b00c:0:7260` in IPv6 case.

Given that you manage to establish a connection to your VPS in the steps before, you do:

```
$ crashc -X 192.168.0.123 -S yourSNI -D -H $VPS -T 1235:[185.60.217.54]:5222 -l user -i authkey.priv -v
```

or

```
 $ crashc -X 192.168.0.123 -S yourSNI -D -H $VPS -T 1235:[2a03:2880:f21c:81c6:face:b00c:0:7260]:5222 -l user -i authkey.priv -v

```

(using DTLS in this example and WA's IPv6 endpoint in the 2nd case)

In your WA messenger, go to `Settings` -> `Storage and data` -> `Proxy settings` and set it to
`192.168.0.123:1235`. It assumes that your phone is connected via wifi and using the same `192.168.0.0` network,
as your *crashc* session is.

## Telegram

With *Telegram* it is similar as easy. Will just use

```
 $ crashc -X 192.168.0.123 -S yourSNI -D -H $VPS -5 1235 -l user -i authkey.priv -v
```

To setup a SOCKS5 proxy and configure it in the app as `Settings` -> `Data and Storage` -> `Proxy Settings` -> `Add Proxy`
as SOCKS5 with `192.168.0.123` and port `1235`.


## Signal

There is a [docu for Signal](https://github.com/signalapp/Signal-TLS-Proxy), using `nginx`.

Unfortunately *Signal* is using TLS-in-TLS tunneling with SNI proxying in the inner tunnel which
requires sort of more complex setup that can't be handled by *crash* alone.

