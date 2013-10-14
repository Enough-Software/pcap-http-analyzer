pcap-http-analyzer
==================

About
-----

**pcap-http-analyzer** is a small utility to convert packet capture files from
tcpdump/wireshark and to convert them into an easily readable textual
log file. **pcap-http-analyzer** supports HTTP and WebSocket (RFC 6455) traffic.

The great strength of this tool is that it can show packets from multiple data streams
sorted in timely manner. Also WebSocket frames are separated displayed as individual packet.

To do this each displayed packet identifies the client (called A, B, C, etc.), a communication direction
(<< or >>), a time stamp, a traffic type indicator (ht for HTTP, ws for WebSocket) and a summary about the packet.

Usage
-----

**pcap-http-analyer** has several optional arguments and one mandatory argument, the file to analyze. Usage is as follows:

```
pcap-http-analyzer [OPTIONS] filename

 --filter, -f          filter for internal devices, comma separated list of netmasks
                       e.g.: -f 192.168.2.107/32,192.168.2.109/32
 --short, -s           short output format, no detailed messages
 --stopwatch, -0       don't use wall clock time for packets, instead start at 00:00:00
 --http-ports=..., -h  comma-separated list of ports for HTTP connections
 --ws-ports=..., -w    comma-separated list of ports for RFC 6455 compliant web socket connections
 --format-json, -j     format JSON
```

Example
-------

A short example showing the different options.

```
pcap-http-analyer -0 -f 192.168.0.0/16 -h 8080,8088 -w 8089 test.pcapnp
```

The output of this looks like this.

```
 A >> 00:00:00.000000 ht DATA

    POST /api/v1/login.json HTTP/1.1
    Host: api.enough.de:8080
    Authorization: OAuth oauth_consumer_key="a38b5cdaa640463f8015dfd1e48541b1", oauth_signature_method="HMAC-SHA1", oauth_version="1.0", oauth_nonce="9417448539462757018", oauth_timestamp="1370251292", oauth_signature="cxQJFZTErWwvRCHuFlXo2fa%2BwoM%3D"
    Accept-Encoding: gzip, deflate
    Content-Type: application/json
    Accept-Language: de-de
    Accept: application/json
    Content-Length: 54
    Connection: keep-alive
    User-Agent: JibeOn/2 CFNetwork/609 Darwin/13.0.0
    
    {"msisdn":"+4917468711116","token":"W9bOnqNL219xdXvW"}

 A << 00:00:00.056903 ht DATA

    HTTP/1.1 200 OK
    Content-Language: de-DE
    Content-Type: application/json;charset=UTF-8
    Pragma: no-cache
    Cache-Control: no-cache, no-store, max-age=0
    Expires: Thu, 01 Jan 1970 00:00:00 GMT
    ETag: "03a35f672392eb5a29b13813a153395d1"
    Content-Length: 181
    Server: Jetty(7.1.6.v20100715)

    {"id":230,"displayName":"BiPhone4","email":"+4917468711116@enough.de","token":"W9bOnqNL219xdXvW","msisdn":"+4917468711116","createDate":"2013-04-22T05:36:43PDT","imsi":"25503"}

 A >> 00:00:00.331600 ht DATA

    GET /api/notificationchannel/v1/sip:+4917468711116@enough.de/channels HTTP/1.1
    Host: api.enough.de:8088
    DeviceId: 5735636dbe3a412d8c69dd462fbf4d28
    Authorization: OAuth oauth_consumer_key="230", oauth_signature_method="HMAC-SHA1", oauth_version="1.0", oauth_nonce="18369866333060263699", oauth_timestamp="1370251292", oauth_signature="gmbv5okogiaKx5bb8UrJ4sLewVY%3D"
    Accept-Encoding: gzip, deflate
    Accept: */*
    Accept-Language: de-de
    Connection: keep-alive
    AppId: a38b5cdaa640463f8015dfd1e48541b1
    User-Agent: JibeOn/2 CFNetwork/609 Darwin/13.0.0
    
 A << 00:00:00.385901 ht DATA

    HTTP/1.1 200 OK
    Server: Apache-Coyote/1.1
    Pragma: no-cache
    Cache-Control: no-cache, no-store, max-age=0
    Expires: Thu, 01 Jan 1970 00:00:00 GMT
    ETag: "072a38b1df7d804d7899791d95e142e7a"
    Content-Type: application/json;charset=UTF-8
    Content-Language: de-DE
    Content-Length: 470
    Date: Mon, 03 Jun 2013 09:21:31 GMT

    {"notificationChannel":[{"channelId":null,"expiryTimestamp":1370253097386,"clientCorrelator":"123","applicationTag":"JibeSDKDemo","channelType":"WebSocket","channelData":{"channelURL":"ws://api.enough.de:8089/ws?c=r1pDGF4FaG","maxNotifications":1},"channelLifetime":2800,"callbackURL":"/api/unused/not-used-by-srg","resourceURL":"/api/notificationchannel/v1/sip:+4917468711116@enough.de/channels/r1pDGF4FaG"}],"resourceURL":null}

 A >> 00:00:00.506426 ws HEADER

    GET /ws?c=r1pDGF4FaG HTTP/1.1
    Host: api.enough.de:8089
    Origin: http://api.enough.de:8089/
    Sec-WebSocket-Key: dmcbgx+r4YhGT/qrXvZ8Zg==
    Upgrade: websocket
    Connection: Upgrade
    Sec-WebSocket-Version: 13

 A << 00:00:00.555896 ws HEADER

    HTTP/1.1 101 Switching Protocols
    Upgrade: WebSocket
    Connection: Upgrade
    Sec-WebSocket-Accept: 0LclA0ce3FsAmx/q7eEl6OHSZLA=

 A << 00:00:01.006071 ws messageType

    {"message":"Message 1"}

 A << 00:00:01.007851 ws messageType

    {"message":"Message 2"}

 A << 00:00:01.010561 ws messageType

    {"message":"Message 3"}

 A << 00:00:01.057956 ws messageType

    {"message":"Message 4"}

 A << 00:00:01.057956 ws messageType

    {"message":"Message 5"}

 A << 00:00:01.057956 ws messageType

    {"address":"Message 6"}

 A << 00:00:01.057956 ws messageType

    {"address":"Message 7"}

 A >> 00:02:00.722177 ws PING

 A << 00:02:00.770794 ws PONG
```

Source
------

Our latest and greatest source of **pcap-http-analyzer** can be found on [GitHub]. Fork us!

Website
-------

All about **pcap-http-analyzer** and other nice things can be found on our website.
You can also follow us on Twitter, @[enoughsoftware].

[GitHub]: https://github.com/Enough-Software/pcap-http-analyzer
[enoughsoftware]: http://twitter.com/enoughsoftware
