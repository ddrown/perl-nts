depends on lib https://github.com/dfoxfranke/libaes_siv
depends on perl modules: Net::SSLeay (1.88 or later), IO::Socket::INET, and Socket::MsgHdr

example:
```
$ ./ntske --host=time.cloudflare.com --debug --context=time.cloudflare.com --port=1234
connected with TLSv1.3 / TLS_AES_256_GCM_SHA384
>>> 80010002000000040002000f80000000
<<< 80010002000000040002000f00050064[...]
1 next-protocol 2 0000
4 aead-algorithm 2 000f
5 new-cookie 100 001da3f0[...]
5 new-cookie 100 001da3f0[...]
5 new-cookie 100 001da3f0[...]
5 new-cookie 100 001da3f0[...]
5 new-cookie 100 001da3f0[...]
5 new-cookie 100 001da3f0[...]
5 new-cookie 100 001da3f0[...]
7 ntpv4-port 2 007b
0 end-of-messages 0
saved to time.cloudflare.com
$ ./ntp-dump --host=time.cloudflare.com --context=time.cloudflare.com
IP: 2606:4700:f1::1
Stratum: 3 (10.135.8.4)
Client Transmit: 1562228855.862856435
Server Reference: 1562228798.754784665
Server Originate 1562228855.862278999
Server Recieve: 1562228855.877107999
Server Transmit: 1562228855.877179544
Client Recieve: 1562228855.886875847
RTT: 24.019412 ms
Offset: 2.170314 ms
Flags leap=0 version=4 mode=4
Poll=0 precision=-25
Root Delay: 0.033126831
Root Dispersion 0.000946044
packet protected by NTS
packet protected by unique id
```
