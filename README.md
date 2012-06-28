ws-ndn
======

Websocket CCND implementation

basic_server.py and basic_client.py are implementations of websocket in python.

ws_server.c is C implementation of server end of websocket.

To compile ws_server.c link to crypto library as follow :

gcc ws_server.c -lcrypto -o ws_server



notes on websockets
===================

websocket implementation varies across browsers (http://caniuse.com/#feat=websockets); primarily the handshakes are different (http://goo.gl/Osuxk). It's difficult to say which implementation will finally be widely supported, so we are using what is easiest for us now to develop the server (RFC 6455 ?). 

The server side socket implementation for CCNx will be done in a manner that allows easy change of handshake protocol, but the data and encoding should remain constant.

lwNDN - the intended final client - sidestepped this issue by using java for a TCP socket, instead of wrestling with websockets just yet.

For testing, we used [insert browser] with the websocket-client.html in /web