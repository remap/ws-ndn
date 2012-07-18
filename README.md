ws-ndn
======

Websocket CCND implementation

basic_server.py and basic_client.py are implementations of websocket in python.

ws_server.c is C implementation of server end of websocket.

To compile ws_server.c link to crypto library as follow :

gcc ws_server.c -lcrypto -o ws_server

To see websocket server functioning :

-> Start C server 
-> Open /web/webscoket-client.html in Mozilla Firefox
-> Open JavaScript Console

	For Firefox:

	    Press CTRL + SHIFT + K to open the Web console.
				OR
	    If Firebug is installed: Press F12 to open Firebug and click on the "Console" tab

Implementation
==============
 
websocket implementation varies across browsers (http://caniuse.com/#feat=websockets); primarily the handshakes are different (http://goo.gl/Osuxk). It's difficult to say which implementation will finally be widely supported, so we are using what is easiest for us now to develop the server (RFC 6455 ?). 

The server side socket implementation for CCNx will be done in a manner that allows easy change of handshake protocol, but the data and encoding should remain constant.

lwNDN - the intended final client - sidestepped this issue by using java for a TCP socket, instead of wrestling with websockets just yet.

For testing, we used [insert browser] with the websocket-client.html in /web

Notes on websockets
===================

WebSocket is a web technology providing for bi-directional, full-duplex communications channels over a single TCP connection. The WebSocket API is being standardized by the W3C, and the WebSocket protocol has been standardized by the IETF as RFC 6455.

To establish a WebSocket connection, the client sends a WebSocket handshake request, and the server sends a WebSocket handshake response, as shown in the following example:

Client request :

	GET / HTTP/1.1
	Host: server.example.com
	User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:13.0) Gecko/20100101 Firefox/13.0.1
	Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
	Accept-Language: en-us,en;q=0.5
	Accept-Encoding: gzip, deflate
	Connection: keep-alive, Upgrade
	Sec-WebSocket-Version: 13
	Origin: null
	Sec-WebSocket-Key: fl/GIXZGTVxEOpjTLObP4w==
	X-DNT-OVersion: 2.2.0.515
	X-DNT-Cohort: 5
	X-DNT-Version: 2.2.1.611 FF ffamo 6659
	Pragma: no-cache
	Cache-Control: no-cache
	Upgrade: websocket

Server response:

	HTTP/1.1 101 Web Socket Protocol Handshake
	Upgrade: Websocket
	Connection: Upgrade
	Sec-WebSocket-Accept: HSmrc0sMlYUkAGmm5OPpG2HaGWk=
	WebSocket-Origin: http://example.com
	WebSocket-Location: ws://example.com/bin/demo

Note that each line ends with an EOL (end of line) sequence, \n or \r\n. There must be a blank line at the end.
The client sends a Sec-WebSocket-Key which is base64 encoded. To form a response, the magic string 258EAFA5-E914-47DA-95CA-C5AB0DC85B11 is appended to this (undecoded) key. The resulting string is then hashed with SHA-1, then base64 encoded. Finally, the resulting reply occurs in the header Sec-WebSocket-Accept.
Details of Sec-WebSocket-Key to Sec-WebSocket-Accept :
x3JJHMbDL1EzLkh9GBhXDw==258EAFA5-E914-47DA-95CA-C5AB0DC85B11 string hashed by SHA-1 gives 1d29ab734b0c9585240069a6e4e3e91b61da1969 hexadecimal value.
Encoding the SHA-1 hash by Base64 yields HSmrc0sMlYUkAGmm5OPpG2HaGWk=, which is the Sec-WebSocket-Accept value.
Once the connection is established, the client and server can send WebSocket data frames back and forth in full-duplex mode. They can send text frames in full-duplex, in either direction at the same time. The data is minimally framed.

In the WebSocket Protocol, data is transmitted using a sequence of frames.
The server MUST close the connection upon receiving a frame that is not masked. In this case, a server MAY send a Close frame with a status code of 1002 (protocol error). A server MUST NOT mask any frames that it sends to the client. A client MUST close a connection if it detects a masked frame.  In this case, it MAY use the status code 1002(protocol error)

For more information regarding data framing, masking/unmasking fo through RFC 6455. 
Link : http://tools.ietf.org/html/rfc6455


