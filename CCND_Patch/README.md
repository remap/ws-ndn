Applying Patch 
==============

Patch three files in ccnx-0.6.0/csrc/ccnd/ using their corresponding patch (SameName.patch)

File                             Corresponding patch
----                            --------------------
ccnd.c				      ccnd.patch
ccnd_stats.c 			    ccnd_stats.patch
ccnd_private.h                      ccnd_private.patch

Testing
=======

1. Make and Run CCND.
2. Using Firefox browser open websocket-client.html(located in Testing directory). This html file runs a JavaScript code which sends a web socket http request to server over port 9695.
3. Open JavaScript Console (Press CTRL + ALT + I to display the Web Inspector or if firebug is installed press F12 and click on console tab).
4. Observe the http request header on terminal.
5. After receiving the request the code prepares a http accept header(which gets displayed on terminal once prepared).
7. This http accept header is then sent to client. On receiving this client logs and prints "Websocket connection opened"
On completion of http handshake, the JavaScript code (used in step#1) logs and prints on browser's JavaScript console - "Websockets connection opened"
8. After http handshake, the server reads and prints the string (in frame) sent by client (after unmasking) on standard output like this : "Here is the message from client: Hello Server (from client)"
9. Then, the server sends string in a frame which gets displayed on client console like this - "Got from server : Hello Client (from Server)"

This completes a round-trip of data transmission after establishing websocket connection.

