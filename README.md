ws-ndn
======

Websocket CCND implementation

basic_server.py and basic_client.py are implementations of websocket in python.

ws_server.c is C implementation of server end of websocket.

To compile ws_server.c link to crypto library as follow :

gcc ws_server.c -lcrypto 
