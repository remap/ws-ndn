import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("", 23456))
sock.listen(5)

handshaken = False

print "TCPServer Waiting for client "

import sys
import hashlib
import base64

data = ''
header = ''

client, address = sock.accept()
while True:
    if handshaken == False:
	values=header.split(' ')
        header += client.recv(16)
        if header.find('\r\n\r\n') != -1:
            data = header.split('\r\n\r\n', 1)[1]
            handshaken = True
            copy= values[6]
	    Sec_WebSocket_Key_value = copy[:-9]
	    key   = Sec_WebSocket_Key_value
	    magic = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
            step1 = hashlib.sha1(key+magic)
            step2 = base64.b64encode(step1.digest())
	    Sec_WebSocket_Accept_value = step2
	    handshake = '\
	    HTTP/1.1 101 Web Socket Protocol Handshake\r\n\
	    Upgrade: WebSocket\r\n\
	    Connection: Upgrade\r\n\
	    '
	    key   = Sec_WebSocket_Key_value
	    magic = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
            step1 = hashlib.sha1(key+magic)
            step2 = base64.b64encode(step1.digest())
            Sec_WebSocket_Accept_value = step2
            seq = (handshake,("Sec-WebSocket-Accept: %s\r\n" %Sec_WebSocket_Accept_value),"WebSocket-Origin: http://localhost:80\r\n WebSocket-Location: ws://localhost:80/\r\n\r\n")
	    handshake = ''.join(seq)
	    client.send(handshake)
	    
    else:
            tmp = client.recv(128)
            data += tmp;

            validated = []

            msgs = data.split('\xff')
            data = msgs.pop()

            for msg in msgs:
                if msg[0] == '\x00':
                    validated.append(msg[1:])

            for v in validated:
                print v
                client.send('\x00' + v + '\xff')
