// To compile this file link to crpto library : gcc ws_server.c -lcrypto

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <assert.h>

/* Function to convert hash into base 64*/
char *base64(const unsigned char *input, int length);

int main( int argc, char *argv[] )
{
	/* For creating, handling and passing data across socket */
	int sockfd, newsockfd, portno, clilen,len,n;
	char buffer[656];
	struct sockaddr_in serv_addr, cli_addr;
    
	/* For http handshake to initiate web socket protocol */
	char handshake[360],message[360];
	char *handshake_part2, *handshake_part3,*key,*magic,*final;
	const void *hand;
    	unsigned char hash [20];
        int handshaken = 0;
    
    	/* For masking and unmasking data sent or recieved*/
    	char data[500];
	char *in, *buffr;
	unsigned int i;
	unsigned char mask[4];
	unsigned int packet_length = 0;
	int rc;
	char frame[131];
 
	/* First call to socket() function */
    	sockfd = socket(AF_INET, SOCK_STREAM, 0);
    	if (sockfd < 0) 
    	{
       		perror("ERROR opening socket");
        	exit(1);
    	}
    
    	/* Initializing socket structure */
    	bzero((char *) &serv_addr, sizeof(serv_addr));
    	portno = 5001;
    	serv_addr.sin_family = AF_INET;
    	serv_addr.sin_addr.s_addr = INADDR_ANY;
    	serv_addr.sin_port = htons(portno);
 
    	/* Now binding the host address using bind() call.*/
    	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
    	{
        	perror("ERROR on binding");
        	exit(1);
    	}

    	/* Now start listening for the clients, here process will
    	* go in sleep mode and will wait for the incoming connection
    	*/
    	listen(sockfd,5);
    	clilen = sizeof(cli_addr);

	/* Accept actual connection from the client */
    	newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
    	if (newsockfd < 0) 
    	{
        	perror("ERROR on accept");
        	exit(1);
    	}
    
    	/* If connection is established then start communicating */
    	while (1)
    	{
		if (handshaken == 0)	// Proceed with http handshake if not done
		{
			bzero(buffer,656);
    			n = read( newsockfd,buffer,655 );
    			if (n < 0)
    			{
        			perror("ERROR reading from socket");
        			exit(1);
    			}
    			printf("HTTP Request Header :\n%s\n",buffer);
    			len= strlen(buffer);
			//printf("%d",len);			
        	        /* Preparing http request response to establish socket */
   			key=strndup(buffer+359, 24);	// Extracting WebSocket-Key 
        	        magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    			final = strcat(key,magic);	//Appending magic key to WebSocket-Key   
    			SHA1(final,strlen(final),hash);		//String hashing by SHA 1
    			handshake_part2= base64(hash, sizeof(hash)); // Encoding the SHA-1 hash by Base64
     			strcpy (handshake,"HTTP/1.1 101 Web Socket Protocol Handshake\r\nUpgrade: Websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ");
    			strcat(handshake,handshake_part2);
    			handshake_part3="\r\nWebSocket-Origin: http://localhost:80\r\nWebSocket-Location: ws://localhost:80/\r\n\r\n";
    			strcat(handshake,handshake_part3);
	
  			/* Write a http response header to the client */
  		        n = write(newsockfd, handshake, strlen(handshake));
    			handshaken=1;
    			if (n < 0)
    			{
        		perror("ERROR writing to socket");
        		exit(1);
    			}
		}
		else
		{
			/* Reading content recieved from client */			
			bzero(data,500);
    			n = read( newsockfd,data,499);
    			if (n < 0)
    			{
        			perror("ERROR reading from socket");
        			exit(1);
    			}
			
                	in=data;
			assert(in[0] == '\x81');
			packet_length = ((unsigned char) in[1]) & 0x7f;
                	//printf("\nPacket length : %d\n", packet_length);
			mask[0] = in[2];
			mask[1] = in[3];
			mask[2] = in[4];
			mask[3] = in[5];
                	if(packet_length <= 126)
			{                      
				/* Unmask the payload. */
				for (i = 0; i < packet_length; i++)
				in[6 + i] ^= mask[i % 4];
			  	rc = asprintf(&buffr, "%.*s", packet_length, in + 6); 
			}
			else if(packet_length == 127)
			{            
	  			/* Unmask the payload. */
	  			for (i = 0; i < packet_length; i++)
	   			 in[8 + i] ^= mask[i % 4];
	  			rc = asprintf(&buffr, "%.*s", packet_length, in + 8);
			}
	

			printf("Here is the message from client :\n%s\n",buffr);
			strcpy(message,"Hello Client (from server)");                
			/* Framing data to be sent to client */
			frame[0] = '\x81';
			frame[1] = 128 + strlen(message);
			frame[2] = '\x00';
			frame[3] = '\x00';
			frame[4] = '\x00';
			frame[5] = '\x00';
			snprintf(frame+6, 124, "%s", message);
                	n = write(newsockfd, frame, 6+strlen(message));
			
      		}	
      	};     
    return 0; 	
}

/* Function to convert hash into base 64*/
char *base64(const unsigned char *input, int length)
{
BIO *bmem, *b64;
BUF_MEM *bptr;

b64 = BIO_new(BIO_f_base64());
bmem = BIO_new(BIO_s_mem());
b64 = BIO_push(b64, bmem);
BIO_write(b64, input, length);
BIO_flush(b64);
BIO_get_mem_ptr(b64, &bptr);

char *buff = (char *)malloc(bptr->length);
memcpy(buff, bptr->data, bptr->length-1);
buff[bptr->length-1] = 0;

BIO_free_all(b64);

return buff;
}
