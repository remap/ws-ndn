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

/* Function to convert hash into base 64*/
char *base64(const unsigned char *input, int length);

int main( int argc, char *argv[] )
{
    int sockfd, newsockfd, portno, clilen,len,n;
    char buffer[256], buf[26];
    struct sockaddr_in serv_addr, cli_addr;
    char handshake[360];
    char message[360];
    char *handshake_part2, *handshake_part3,*key,*magic,*final;
    const void *hand;
    unsigned char hash [20];
    int handshaken = 0;
    
    /* First call to socket() function */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
    {
        perror("ERROR opening socket");
        exit(1);
    }
    
    /* Initialize socket structure */
    bzero((char *) &serv_addr, sizeof(serv_addr));
    portno = 5001;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);
 
    /* Now bind the host address using bind() call.*/
    if (bind(sockfd, (struct sockaddr *) &serv_addr,
                          sizeof(serv_addr)) < 0)
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
    newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, 
                                &clilen);
    if (newsockfd < 0) 
    {
        perror("ERROR on accept");
        exit(1);
    }
    
    /* If connection is established then start communicating */
    
    while (1)

	if (handshaken == 0)
	{
		bzero(buffer,256);
    		n = read( newsockfd,buffer,255 );
    		if (n < 0)
    		{
        		perror("ERROR reading from socket");
        		exit(1);
    		}
    		printf("Here is the message:\n%s\n",buffer);
    		
                /* Preparing http request response to establish socket */
   		key=strndup(buffer+98, 24);
   		magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    		final = strcat(key,magic);
    		SHA1(final,strlen(final),hash);
    		handshake_part2= base64(hash, sizeof(hash));
     
    		strcpy (handshake,"HTTP/1.1 101 Web Socket Protocol Handshake\nUpgrade: Websocket\nConnection: Upgrade\nSec-WebSocket-Accept: ");
    		strcat(handshake,handshake_part2);
    		handshake_part3="\nWebSocket-Origin: http://localhost:80\nWebSocket-Location: ws://localhost:80/\r\n\r\n";
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
		bzero(buffer,256);
    		n = read( newsockfd,buffer,255 );
    		if (n < 0)
    		{
        		perror("ERROR reading from socket");
        		exit(1);
    		}
		len=strlen(buffer);
    		printf("%d",len);
                printf("Here is the message:\n%s\n",buffer);
                strcpy(message,"Server here !");
                n = write(newsockfd, message, strlen(message));
      	}     
    return 0; 
}

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
