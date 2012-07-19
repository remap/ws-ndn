/**
 * @file ccnd_stats.c
 *
 * Statistics presentation for ccnd.
 *
 * Part of ccnd - the CCNx Daemon.
 *
 * Copyright (C) 2008-2011 Palo Alto Research Center, Inc.
 *
 * This work is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation.
 * This work is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details. You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include <ccn/ccn.h>
#include <ccn/ccnd.h>
#include <ccn/charbuf.h>
#include <ccn/coding.h>
#include <ccn/indexbuf.h>
#include <ccn/schedule.h>
#include <ccn/sockaddrutil.h>
#include <ccn/hashtb.h>
#include <ccn/uri.h>
//
#include <sys/types.h> 
#include <netinet/in.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <assert.h>
//
#include "ccnd_private.h"

#define CRLF "\r\n"
#define NL   "\n"

/**
 * Provide a way to monitor rates.
 */
struct ccnd_meter {
    uintmax_t total;
    char what[8];
    unsigned rate; /** a scale factor applies */
    unsigned lastupdate;
};

struct ccnd_stats {
    long total_interest_counts;
    long total_flood_control;      /* done propagating, still recorded */
};

static int ccnd_collect_stats(struct ccnd_handle *h, struct ccnd_stats *ans);
static struct ccn_charbuf *collect_stats_html(struct ccnd_handle *h);
static void send_http_response(struct ccnd_handle *h, struct face *face,
                               const char *mime_type,
                               struct ccn_charbuf *response);
static struct ccn_charbuf *collect_stats_html(struct ccnd_handle *h);
static struct ccn_charbuf *collect_stats_xml(struct ccnd_handle *h);

/* HTTP */

static const char *resp404 =
    "HTTP/1.1 404 Not Found" CRLF
    "Connection: close" CRLF CRLF;

static const char *resp405 =
    "HTTP/1.1 405 Method Not Allowed" CRLF
    "Connection: close" CRLF CRLF;

static void
ccnd_stats_http_set_debug(struct ccnd_handle *h, struct face *face, int level)
{
    struct ccn_charbuf *response = ccn_charbuf_create();
    
    h->debug = 1;
    ccnd_msg(h, "CCND_DEBUG=%d", level);
    h->debug = level;
    ccn_charbuf_putf(response, "<title>CCND_DEBUG=%d</title><tt>CCND_DEBUG=%d</tt>" CRLF, level, level);
    send_http_response(h, face, "text/html", response);
    ccn_charbuf_destroy(&response);
}
//

char *base64(const unsigned char *input, int length)
{
BIO *bmem, *b64;
BUF_MEM *bptr;
char *buff;
b64 = BIO_new(BIO_f_base64());
bmem = BIO_new(BIO_s_mem());
b64 = BIO_push(b64, bmem);
BIO_write(b64, input, length);
BIO_flush(b64);
BIO_get_mem_ptr(b64, &bptr);

buff = (char *)malloc(bptr->length);
memcpy(buff, bptr->data, bptr->length-1);
buff[bptr->length-1] = 0;

BIO_free_all(b64);

return buff;
};


///////Modified


/*Function to establish web socket by making http handshake */

int
ccnd_handle_http_websocket_connection_handshake(struct ccnd_handle *h, struct face *face)
{
    int i,j,n;
    char rbuf[656];
    int len;
    char handshake[800],key[80];
    char *handshake_part2, *handshake_part3,*magic,*final;
    unsigned char hash[20];
    if (face->inbuf->length < 4)
        return(-1);
    if ((face->flags & CCN_FACE_NOSEND) != 0) {
        ccnd_destroy_face(h, face->faceid);
        printf(" face killed");
        return(-1);
    }
    n = sizeof(rbuf) - 1;
    if (face->inbuf->length < n)
        n = face->inbuf->length;
    for (i = 0; i < n; i++) {
        rbuf[i] = face->inbuf->buf[i];
    }
    rbuf[i]='\0';
    printf("\nHTTP Request Header :\n%s",rbuf);
    /* Preparing http request response to establish web socket */
    //key = (char *) malloc(130);
    for(i=359,j=0;i<383;i++,j++)
    key[j]=rbuf[i];                           // Extracting WebSocket-Key 
    key[j]='\0';
    magic=(char *)"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    strcat(key,magic);                          //Appending magic key to WebSocket-Key   
    SHA1(key,strlen(key),hash);                     //String hashing by SHA 1
    //handshake_part2= (char *) malloc(40);
    handshake_part2= base64(hash, sizeof(hash));        // Encoding the SHA-1 hash by Base64
    strcpy(handshake, "HTTP/1.1 101 Web Socket Protocol Handshake\r\nUpgrade: Websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ");
    strcat(handshake,handshake_part2);
    handshake_part3="\r\nWebSocket-Origin: http://localhost:9695\r\nWebSocket-Location: ws://localhost:9695/\r\n\r\n";
    strcat(handshake,handshake_part3);
    printf("Response Header :\n%s", handshake);
    
    /*face->flags |= CCN_FACE_PERMANENT;             // Not sure if this could be used
    if ((face->flags & CCN_FACE_PERMANENT) != 0)
         printf("CCN_FACE_PERMANENT bit set !\n");*/
    ccnd_send(h, face, handshake, strlen(handshake));
    //face->flags &= ~CCN_FACE_UNDECIDED; 
    if ((face->flags & CCN_FACE_UNDECIDED) == 0){
         printf("CCN_FACE_UNDECIDED bit cleared !\n");
    }     
    //if ((face->flags & CCN_FACE_CLOSING) == 0)
    //     printf("CCN_FACE_CLOSING bit not set !\n");
    //printf("\n Returning back ! %s", handshake);
    //face->flags |=(CCN_FACE_NOSEND | CCN_FACE_CLOSING);    
    //free(key);
    //free(handshake_part2);
    return (0); 	
 }
   
/*Function to handle data transmission on established web socket*/

int
ccnd_handle_http_websocket_connection_data(struct ccnd_handle *h, struct face *face)
{
    int n;
    char rbuf[656];
    
    /* For masking and unmasking data sent or recieved*/
    char *in, *buffr;
    unsigned int i,j;
    unsigned char mask[4];
    unsigned int packet_length = 0;
    int rc;
    char frame[131];
    char message[360];
    
    if (face->inbuf->length < 4)
        return(-1);
    if ((face->flags & CCN_FACE_NOSEND) != 0) {
        ccnd_destroy_face(h, face->faceid);
        return(-1);
    }
    n = sizeof(rbuf) - 1;
    if (face->inbuf->length < n)
        n = face->inbuf->length;
    for (i = 534,j=0; i < n; i++,j++) {
        rbuf[j] = face->inbuf->buf[i];
    }

     in=rbuf;
     assert(in[0] == '\x81');
     packet_length = ((unsigned char) in[1]) & 0x7f;
     printf("\nPacket length : %d\n", packet_length);
     mask[0] = in[2];
     mask[1] = in[3];
     mask[2] = in[4];
     mask[3] = in[5];
     //buffr=(char *)malloc(200);
     //if(buffr==NULL)
     //    printf("Error allocating memory to buffr");
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
     //free(buffr);
     strcpy(message,"Hello Client (from server)");                
     printf("Message :%s",message);
     /* Framing data to be sent to client */
     frame[0] = '\x81';
     frame[1] = 128 + strlen(message);
     frame[2] = '\x00';
     frame[3] = '\x00';
     frame[4] = '\x00';
     frame[5] = '\x00';
     snprintf(frame+6, 124, "%s", message);
     printf("Message :%s",message);
     ccnd_send(h, face, message, strlen(message));
     printf("Message sent to client !");
     face->flags &= ~CCN_FACE_UNDECIDED; 
     //if ((face->flags & CCN_FACE_UNDECIDED) == 0)
       //  printf("CCN_FACE_UNDECIDED bit cleared %s\n", message);
     //face->flags |= (CCN_FACE_NOSEND | CCN_FACE_CLOSING);
     
     return (0);
}


//////    
    
int
ccnd_stats_handle_http_connection(struct ccnd_handle *h, struct face *face)
{
    struct ccn_charbuf *response = NULL;
    char rbuf[16];
    int i;
    int nspace;
    int n;
    
    if (face->inbuf->length < 4)
        return(-1);
    if ((face->flags & CCN_FACE_NOSEND) != 0) {
        ccnd_destroy_face(h, face->faceid);
        return(-1);
    }
    n = sizeof(rbuf) - 1;
    if (face->inbuf->length < n)
        n = face->inbuf->length;
    for (i = 0, nspace = 0; i < n && nspace < 2; i++) {
        rbuf[i] = face->inbuf->buf[i];
        if (rbuf[i] == ' ')
            nspace++;
    }
    rbuf[i] = 0;
    if (nspace < 2 && i < sizeof(rbuf) - 1)
        return(-1);
    if (0 == strcmp(rbuf, "GET / ") ||  0 == strcmp(rbuf, "GET /? ")) {
        response = collect_stats_html(h);
        send_http_response(h, face, "text/html", response);
    }
    else if (0 == strcmp(rbuf, "GET /?l=none ")) {
        ccnd_stats_http_set_debug(h, face, 0);
    }
    else if (0 == strcmp(rbuf, "GET /?l=low ")) {
        ccnd_stats_http_set_debug(h, face, 1);
    }
    else if (0 == strcmp(rbuf, "GET /?l=co ")) {
        ccnd_stats_http_set_debug(h, face, 4);
    }
    else if (0 == strcmp(rbuf, "GET /?l=med ")) {
        ccnd_stats_http_set_debug(h, face, 71);
    }
    else if (0 == strcmp(rbuf, "GET /?l=high ")) {
        ccnd_stats_http_set_debug(h, face, -1);
    }
    else if (0 == strcmp(rbuf, "GET /?f=xml ")) {
        response = collect_stats_xml(h);
        send_http_response(h, face, "text/xml", response);
    }
    else if (0 == strcmp(rbuf, "GET "))
        ccnd_send(h, face, resp404, strlen(resp404));
    else
        ccnd_send(h, face, resp405, strlen(resp405));
    face->flags |= (CCN_FACE_NOSEND | CCN_FACE_CLOSING);
    ccn_charbuf_destroy(&response);
    return(0);
}

static void
send_http_response(struct ccnd_handle *h, struct face *face,
                   const char *mime_type, struct ccn_charbuf *response)
{
    struct linger linger = { .l_onoff = 1, .l_linger = 1 };
    char buf[128];
    int hdrlen;

    /* Set linger to prevent quickly resetting the connection on close.*/
    setsockopt(face->recv_fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger));
    hdrlen = snprintf(buf, sizeof(buf),
                      "HTTP/1.1 200 OK" CRLF
                      "Content-Type: %s; charset=utf-8" CRLF
                      "Connection: close" CRLF
                      "Content-Length: %jd" CRLF CRLF,
                      mime_type,
                      (intmax_t)response->length);
    ccnd_send(h, face, buf, hdrlen);
    ccnd_send(h, face, response->buf, response->length);
}

/* Common statistics collection */

static int
ccnd_collect_stats(struct ccnd_handle *h, struct ccnd_stats *ans)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    long sum;
    unsigned i;
    for (sum = 0, hashtb_start(h->nameprefix_tab, e);
         e->data != NULL; hashtb_next(e)) {
        struct nameprefix_entry *npe = e->data;
        struct propagating_entry *head = &npe->pe_head;
        struct propagating_entry *p;
        for (p = head->next; p != head; p = p->next) {
            if (ccnd_face_from_faceid(h, p->faceid) != NULL)
                sum += 1;
        }
    }
    ans->total_interest_counts = sum;
    hashtb_end(e);
    for (sum = 0, hashtb_start(h->propagating_tab, e);
         e->data != NULL; hashtb_next(e)) {
        struct propagating_entry *pe = e->data;
        if (pe->interest_msg == NULL)
            sum += 1;
    }
    ans->total_flood_control = sum;
    hashtb_end(e);
    /* Do a consistency check on pending interest counts */
    for (sum = 0, i = 0; i < h->face_limit; i++) {
        struct face *face = h->faces_by_faceid[i];
        if (face != NULL)
            sum += face->pending_interests;
    }
    if (sum != ans->total_interest_counts)
        ccnd_msg(h, "ccnd_collect_stats found inconsistency %ld != %ld\n",
                 (long)sum, (long)ans->total_interest_counts);
    ans->total_interest_counts = sum;
    return(0);
}

/* HTML formatting */

static void
collect_faces_html(struct ccnd_handle *h, struct ccn_charbuf *b)
{
    int i;
    struct ccn_charbuf *nodebuf;
    int port;
    
    nodebuf = ccn_charbuf_create();
    ccn_charbuf_putf(b, "<h4>Faces</h4>" NL);
    ccn_charbuf_putf(b, "<ul>");
    for (i = 0; i < h->face_limit; i++) {
        struct face *face = h->faces_by_faceid[i];
        if (face != NULL && (face->flags & CCN_FACE_UNDECIDED) == 0) {
            ccn_charbuf_putf(b, " <li>");
            ccn_charbuf_putf(b, "<b>face:</b> %u <b>flags:</b> 0x%x",
                             face->faceid, face->flags);
            ccn_charbuf_putf(b, " <b>pending:</b> %d",
                             face->pending_interests);
            if (face->recvcount != 0)
                ccn_charbuf_putf(b, " <b>activity:</b> %d",
                                 face->recvcount);
            nodebuf->length = 0;
            port = ccn_charbuf_append_sockaddr(nodebuf, face->addr);
            if (port > 0) {
                const char *node = ccn_charbuf_as_string(nodebuf);
                int chk = CCN_FACE_MCAST | CCN_FACE_UNDECIDED |
                CCN_FACE_NOSEND | CCN_FACE_GG | CCN_FACE_PASSIVE;
                if ((face->flags & chk) == 0)
                    ccn_charbuf_putf(b,
                                     " <b>remote:</b> "
                                     "<a href='http://%s:%s/'>"
                                     "%s:%d</a>",
                                     node, CCN_DEFAULT_UNICAST_PORT,
                                     node, port);
                else if ((face->flags & CCN_FACE_PASSIVE) == 0)
                    ccn_charbuf_putf(b, " <b>remote:</b> %s:%d",
                                     node, port);
                else
                    ccn_charbuf_putf(b, " <b>local:</b> %s:%d",
                                     node, port);
                if (face->sendface != face->faceid &&
                    face->sendface != CCN_NOFACEID)
                    ccn_charbuf_putf(b, " <b>via:</b> %u", face->sendface);
            }
            ccn_charbuf_putf(b, "</li>" NL);
        }
    }
    ccn_charbuf_putf(b, "</ul>");
    ccn_charbuf_destroy(&nodebuf);
}

static void
collect_face_meter_html(struct ccnd_handle *h, struct ccn_charbuf *b)
{
    int i;
    ccn_charbuf_putf(b, "<h4>Face Activity Rates</h4>");
    ccn_charbuf_putf(b, "<table cellspacing='0' cellpadding='0' class='tbl' summary='face activity rates'>");
    ccn_charbuf_putf(b, "<tbody>" NL);
    ccn_charbuf_putf(b, " <tr><td>        </td>\t"
                        " <td>Bytes/sec In/Out</td>\t"
                        " <td>recv data/intr sent</td>\t"
                        " <td>sent data/intr recv</td></tr>" NL);
    for (i = 0; i < h->face_limit; i++) {
        struct face *face = h->faces_by_faceid[i];
        if (face != NULL && (face->flags & (CCN_FACE_UNDECIDED|CCN_FACE_PASSIVE)) == 0) {
            ccn_charbuf_putf(b, " <tr>");
            ccn_charbuf_putf(b, "<td><b>face:</b> %u</td>\t",
                             face->faceid);
            ccn_charbuf_putf(b, "<td>%6u / %u</td>\t\t",
                                 ccnd_meter_rate(h, face->meter[FM_BYTI]),
                                 ccnd_meter_rate(h, face->meter[FM_BYTO]));
            ccn_charbuf_putf(b, "<td>%9u / %u</td>\t\t",
                                 ccnd_meter_rate(h, face->meter[FM_DATI]),
                                 ccnd_meter_rate(h, face->meter[FM_INTO]));
            ccn_charbuf_putf(b, "<td>%9u / %u</td>",
                                 ccnd_meter_rate(h, face->meter[FM_DATO]),
                                 ccnd_meter_rate(h, face->meter[FM_INTI]));
            ccn_charbuf_putf(b, "</tr>" NL);
        }
    }
    ccn_charbuf_putf(b, "</tbody>");
    ccn_charbuf_putf(b, "</table>");
}

static void
collect_forwarding_html(struct ccnd_handle *h, struct ccn_charbuf *b)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    struct ccn_forwarding *f;
    int res;
    struct ccn_charbuf *name = ccn_charbuf_create();
    
    ccn_charbuf_putf(b, "<h4>Forwarding</h4>" NL);
    ccn_charbuf_putf(b, "<ul>");
    hashtb_start(h->nameprefix_tab, e);
    for (; e->data != NULL; hashtb_next(e)) {
        struct nameprefix_entry *ipe = e->data;
        ccn_name_init(name);
        res = ccn_name_append_components(name, e->key, 0, e->keysize);
        if (res < 0)
            abort();
        if (0) {
            ccn_charbuf_putf(b, " <li>");
            ccn_uri_append(b, name->buf, name->length, 1);
            ccn_charbuf_putf(b, "</li>" NL);
        }
        for (f = ipe->forwarding; f != NULL; f = f->next) {
            if ((f->flags & (CCN_FORW_ACTIVE | CCN_FORW_PFXO)) != 0) {
                ccn_name_init(name);
                ccn_name_append_components(name, e->key, 0, e->keysize);
                ccn_charbuf_putf(b, " <li>");
                ccn_uri_append(b, name->buf, name->length, 1);
                ccn_charbuf_putf(b,
                                 " <b>face:</b> %u"
                                 " <b>flags:</b> 0x%x"
                                 " <b>expires:</b> %d",
                                 f->faceid,
                                 f->flags & CCN_FORW_PUBMASK,
                                 f->expires);
                ccn_charbuf_putf(b, "</li>" NL);
            }
        }
    }
    hashtb_end(e);
    ccn_charbuf_destroy(&name);
    ccn_charbuf_putf(b, "</ul>");
}

static unsigned
ccnd_colorhash(struct ccnd_handle *h)
{
    unsigned const char *a = h->ccnd_id;
    unsigned v;
    
    v = (a[0] << 16) + (a[1] << 8) + a[2];
    return (v | 0xC0C0C0);
}

static struct ccn_charbuf *
collect_stats_html(struct ccnd_handle *h)
{
    struct ccnd_stats stats = {0};
    struct ccn_charbuf *b = ccn_charbuf_create();
    int pid;
    struct utsname un;
    const char *portstr;
    
    portstr = getenv(CCN_LOCAL_PORT_ENVNAME);
    if (portstr == NULL || portstr[0] == 0 || strlen(portstr) > 10)
        portstr = CCN_DEFAULT_UNICAST_PORT;
    uname(&un);
    pid = getpid();
    
    ccnd_collect_stats(h, &stats);
    ccn_charbuf_putf(b,
        "<html xmlns='http://www.w3.org/1999/xhtml'>"
        "<head>"
        "<title>%s ccnd[%d]</title>"
        //"<meta http-equiv='refresh' content='3'>"
        "<style type='text/css'>"
        "/*<![CDATA[*/"
        "p.header {color: white; background-color: blue; width: 100%%} "
        "table.tbl {border-style: solid; border-width: 1.0px 1.0px 1.0px 1.0px; border-color: black} "
        "td {border-style: solid; "
            "border-width: 1.0px 1.0px 1.0px 1.0px; "
            "border-color: #808080 #808080 #808080 #808080; "
            "padding: 6px 6px 6px 6px; "
            "margin-left: auto; margin-right: auto; "
            "text-align: center"
            "} "
        "td.left {text-align: left} "
        "/*]]>*/"
        "</style>"
        "</head>" NL
        "<body bgcolor='#%06X'>"
        "<p class='header'>%s ccnd[%d] local port %s api %d start %ld.%06u now %ld.%06u</p>" NL
        "<div><b>Content items:</b> %llu accessioned,"
        " %d stored, %lu stale, %d sparse, %lu duplicate, %lu sent</div>" NL
        "<div><b>Interests:</b> %d names,"
        " %ld pending, %ld propagating, %ld noted</div>" NL
        "<div><b>Interest totals:</b> %lu accepted,"
        " %lu dropped, %lu sent, %lu stuffed</div>" NL,
        un.nodename,
        pid,
        ccnd_colorhash(h),
        un.nodename,
        pid,
        portstr,
        (int)CCN_API_VERSION,
        h->starttime, h->starttime_usec,
        h->sec,
        h->usec,
        (unsigned long long)h->accession,
        hashtb_n(h->content_tab),
        h->n_stale,
        hashtb_n(h->sparse_straggler_tab),
        h->content_dups_recvd,
        h->content_items_sent,
        hashtb_n(h->nameprefix_tab), stats.total_interest_counts,
        hashtb_n(h->propagating_tab) - stats.total_flood_control,
        stats.total_flood_control,
        h->interests_accepted, h->interests_dropped,
        h->interests_sent, h->interests_stuffed);
    if (0)
        ccn_charbuf_putf(b,
                         "<div><b>Active faces and listeners:</b> %d</div>" NL,
                         hashtb_n(h->faces_by_fd) + hashtb_n(h->dgram_faces));
    collect_faces_html(h, b);
    collect_face_meter_html(h, b);
    collect_forwarding_html(h, b);
    ccn_charbuf_putf(b,
        "</body>"
        "</html>" NL);
    return(b);
}

/* XML formatting */

static void
collect_meter_xml(struct ccnd_handle *h, struct ccn_charbuf *b, struct ccnd_meter *m)
{
    uintmax_t total;
    unsigned rate;
    
    if (m == NULL)
        return;
    total = ccnd_meter_total(m);
    rate = ccnd_meter_rate(h, m);
    ccn_charbuf_putf(b, "<%s><total>%ju</total><persec>%u</persec></%s>",
        m->what, total, rate, m->what);
}

static void
collect_faces_xml(struct ccnd_handle *h, struct ccn_charbuf *b)
{
    int i;
    int m;
    int port;
    struct ccn_charbuf *nodebuf;
    
    nodebuf = ccn_charbuf_create();
    ccn_charbuf_putf(b, "<faces>");
    for (i = 0; i < h->face_limit; i++) {
        struct face *face = h->faces_by_faceid[i];
        if (face != NULL && (face->flags & CCN_FACE_UNDECIDED) == 0) {
            ccn_charbuf_putf(b, "<face>");
            ccn_charbuf_putf(b,
                             "<faceid>%u</faceid>"
                             "<faceflags>%04x</faceflags>",
                             face->faceid, face->flags);
            ccn_charbuf_putf(b, "<pending>%d</pending>",
                             face->pending_interests);
            ccn_charbuf_putf(b, "<recvcount>%d</recvcount>",
                             face->recvcount);
            nodebuf->length = 0;
            port = ccn_charbuf_append_sockaddr(nodebuf, face->addr);
            if (port > 0) {
                const char *node = ccn_charbuf_as_string(nodebuf);
                ccn_charbuf_putf(b, "<ip>%s:%d</ip>", node, port);
            }
            if (face->sendface != face->faceid &&
                face->sendface != CCN_NOFACEID)
                ccn_charbuf_putf(b, "<via>%u</via>", face->sendface);
            if (face != NULL && (face->flags & CCN_FACE_PASSIVE) == 0) {
                ccn_charbuf_putf(b, "<meters>");
                for (m = 0; m < CCND_FACE_METER_N; m++)
                    collect_meter_xml(h, b, face->meter[m]);
                ccn_charbuf_putf(b, "</meters>");
            }
            ccn_charbuf_putf(b, "</face>" NL);
        }
    }
    ccn_charbuf_putf(b, "</faces>");
    ccn_charbuf_destroy(&nodebuf);
}

static void
collect_forwarding_xml(struct ccnd_handle *h, struct ccn_charbuf *b)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    struct ccn_forwarding *f;
    int res;
    struct ccn_charbuf *name = ccn_charbuf_create();
    
    ccn_charbuf_putf(b, "<forwarding>");
    hashtb_start(h->nameprefix_tab, e);
    for (; e->data != NULL; hashtb_next(e)) {
        struct nameprefix_entry *ipe = e->data;
        for (f = ipe->forwarding, res = 0; f != NULL && !res; f = f->next) {
            if ((f->flags & (CCN_FORW_ACTIVE | CCN_FORW_PFXO)) != 0)
                res = 1;
        }
        if (res) {
            ccn_name_init(name);
            ccn_name_append_components(name, e->key, 0, e->keysize);
            ccn_charbuf_putf(b, "<fentry>");
            ccn_charbuf_putf(b, "<prefix>");
            ccn_uri_append(b, name->buf, name->length, 1);
            ccn_charbuf_putf(b, "</prefix>");
            for (f = ipe->forwarding; f != NULL; f = f->next) {
                if ((f->flags & (CCN_FORW_ACTIVE | CCN_FORW_PFXO)) != 0) {
                    ccn_charbuf_putf(b,
                                     "<dest>"
                                     "<faceid>%u</faceid>"
                                     "<flags>%x</flags>"
                                     "<expires>%d</expires>"
                                     "</dest>",
                                     f->faceid,
                                     f->flags & CCN_FORW_PUBMASK,
                                     f->expires);
                }
            }
            ccn_charbuf_putf(b, "</fentry>");
        }
    }
    hashtb_end(e);
    ccn_charbuf_destroy(&name);
    ccn_charbuf_putf(b, "</forwarding>");
}

static struct ccn_charbuf *
collect_stats_xml(struct ccnd_handle *h)
{
    struct ccnd_stats stats = {0};
    struct ccn_charbuf *b = ccn_charbuf_create();
    int i;
        
    ccnd_collect_stats(h, &stats);
    ccn_charbuf_putf(b,
        "<ccnd>"
        "<identity>"
        "<ccndid>");
    for (i = 0; i < sizeof(h->ccnd_id); i++)
        ccn_charbuf_putf(b, "%02X", h->ccnd_id[i]);
    ccn_charbuf_putf(b, "</ccndid>"
        "<apiversion>%d</apiversion>"
        "<starttime>%ld.%06u</starttime>"
        "<now>%ld.%06u</now>"
        "</identity>",
        (int)CCN_API_VERSION,
        h->starttime, h->starttime_usec,
        h->sec,
        h->usec);
    ccn_charbuf_putf(b,
        "<cobs>"
        "<accessioned>%llu</accessioned>"
        "<stored>%d</stored>"
        "<stale>%lu</stale>"
        "<sparse>%d</sparse>"
        "<duplicate>%lu</duplicate>"
        "<sent>%lu</sent>"
        "</cobs>"
        "<interests>"
        "<names>%d</names>"
        "<pending>%ld</pending>"
        "<propagating>%ld</propagating>"
        "<noted>%ld</noted>"
        "<accepted>%lu</accepted>"
        "<dropped>%lu</dropped>"
        "<sent>%lu</sent>"
        "<stuffed>%lu</stuffed>"
        "</interests>",
        (unsigned long long)h->accession,
        hashtb_n(h->content_tab),
        h->n_stale,
        hashtb_n(h->sparse_straggler_tab),
        h->content_dups_recvd,
        h->content_items_sent,
        hashtb_n(h->nameprefix_tab), stats.total_interest_counts,
        hashtb_n(h->propagating_tab) - stats.total_flood_control,
        stats.total_flood_control,
        h->interests_accepted, h->interests_dropped,
        h->interests_sent, h->interests_stuffed);
    collect_faces_xml(h, b);
    collect_forwarding_xml(h, b);
    ccn_charbuf_putf(b, "</ccnd>" NL);
    return(b);
}

/**
 * create and initialize separately allocated meter.
 */
struct ccnd_meter *
ccnd_meter_create(struct ccnd_handle *h, const char *what)
{
    struct ccnd_meter *m;
    m = calloc(1, sizeof(*m));
    if (m == NULL)
        return(NULL);
    ccnd_meter_init(h, m, what);
    return(m);
}

/**
 * Destroy a separately allocated meter.
 */
void
ccnd_meter_destroy(struct ccnd_meter **pm)
{
    if (*pm != NULL) {
        free(*pm);
        *pm = NULL;
    }
}

/**
 * Initialize a meter.
 */
void
ccnd_meter_init(struct ccnd_handle *h, struct ccnd_meter *m, const char *what)
{
    if (m == NULL)
        return;
    memset(m, 0, sizeof(m));
    if (what != NULL)
        strncpy(m->what, what, sizeof(m->what)-1);
    ccnd_meter_bump(h, m, 0);
}

static const unsigned meterHz = 7; /* 1/ln(8/7) would give RC const of 1 sec */

/**
 * Count something (messages, packets, bytes), and roll up some kind of
 * statistics on it.
 */
void
ccnd_meter_bump(struct ccnd_handle *h, struct ccnd_meter *m, unsigned amt)
{
    unsigned now; /* my ticks, wrap OK */
    unsigned t;
    unsigned r;
    if (m == NULL)
        return;
    now = (((unsigned)(h->sec)) * meterHz) + (h->usec * meterHz / 1000000U);
    t = m->lastupdate;
    m->total += amt;
    if (now - t > 166U)
        m->rate = amt; /* history has decayed away */
    else {
        /* Decay the old rate exponentially based on time since last sample. */
        for (r = m->rate; t != now && r != 0; t++)
            r = r - ((r + 7U) / 8U); /* multiply by 7/8, truncating */
        m->rate = r + amt;
    }
    m->lastupdate = now;
}

/**
 * Return the average rate (units per second) of a metered quantity.
 *
 * m may be NULL.
 */
unsigned
ccnd_meter_rate(struct ccnd_handle *h, struct ccnd_meter *m)
{
    unsigned denom = 8;
    if (m == NULL)
        return(0);
    ccnd_meter_bump(h, m, 0);
    if (m->rate > 0x0FFFFFFF)
        return(m->rate / denom * meterHz);
    return ((m->rate * meterHz + (denom - 1)) / denom);
}

/**
 * Return the grand total for a metered quantity.
 *
 * m may be NULL.
 */
uintmax_t
ccnd_meter_total(struct ccnd_meter *m)
{
    if (m == NULL)
        return(0);
    return (m->total);
}
