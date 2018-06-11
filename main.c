// Katedra: Katedra za racunarsku tehniku i racunarske komunikacije
// Predmet: Osnovi racunarskih mreza 2
// Godina studija: III godina
// Semestar: Letnji (VI)
// Skolska godina: 2015/2016
// Datoteka: project.c

#ifdef _MSC_VER
/*
* we do not want the warnings about the old deprecated and unsecure CRT functions
* since these examples can be compiled under *nix as well
*/
#define _CRT_SECURE_NO_WARNINGS
#else
#include <stdlib.h>
#include <netinet/in.h>
#include<net/ethernet.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <time.h>
#include "arpa/inet.h"
#endif
#include <string.h>

#define min(a,b) ((a) < (b) ? (a) : (b))

#include "pcap.h"
#include <pthread.h>

void server_init(char *recvfile);
void client_init(char* send_file);
pthread_mutex_t mutex;

#define SIGNATURE 54654
#define ACK_TRIES 10
char ip_src[][64]={"10.81.2.102"};
char ip_dst[][64]={"10.81.2.94"};
char devices_client[][64] = { "eth0", "wlan0" };
char devices_server[][64] = { "eth0", "wlan1" };
#define N_DEVICES 2
pthread_t threads[N_DEVICES];
// za klijenta (i server koristi iste podatke samo ih cita obrnuto)
char macs[][6] = {
        "\x2c\x4d\x54\xd0\x63\xb8",// dmac dev0  2c:4d:54:56:99:eb
        "\x2c\x4d\x54\x56\x99\xeb", // smac dev0



        "\x00\x0f\x60\x05\x53\x94",// dmac dev1 00:0f:60:06:07:14
        "\x00\x0f\x60\x04\x51\xe2" // smac dev1  b8:27:eb:b9:80:45
};
struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};


int main(int argc, char* argv[])
{
    pthread_mutex_init(&mutex,NULL);
    if (argc != 3) return 0;
    char* filename = argv[2];
    char* role = argv[1];
    if (strcmp(role, "server") == 0) {
        printf("setting up server\n");
        server_init(filename);
    } else {
        printf("setting up client\n");
        client_init(filename);
    }
    pthread_mutex_destroy(&mutex);

    struct ethhdr;
    return 0;
}


FILE* file;
#define PACKET_SIZE 1400
int file_size;

int *packets;


struct t_context {
    char smac[6];
    char dmac[6];
    char name[6];
    pcap_t* p;
};

typedef struct t_context context;
int packet_num;
#define MAC_HEADER 12

enum packet_type {
    pkt_ack,
    pkt_data,
    pkt_init,
    pkt_eof
};

enum {
    SENT,
    UNSENT
};

struct eth_header {
    char dmac[6];
    char smac[6];
    short type;
};

struct my_header {
    // handled by packet_process
    enum packet_type type;
    int signature;
    int data_size;
    int sum;

    // manual
    int ack_id;
    int offset;
};

struct packet {
    struct ethhdr ethernet;
    //struct eth_header ethernet;
    struct ip ip2;
    struct udphdr udp_hdr;
    struct my_header header;
    char data[PACKET_SIZE];
}__attribute__((packed));

void print_mac(char* mac) {
    int i;
    for (i = 0; i < 6; i++) {
        printf("%X:", (unsigned char)mac[i]);
    }
}
unsigned short
in_cksum(unsigned short *addr, int len)
{
    register int sum = 0;
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;
    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
    /* mop up an odd byte, if necessary */
    if (nleft == 1)
    {
        *(u_char *)(&answer) = *(u_char *) w;
        sum += answer;
    }
    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
    sum += (sum >> 16);             /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    return (answer);
}

void
ip_output(struct ip *ip_header, int len)
{



    ip_header->ip_v= 4;
    ip_header->ip_hl= 5;
    ip_header->ip_tos =htons (0x0004);
    ip_header->ip_len = htons(len);
    ip_header->ip_id = htons(0x0001);
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 64;
    ip_header->ip_p = IPPROTO_UDP;
    ip_header->ip_sum = htons(0x0000);
    ip_header->ip_src.s_addr = /*inet_addr("10.81.31.51");*/ inet_addr("10.81.2.102");
    ip_header->ip_dst.s_addr = /* inet_addr("10.81.31.49");;*/inet_addr("10.81.2.94");

    ip_header->ip_sum = in_cksum((unsigned short *) ip_header, sizeof(struct ip));

}
int wait_for_ack(pcap_t* p, int ack_id) {
    struct pcap_pkthdr d;
    int i;
    for (i = 0; i < ACK_TRIES; i++) {
        const char* data = pcap_next(p, &d);

        if (!data) continue;
        struct packet *pkt = (struct packet*)data;
        if (pkt->header.signature != SIGNATURE) continue;

        printf("Received: %d,  %d = %d (", pkt->header.type, pkt->header.ack_id, ack_id,")");
        /*   printf("D=");
           print_mac(pkt->ethernet.dmac);
           printf("\t");
           printf("S=");
           print_mac(pkt->ethernet.smac);
           printf(") \n");*/

        if (pkt->header.type == pkt_ack) {
            if (pkt->header.ack_id == ack_id) {
                return 1;
            }
        }
    }
    return 0;
}



int packet_size(const struct packet* pkt) {
    return sizeof(struct packet) + pkt->header.data_size - PACKET_SIZE;
}

void packet_process(struct packet* pkt, enum packet_type type, int data_size) {

    int size = sizeof(struct iphdr)+sizeof(struct udphdr)+data_size+sizeof(struct my_header);
    pkt->ethernet.h_proto = htons(0x0800);
    ip_output(&pkt->ip2,size);
    pkt->udp_hdr.uh_dport=htons(0x5000);
    pkt->udp_hdr.uh_sport=htons(0x5000);

    if(data_size==0){
        pkt->udp_hdr.uh_ulen=htons(8+sizeof(struct my_header));
    }else{

        pkt->udp_hdr.uh_ulen=htons(8 + data_size+sizeof(struct my_header));
    }

    pkt->udp_hdr.uh_sum=htons(0x00000000);



    pkt->header.signature = SIGNATURE;
    pkt->header.data_size = data_size;

    pkt->header.sum = 0;
    pkt->header.type = type;
    for(int i=0; i < data_size; i++) {
        pkt->header.sum += pkt->data[i];
    }
    struct pseudo_header psh;
    //Now the UDP checksum using the pseudo header
    psh.source_address = htons(0x00000000);
    psh.dest_address = 0xFFFFFFFF;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr) +  data_size );


    pkt->udp_hdr.uh_sum=htons(0x3423);

}



void send_packet(pcap_t* p, struct packet* pkt, enum packet_type type, int data_size) {
    packet_process(pkt, type, data_size);
    printf("Sending packet size: %d (", pkt->header.data_size);
    printf("D=");
       print_mac(pkt->ethernet.h_dest);
       printf("\t");
       printf("S=");
       print_mac(pkt->ethernet.h_source);
       printf(")\n");
    pcap_sendpacket(p, (const u_char*)pkt, packet_size(pkt));
}

void send_ack(context* t, int ack_id) {
    struct packet pkt;
    memcpy(pkt.ethernet.h_dest, t->dmac, 6);
    memcpy(pkt.ethernet.h_source, t->smac, 6);

    pkt.header.ack_id = ack_id;
    send_packet(t->p, &pkt, pkt_ack, 0);
}




void client(context *c) {
    int i;
    int packet_to_send = -1;
    struct packet pkt;
    memcpy(pkt.ethernet.h_dest, c->dmac, 6);
    memcpy(pkt.ethernet.h_source, c->smac, 6);
    /* memcpy(pkt.ethernet.dmac, c->dmac, 6);
     memcpy(pkt.ethernet.smac, c->smac, 6);*/
    printf("Sending file with size %d\n", file_size);
    int ack_id = 0;
    while (1) {
        packet_to_send = -1;

        // pronadji paket za slanje
        for (i = 0; i < packet_num; i++) {
            if (packets[i] == UNSENT) {
                packet_to_send = i;
                break;
            }
        }
        if (packet_to_send == -1) {
            send_packet(c->p, &pkt, pkt_eof, 0);
            return;
        }
        printf("Sending packet %d\n", packet_to_send);
        int size = min(PACKET_SIZE, file_size - PACKET_SIZE*packet_to_send);

        // ucitaj paket
        pthread_mutex_lock(&mutex);
        fseek(file, packet_to_send*PACKET_SIZE, SEEK_SET);
        fread(pkt.data, 1, size, file);
        pthread_mutex_unlock(&mutex);
        pkt.header.offset = packet_to_send*PACKET_SIZE;
        pkt.header.ack_id = rand() % 5000;
        send_packet(c->p, &pkt, pkt_data, size);
        ack_id = pkt.header.ack_id;

        if (wait_for_ack(c->p, ack_id)) {
            packets[packet_to_send] = SENT;
            printf("Marking as sent\n");
        }
        else {

            printf("ACK not received, waiting for ACK\n");
        }
    }
}


void client_init(char* send_file) {

    char errbuf[PCAP_ERRBUF_SIZE];

    int i;
    pcap_t *dev[N_DEVICES];
    for (i = 0; i < N_DEVICES; i++) {
        if ((dev[i] = pcap_open_live(devices_client[i],	// name of the device
                                     65536,			// portion of the packet to capture.
                // 65536 grants that the whole packet will be captured on all the MACs.
                                     1,				// promiscuous mode (nonzero means promiscuous)
                                     1000,			// read timeout
                                     errbuf			// error buffer
        )) == NULL)
        {
            fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", devices_client[i]);

            fprintf(stderr, "supported devices are: \n");
            pcap_if_t* alldevs;
            pcap_if_t* d;
            /* Retrieve the device list */
            if (pcap_findalldevs(&alldevs, errbuf) == -1)
            {
                fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
                exit(1);
            }
            /* Print the list */
            for (d = alldevs; d; d = d->next)
            {
                fprintf(stderr, "%d. %s", ++i, d->name);
                if (d->description)
                    fprintf(stderr, " (%s)\n", d->description);
                else
                    fprintf(stderr, " (No description available)\n");
            }
            /* Free the device list */
            pcap_freealldevs(alldevs);
            return;
        }
    }

    pthread_t threads[N_DEVICES];
    context ctx[N_DEVICES];
    file = fopen(send_file, "rb");
    if (!file)  {
        printf("file %s not found\n", send_file);
        return;
    }
    int size;
    fseek(file, 0, SEEK_END);
    size = ftell(file);
    file_size = size;
    packet_num = (size / PACKET_SIZE + 1);
    printf("packet_num: %d\n", packet_num);
    packets = (int*)malloc(sizeof(int)* packet_num);
    for (i = 0; i < packet_num; i++) {
        packets[i] = UNSENT;
    }

    printf("Creating threads\n");
    time_t start, end;
    double seconds;
    time(&start);
    for (i = 0; i < N_DEVICES; i++) {
        ctx[i].p = dev[i];
        memcpy(ctx[i].dmac, macs[i * 2], 6);
        memcpy(ctx[i].smac, macs[i * 2 + 1], 6);
        pthread_create(&threads[i], NULL,(void *)client, &ctx[i]);
    }
    printf("Waiting for transfer to finish\n");
    for (i = 0; i < N_DEVICES; i++) {
        pthread_join(threads[i], 0);
    }time(&end);

    seconds = difftime(end, start);
    printf("File transfer took %.2lf seconds to run.\n", seconds);
    printf("Sending finished\n");

    free(packets);


}


void server(context *c) {
    struct pcap_pkthdr d;
    struct packet *pkt;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char * data;
   // struct t_context *c=m;
    int mac_initialized = 0;
    while (1) {
      int err  = pcap_next_ex(c->p, &d,&data);


        if(err == 0)
            continue;
        if (err == -1) {
            c->p = NULL;

            do {
                printf("Hello someone touched things\n");

                c->p = pcap_open_live(c->name, 65536,            // portion of the packet to capture.
                        // 65536 grants that the whole packet will be captured on all the MACs.
                                      1,                // promiscuous mode (nonzero means promiscuous)
                                      1000,            // read timeout
                                      errbuf);
            } while (c->p == NULL);
        }
        if (!data) continue;


        pkt = (struct packet*)data;
        if(pkt->header.signature != SIGNATURE) continue;

        if(mac_initialized == 0) {
            memcpy(c->smac, pkt->ethernet.h_dest, 6);
            memcpy(c->dmac, pkt->ethernet.h_source, 6);
            /* memcpy(c->dmac, pkt->ethernet.smac, 6);
             memcpy(c->smac, pkt->ethernet.dmac, 6);*/
            mac_initialized = 1;
        }
        printf("Received pkt type %d %d\n", pkt->header.type, pkt->header.offset);
        if (pkt->header.type == pkt_data) {
            pthread_mutex_lock(&mutex);
            printf("Writing data: offs: %d size: %d\n", pkt->header.offset, pkt->header.data_size);
            fseek(file, pkt->header.offset, SEEK_SET);
            fwrite(pkt->data, 1, pkt->header.data_size, file);
            pthread_mutex_unlock(&mutex);
            send_ack(c, pkt->header.ack_id);
        }
        else if (pkt->header.type == pkt_eof) {
            break;
        }
        printf("Waiting for next pkt\n");
    }

}

void server_init(char *recvfile) {

    char errbuf[PCAP_ERRBUF_SIZE];

    int i;
    pcap_t *dev[N_DEVICES];
    for (i = 0; i < N_DEVICES; i++) {
        if ((dev[i] = pcap_open_live(devices_server[i],	// name of the device
                                     65536,			// portion of the packet to capture.
                // 65536 grants that the whole packet will be captured on all the MACs.
                                     1,				// promiscuous mode (nonzero means promiscuous)
                                     1000,			// read timeout
                                     errbuf			// error buffer
        )) == NULL)
        {
            fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", devices_server[i]);
            /* Free the device list */
            return;
        }
    }


    struct t_context mak[N_DEVICES];
    file = fopen(recvfile, "wb");

    for (i = 0; i < N_DEVICES; i++) {
        mak[i].p=dev[i];

        memcpy(mak[i].dmac, macs[i * 2 + 1], 6);
        memcpy(mak[i].smac, macs[i * 2], 6);
        strcpy(mak[i].name,devices_server[i]);
        pthread_create(&threads[i], NULL,(void *)server, &mak[i]);
    }

    for (i = 0; i < N_DEVICES; i++) {
        pthread_join(threads[i], 0);
    }

    printf("Receiving finished\n");
    for (i = 0; i < N_DEVICES; i++) {
        pcap_close(dev[i]);
    }


    fclose(file);
}
