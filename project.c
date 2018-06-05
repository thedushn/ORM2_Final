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
#include <time.h>
#endif
#include <string.h>

#define min(a,b) ((a) < (b) ? (a) : (b))

#include "pcap.h"
//#include "tinycthread.h"
#include "pthread.h"

void server_init(char *recvfile);
void client_init(char* send_file);
//mtx_t mutex;
pthread_mutex_t mutex;
#define SIGNATURE 1111 //54654
#define ACK_TRIES 10
//\\Device\\NPF_{95803CA8-BCA8-4E3D-923C-5868F019B9DE
char devices_client[][64] = { "eth0", "wlan1" };
char devices_server[][64] = { "eth0" ,"wlan1" };
#define N_DEVICES 2

// za klijenta (i server koristi iste podatke samo ih cita obrnuto)
char macs[][6] = {"\x2c\x4d\x54\x56\x99\xea",// dmac dev0
		  "\x2c\x4d\x54\x56\x99\xea",// smac dev0

		  "\x00\x0f\x60\x06\x07\x14",// dmac dev1 00:0f:60:06:07:14
		  "\x00\x0f\x60\x06\x07\x14" // smac dev1
		};


int main(int argc, char* argv[])
{
	pthread_mutex_init(&mutex,NULL);
	//mtx_init(&mutex, mtx_plain);
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

	//mtx_destroy(&mutex);
	return 0;
}


FILE* file;
#define PACKET_SIZE 1400
int file_size;

int *packets;


struct t_context {
	char smac[6];
	char dmac[6];
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
	struct eth_header ethernet;
	struct my_header header;
	char data[PACKET_SIZE];
};

void print_mac(char* mac) {
	int i;
	for (i = 0; i < 6; i++) {
		printf("%X:", (unsigned char)mac[i]);
	}
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
		printf("D=");
		print_mac(pkt->ethernet.dmac);
		printf("\t");
		printf("S=");
		print_mac(pkt->ethernet.smac);
		printf(") \n");

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
	int i;
	pkt->ethernet.type = htons(0x0800);
	pkt->header.signature = htons(SIGNATURE);
	
	pkt->header.data_size = data_size;
	pkt->header.sum = 0;
	pkt->header.type = type;
	for(i=0; i < data_size; i++) {
		pkt->header.sum += pkt->data[i];
	}
}

int packet_check(struct packet* pkt) {
	int i,sum;
	if(pkt->ethernet.type == 0x0800 &&
	   pkt->header.signature == SIGNATURE) {
		for(i=0,sum=0; i < pkt->header.data_size; i++) {
			sum += pkt->data[i];
		}
		if(sum == pkt->header.sum) {
			return 1;
		}
	}
	return 0;
}

void send_packet(pcap_t* p, struct packet* pkt, enum packet_type type, int data_size) {
	packet_process(pkt, type, data_size);
	printf("Sending packet size: %d (", pkt->header.data_size);
	printf("D=");
	print_mac(pkt->ethernet.dmac);
	printf("\t");
	printf("S=");
	print_mac(pkt->ethernet.smac);
	printf(")\n");
	printf("what the packet says%s\n",(u_char*)pkt);
	pcap_sendpacket(p, (const u_char*)pkt,packet_size(pkt)); // 
}

void send_ack(context* t, int ack_id) {
	struct packet pkt;
	memcpy(pkt.ethernet.dmac, t->dmac, 6);
	memcpy(pkt.ethernet.smac, t->smac, 6);
	pkt.header.ack_id = ack_id;
	send_packet(t->p, &pkt, pkt_ack, 0);
}




void client(context *c) {
	int i;
	int packet_to_send = -1;
	struct packet pkt;
	memcpy(pkt.ethernet.dmac, c->dmac, 6);
	memcpy(pkt.ethernet.smac, c->smac, 6);
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

		// ucitaj paket+
 		pthread_mutex_lock(&mutex);
		//mtx_lock(&mutex);
		fseek(file, packet_to_send*PACKET_SIZE, SEEK_SET);
		fread(pkt.data, 1, size, file);
		//mtx_unlock(&mutex);
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
			return;
		}
	}
	pthread_t threads[N_DEVICES];	
	//thrd_t threads[N_DEVICES];
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
	//	thrd_create(&threads[i], (thrd_start_t)client, &ctx[i]);
	}
	printf("Waiting for transfer to finish\n");
	for (i = 0; i < N_DEVICES; i++) {
			pthread_join(threads[i], 0);
		//thrd_join(threads[i], 0);
	}time(&end);
	int a;
	seconds = difftime(end, start);
	printf("File transfer took %.2lf seconds to run.\n", seconds);
	printf("Sending finished\n");
	//scanf("%d", &a);
	
}


void server(void* m) {
	struct pcap_pkthdr d;
	struct packet *pkt;
	int mac_initialized = 0;
	struct t_context *c=m;
	while (1) {
		const char * data = pcap_next(c->p, &d);
		
		if (!data) continue;
		
			
		pkt = (struct packet*)data;
		if(pkt->header.signature != SIGNATURE) continue;
		
		if(mac_initialized == 0) {
			memcpy(c->dmac, pkt->ethernet.smac, 6);
			memcpy(c->smac, pkt->ethernet.dmac, 6);
			mac_initialized = 1;
		}
		printf("Received pkt type %d %d\n", pkt->header.type, pkt->header.offset);
		if (pkt->header.type == pkt_data) {
			//mtx_lock(&mutex);
			pthread_mutex_lock(&mutex);
			printf("%s",pkt->data);
			printf("Writing data: offs: %d size: %d\n", pkt->header.offset, pkt->header.data_size);
			fseek(file, pkt->header.offset, SEEK_SET);
			fwrite(pkt->data, 1, pkt->header.data_size, file);
			//mtx_unlock(&mutex);
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

	pthread_t threads[N_DEVICES];
//	thrd_t threads[N_DEVICES];
	struct t_context mak[N_DEVICES];
//	context ctx[N_DEVICES];
	file = fopen(recvfile, "wb");

	for (i = 0; i < N_DEVICES; i++) {
		//ctx[i].p = dev[i];
		mak[i].p=dev[i];
	//	memcpy(ctx[i].dmac, macs[i * 2 + 1], 6);
	//	memcpy(ctx[i].smac, macs[i * 2], 6);
		memcpy(mak[i].dmac, macs[i * 2 + 1], 6);
		memcpy(mak[i].smac, macs[i * 2], 6);
		//thrd_create(&threads[i], (thrd_start_t)server, &ctx[i]);
		 pthread_create(&threads[i], NULL,(void *)server, &mak[i]);
	}

	for (i = 0; i < N_DEVICES; i++) {
		 pthread_join(threads[i], 0);
		//thrd_join(threads[i], 0);
	}
	printf("Receiving finished\n");
	pcap_close(dev[0]);
	pcap_close(dev[1]);
	fclose(file);
}
