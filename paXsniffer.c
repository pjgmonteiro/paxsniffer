/*
*	PaXSniffer - Revision32
*	DNS Sniffer - Capture and analize the captured packets
*	INSTITUTO POLITECNICO DE BEJA
*	MESTRADO EM ENGENHARIA DE SEGURANÃ‡A INFORMATICA
*	For academic purposes - Para fins acadÃ©micos
* 	Discentes: P. Monteiro | A. Mendes | M. Candeias 
*	
*/

//INCLUDES
#include <pcap.h> //Provides declarations for capture (handle the device, pcap_open_live, struct pcap_pkthdr, pcap_loop)
#include <stdio.h> 
#include <stdlib.h> // for exit()
#include <string.h> //for memset
#include <arpa/inet.h> // for inet_ntoa()
#include <net/ethernet.h> //Provides declaration for eth and some ip hdr
#include <netinet/udp.h>	//Provides declarations for udp header
#include <netinet/ip.h>	//Provides declarations for ip header
#include <signal.h> //Provides declarations for signal - break capture

//Types of DNS resource records :)
#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 // start of authority zone
#define T_PTR 12 // domain name pointer
#define T_MX 15 //Mail server
//Defines
#define MAXFLDS 600  /* maximum possible number of fields */
#define MAXFLDSIZE 32  /* longest possible field + 1 = 31 byte field */
#define MAX_STRING 256 /* for size of string and multidimensional string strs*/
//Globals
struct sockaddr_in source, dest;
int number=0,dns=0,udp=0,others=0,count=0,stopApp=0,i,j;
char optionSave='m';
char optionSaveStats='3';
long elapsed_utime;    /* elapsed time in microseconds */
long elapsed_seconds;  /* diff between seconds counter */
long elapsed_useconds; /* diff between microseconds counter */
long temp; /* diff between first packet */

//definition of type string
typedef char string[MAX_STRING];
string strs[MAXFLDS][MAXFLDSIZE];
string filename;

//List of DNS Servers registered on the system
char dns_servers[10][100];
int dns_server_count = 0;

//Files
FILE *logfile;
FILE *logfilecsv;
FILE *in;

//Function Prototypes
char mainMenu(void);
char statsMenu();
void startCapture(char optionSave);
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void print_ethernet_header(const u_char *Buffer, int Size);
void print_ethernet_header_csv(const u_char *Buffer, int Size);
void print_ip_header(const u_char * Buffer, int Size);
void print_ip_header_csv(const u_char * Buffer, int Size);
void print_udp_packet(const u_char * , int);
void print_udp_packet_csv(const u_char *Buffer , int Size);
void PrintData (const u_char * , int);
u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count);
char *time_stamp(void);
void print_all(int records, int pos, string name);
void print_all_macip(int records, int pos, string name);
void rep_count(int records, int pos, string verify, string name);
void check_times(int records, int posid);
void print_all_stats(int records, int pos, string name);
void count_occurrences(int records, int pos, string name, string keyword);
void check_blacklisted(int records, int pos, string name);
void statistics(char stat);
void ngethostbyname(unsigned char *host , int query_type);
void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host);
void get_dns_servers();
void parse(char *record, char *delim, char arr[][MAXFLDSIZE],int *fldcnt);
void PressEnterToReturn(void);
int checkFileIn(void);
void catFile();
void ex_program(int sig);

//timeval structure
struct timeval tempo1, tempo2;
   
/*DNS header structure*/
struct DNS_HEADER
{
	unsigned short id; // identification number

	unsigned char rd :1; // recursion desired
	unsigned char tc :1; // truncated message 
	unsigned char aa :1; // authoritive answer
	unsigned char opcode :4; // purpose of message
	unsigned char qr :1; // query/response flag

	unsigned char rcode :4; // response code
	unsigned char cd :1; // checking disabled
	unsigned char ad :1; // authenticated data
	unsigned char z :1; // its z! reserved
	unsigned char ra :1; // recursion available

	unsigned short q_count; // number of question entries
	unsigned short ans_count; // number of answer entries
	unsigned short auth_count; // number of authority entries
	unsigned short add_count; // number of resource entries

};

//Constant sized fields of query structure
struct QUESTION
{
	unsigned short qtype;
	unsigned short qclass;
};

//Structure Query
typedef struct 
{
	unsigned char qname;
	struct QUESTION *ques;
}QUERY;

//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
	unsigned short type;
	unsigned short _class;
	unsigned int ttl;
	unsigned short data_len;
};
#pragma pack(pop)

/*Pointers to resource record contents*/
struct RES_RECORD
{
	unsigned char *name;
	struct R_DATA *resource;
	unsigned char *rdata;
};

	
pcap_t *handle; //Handle of the device that shall be sniffed - global to break loop

//Main program
int main()
{
	stopApp = 0;
    (void) signal(SIGINT, ex_program);

	
	//Options for menus
	system("clear");
	optionSave='m';
	mainMenu();
	return 0;
}

//Print Main Menu
char mainMenu()
{
    char selectmenu;
	printf("\n");       
    printf("%60s","################## M E N U ####################\n");
    printf("%60s","# ########################################### #\n");
    printf("%60s","# #                                         # #\n");
    printf("%60s","# #  1 -> Capture to TXT                    # #\n");
    printf("%60s","# #  2 -> Capture to CSV - Excel            # #\n");
    printf("%60s","# #  3 -> Visualize TXT file                # #\n");
    printf("%60s","# #  4 -> Statistics (CSV files)            # #\n");
    printf("%60s","# #  5 -> Exit                              # #\n");
    printf("%60s","# #                                         # #\n");
    printf("%60s","# ########################################### #\n");
    printf("%60s","###############################################\n");
    printf("\nOption: ");
        
    if(optionSave=='m'){
		scanf("%c", &selectmenu);
    }
                
    switch (selectmenu)
    {        
		case '1': optionSave = selectmenu; system("clear");startCapture(selectmenu);fclose(logfile); break;
		case '2': optionSave = selectmenu; system("clear"); startCapture(selectmenu);fclose(logfilecsv); break;
		case '3': optionSave = selectmenu; system("clear"); catFile(); break;
		case '4': optionSave = selectmenu; system("clear"); statsMenu(); break;
		case '5': printf("Thanks for using this amazing sniffer, bye!!!!\n"); optionSave = selectmenu; exit(0); break; 
		default: system("clear"); printf(" Invalid option - please select options 1-4!!! \n "); main(); break;
	}
        
}

//Print Stats Menu
char statsMenu()
{
		system("clear");
		char select;
		printf("\n");
        printf("%60s","######## S T A T I S T I C S  M E N U #########\n");
        printf("%60s","# ################## D N S ################## #\n");
        printf("%60s","# #                                         # #\n");
        printf("%60s","# #  a -> Load file [csv]                   # #\n");
        printf("%60s","# #  b -> Source devices                    # #\n");    
        printf("%60s","# #  c -> Source ports                      # #\n");
        printf("%60s","# #  d -> Destination devices               # #\n");
        printf("%60s","# #  e -> Destination ports                 # #\n");
        printf("%60s","# #  f -> Number of queries                 # #\n");
        printf("%60s","# #  g -> Number of responses               # #\n");
        printf("%60s","# #  h -> Number of Rcodes                  # #\n");
        printf("%60s","# #  i -> Delay between questions/answers   # #\n");
        printf("%60s","# #  j -> Frequencies for MAC source        # #\n");
        printf("%60s","# #  k -> Frequencies for MAC destination   # #\n");
        printf("%60s","# #  l -> Frequencies for Names             # #\n");
        printf("%60s","# #  m -> Search keywords occurencies       # #\n");
        printf("%60s","# #  n -> Check answers in blacklist        # #\n");
        printf("%60s","# #                                         # #\n");
        printf("%60s","# #  q -> RETURN TO MAIN MENU               # #\n");
        printf("%60s","# #                                         # #\n");
        printf("%60s","# ########################################### #\n");
        printf("%60s","###############################################\n");
        printf("Option: ");
        
                scanf("%1s", &select);
        
        switch (select)
        {        
                case 'a': system("clear"); statistics(select); optionSaveStats=='3'; statsMenu(); break;
				case 'b': system("clear"); statistics(select); optionSaveStats=='3'; statsMenu(); break;
				case 'c': system("clear"); statistics(select); optionSaveStats=='3'; statsMenu(); break;
				case 'd': system("clear"); statistics(select); optionSaveStats=='3'; statsMenu(); break;
				case 'e': system("clear"); statistics(select); optionSaveStats=='3'; statsMenu(); break;
				case 'f': system("clear"); statistics(select); optionSaveStats=='3'; statsMenu(); break;
				case 'g': system("clear"); statistics(select); optionSaveStats=='3'; statsMenu(); break;
				case 'h': system("clear"); statistics(select); optionSaveStats=='3'; statsMenu(); break;
				case 'i': system("clear"); statistics(select); optionSaveStats=='3'; statsMenu(); break;
				case 'j': system("clear"); statistics(select); optionSaveStats=='3'; statsMenu(); break;
				case 'k': system("clear"); statistics(select); optionSaveStats=='3'; statsMenu(); break;
				case 'l': system("clear"); statistics(select); optionSaveStats=='3'; statsMenu(); break;
				case 'm': system("clear"); statistics(select); optionSaveStats=='3'; statsMenu(); break;
				case 'n': system("clear"); statistics(select); optionSaveStats=='3'; statsMenu(); break;
				case 'q': optionSave = 'm'; optionSaveStats='3'; system("clear"); mainMenu(); break; 
				default: 
				system("clear"); 
				printf(" Invalid option - please select options [a-n] or [q] to return!!! \n ");
                sleep(1);
                optionSaveStats='3';
                statsMenu();
                break;
			}
}

//search for capture devices and begin capture
void startCapture(char optionSave)
{
	if(optionSave=='1'){
		
		printf("##Capture to TXT file selected!\n\n");
		strcpy(filename,"");
		if (!strcmp(filename,""))
		{
			printf("Enter key [d] to assume defaults [log.txt],\n"); 
			printf("or insert the name of the file (without .txt): ");
			scanf("%s", filename);
		}
		if (!strcmp(filename,"d"))
			strcpy(filename,"log.txt");
		else
			strcat(filename,".txt");
		
		//create file txt to save capture
		if(optionSave=='1'){
		logfile=fopen(filename,"wr");
			if(logfile==NULL) 
			{
				printf("Unable to create file.");
				PressEnterToReturn();
			}
		}
	}
	
	if(optionSave=='2'){
		printf("##Capture to CSV file selected!\n\n");
		
		strcpy(filename,"");
		if (!strcmp(filename,""))
		{
			printf("Enter key [d] to assume defaults [logcsv.csv],\n"); 
			printf("or insert the name of the file (without .csv): ");
			scanf("%s", filename);
		}
		if (!strcmp(filename,"d"))
			strcpy(filename,"logcsv.csv");
		else
			strcat(filename,".csv");
		
		//create file csv to save capture
		if(optionSave=='2'){
			logfilecsv=fopen(filename,"wr");
			if(logfilecsv==NULL) 
			{
				printf("Unable to create file.");
				PressEnterToReturn();
			}
		}
			
	}

	//search for capture devices	
	pcap_if_t *alldevsp , *device;
	char errbuf[100] , *devname , devs[100][100];
	int count = 1 , n;
	
	//Find the all devices
	printf("\nFinding available devices ... ");
	if( pcap_findalldevs( &alldevsp , errbuf) )
	{	//if not available devices or errbuf
		printf("Error finding devices : %s" , errbuf);
		exit(1);
	}
	printf("Done");
	
	//Print the list of available devices
	printf("\nAvailable Devices are :\n");
	for(device = alldevsp ; device != NULL ; device = device->next)
	{
		printf("%d. %s - %s\n" , count , device->name , device->description);
		if(device->name != NULL)
		{
			strcpy(devs[count] , device->name);
		}
		count++;
	}
	
	//Ask user which device to sniff
	printf("\nEnter the number of the device you want to sniff : ");
	scanf("%d" , &n);
	devname = devs[n];
	printf("\nEnter the number of dns queries to capture : ");
	scanf("%d" , &number);
		
	//Open the device for sniffing
	printf("\nOpening device %s for sniffing (or [CTRL]+[C] to stop)... " , devname);
	handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);		
	//checking if handle equal to null - no devices found 
	if (handle == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
		exit(1);
	}
	else
	printf("Capturing...\n");
	
    //Put the device in sniff loop
    pcap_loop(handle , -1 , process_packet , NULL);
    printf("\n\n\nDone!!!");
    PressEnterToReturn();
    main();
}

//Process and check the Protocol and do accordingly...
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	int size = header->len;
	
	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
        
	switch (iph->protocol) //Check the Protocol and do accordingly...
	{
		
		case 17: //UDP Protocol
			++udp;
			if(optionSave == '1') print_udp_packet(buffer, size);
			if(optionSave == '2') print_udp_packet_csv(buffer, size);
			break;
		default: //Some Other Protocol like ARP, HTTP, ICMP, etc.
			++others;
			break;
	}
	
	printf("DNS : %d  ||  Others : %d \r", dns, others+udp-dns);
	
	if(dns==number*2){
		//break loop
		pcap_breakloop(handle);
		if(optionSave == '1'){
			fprintf(logfile,"\n##########Captured %d DNS packets | Others packets: %d in network!\n", dns, others+udp-dns);
			fclose(logfile); 
		}
		if(optionSave == '2'){
			fclose(logfilecsv);
		}
		elapsed_utime=0; elapsed_seconds=0; elapsed_useconds=0; temp=0; dns=0; others=0,number=0; //initialization for start another capture
	}

}

//Print ETHERNET Header - only for txt file
void print_ethernet_header(const u_char *Buffer, int Size)
{
	struct ethhdr *eth = (struct ethhdr *)Buffer;
	
	fprintf(logfile , "\n");
	fprintf(logfile , "Ethernet Header\n");
	fprintf(logfile , "   |-Source Address------: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	fprintf(logfile , "   |-Destination Address-: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	fprintf(logfile , "   |-Protocol------------: %u \n",(unsigned short)eth->h_proto);
}

//Print ETHERNET Header - only for csv file
void print_ethernet_header_csv(const u_char *Buffer, int Size)
{
	struct ethhdr *eth = (struct ethhdr *)Buffer;
	fprintf(logfilecsv , "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X,", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	fprintf(logfilecsv , "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X,", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	
}

//Print IP Header - only for txt file
void print_ip_header(const u_char * Buffer, int Size)
{
	print_ethernet_header(Buffer , Size);
  
	unsigned short iphdrlen;
		
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	
	fprintf(logfile , "\n");
	fprintf(logfile , "IP Header\n");
	fprintf(logfile , "   |-IP Version----------: %d\n",(unsigned int)iph->version);
	fprintf(logfile , "   |-IP Header Length----: %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	fprintf(logfile , "   |-Type Of Service-----: %d\n",(unsigned int)iph->tos);
	fprintf(logfile , "   |-IP Total Length-----: %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	fprintf(logfile , "   |-Identification------: %d\n",ntohs(iph->id));
	fprintf(logfile , "   |-TTL-----------------: %d\n",(unsigned int)iph->ttl);
	fprintf(logfile , "   |-Protocol------------: %d\n",(unsigned int)iph->protocol);
	fprintf(logfile , "   |-Checksum : %d\n",ntohs(iph->check));
	fprintf(logfile , "   |-Source IP-----------: %s\n" , inet_ntoa(source.sin_addr) );
	fprintf(logfile , "   |-Destination IP------: %s\n" , inet_ntoa(dest.sin_addr) );
}

//Print IP Header - only for csv file
void print_ip_header_csv(const u_char * Buffer, int Size)
{
	print_ethernet_header_csv(Buffer , Size);
  	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	fprintf(logfilecsv , "%d,%d,%s,",(unsigned int)iph->version, (unsigned int)iph->ttl, inet_ntoa(source.sin_addr));
	fprintf(logfilecsv , "%s,", inet_ntoa(dest.sin_addr));
}

//Print UDP and DNS PACKET - only for txt file
void print_udp_packet(const u_char *Buffer , int Size)
{
	
	unsigned short iphdrlen;
	unsigned short udprlen;	
	unsigned char buf[65536],*qname,*reader;		
	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
    	
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	udprlen = ntohs(udph->len);
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	
	if(ntohs(udph->source)==53 || ntohs(udph->dest)==53){
	dns++;
	fprintf(logfile , "###|-DNS Packet Number %3d #################################################\n", dns);
	
	fprintf(logfile , "   |-Timestamp-----------: %s seconds\n", time_stamp());
	
	print_ip_header(Buffer,Size);			 
	fprintf(logfile , "\nUDP Header\n");
	fprintf(logfile , "   |-Source Port---------: %d\n" , ntohs(udph->source));
	fprintf(logfile , "   |-Destination Port----: %d\n" , ntohs(udph->dest));
	fprintf(logfile , "   |-UDP Length----------: %d\n" , ntohs(udph->len));
	fprintf(logfile , "   |-UDP Checksum--------: %d\n" , ntohs(udph->check));
	fprintf(logfile , "\n");
	fprintf(logfile , "IP Header\n");
	PrintData(Buffer , iphdrlen);
		
	fprintf(logfile , "UDP Header\n");
	PrintData(Buffer+iphdrlen , sizeof udph);
		
	fprintf(logfile , "Data Payload\n");	
	//Move the pointer ahead and reduce the size of string
	PrintData(Buffer + header_size , Size - header_size);
	struct DNS_HEADER *dnsh = (struct DNS_HEADER*)(Buffer + header_size);
	fprintf(logfile , "\nDNS Header\n");
	fprintf(logfile , "   |-ID------------------: %d\n" , ntohs(dnsh->id));
	fprintf(logfile , "   |-OPCode--------------: %d\n" , (unsigned int)dnsh->opcode);
	fprintf(logfile , "   |-FlagResp------------: %d\n" , (unsigned int)dnsh->qr);
	fprintf(logfile , "   |-RCode---------------: %d\n" , (unsigned int)dnsh->rcode);
	fprintf(logfile , "   |-QCount--------------: %d\n" , ntohs(dnsh->q_count));
	fprintf(logfile , "   |-ACount--------------: %d\n" , ntohs(dnsh->ans_count));	
	fprintf(logfile , "   |-RecDes--------------: %d\n" , (unsigned int)dnsh->rd);
	fprintf(logfile , "   |-RecAva--------------: %d\n" , (unsigned int)dnsh->ra);
	
	struct DNS_HEADER *dns = NULL;	
	struct QUESTION *qinfo = NULL;	
	struct sockaddr_in a;	
	
	//move ahead of the dns header and the query field	
	strcpy(buf, Buffer);	
	dns = (struct DNS_HEADER*)(Buffer + header_size);	
	
	//point to the query portion
	qname =(unsigned char*)(Buffer + header_size + sizeof(struct DNS_HEADER));
	
	//print the query name
	int stop=0;
	char *s = ReadName(qname, buf, &stop);
	fprintf(logfile , "   |-Name----------------: %s\n" , s);
	//point to the question portion - type and class
	qinfo =(struct QUESTION*)(Buffer + header_size + sizeof(struct DNS_HEADER)+(strlen((const char*)qname))+2);
	fprintf(logfile , "   |-Type----------------: %d\n" , (unsigned char)qinfo->qtype);	
	fprintf(logfile , "   |-Class---------------: %d\n" , (unsigned char)qinfo->qclass);	
		
	//print answers
	if((unsigned int)dnsh->qr == 1){
		
		struct RES_RECORD answers[20];
		if((unsigned char)qinfo->qtype==1)
		reader = (unsigned char*)(Buffer + header_size + sizeof(struct DNS_HEADER) + sizeof(struct QUESTION) + (strlen((const char*)qname))+1);
		if((unsigned char)qinfo->qtype==12)
		reader = (unsigned char*)(Buffer + header_size + sizeof(struct DNS_HEADER) + sizeof(struct QUESTION) + (strlen((const char*)qname))+1);
		
		//Start reading answers
		int stop1=0;
		for(i=0;i<ntohs(dns->ans_count);i++)
		{
			answers[i].name=ReadName(reader,buf,&stop1);
			reader = reader + stop1;
			answers[i].resource = (struct R_DATA*)(reader);
			reader = reader + sizeof(struct R_DATA);

			if(ntohs(answers[i].resource->type) == 1) //if its an ipv4 address
			{
				answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));

				for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
				{
					answers[i].rdata[j]=reader[j];
				}

				answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

				reader = reader + ntohs(answers[i].resource->data_len);
			}
			else
			{
				answers[i].rdata = ReadName(reader,buf,&stop1);
				reader = reader + stop1;
			}
		}
		
		if(ntohs(dns->ans_count)>0){ 	
			fprintf(logfile, "   |-Answer Records------: %d \n" , ntohs(dns->ans_count) );	
			for(i=0 ; i < ntohs(dns->ans_count) ; i++)
			{
			

			if( ntohs(answers[i].resource->type) == T_A) //IPv4 address
			{
				long *p;
				p=(long*)answers[i].rdata;
				a.sin_addr.s_addr=(*p); //working without ntohl
				fprintf(logfile, "   |-Answer Record %2d----: %s has ipv4 address-: %s", i+1, s, inet_ntoa(a.sin_addr));
			}
			
			if(ntohs(answers[i].resource->type)==12) {
				//Canonical name for an alias
				fprintf(logfile, "   |-Answer Record %2d----: %s has alias name---: %s", i+1, s, answers[i].rdata);
			}
	
			fprintf(logfile,"\n");
			}
		}
	}
	fprintf(logfile , "\n############################################################################\n");
}
if(stopApp==1){
	fprintf(logfile,"\n##########Captured %d DNS packets | Others packets: %d in network!\n", dns, others+udp-dns);
	fclose(logfile);
	main();
	}
}

//Print UDP and DNS PACKET - only for csv file
void print_udp_packet_csv(const u_char *Buffer , int Size)
{
	
	unsigned short iphdrlen;
	unsigned short udprlen;	
	unsigned char buf[65536],*qname,*reader;		
	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
    	
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	udprlen = ntohs(udph->len);
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	
	if(ntohs(udph->source)==53 || ntohs(udph->dest)==53){
	dns++;
	if(dns==1)
	fprintf(logfilecsv ,"NUMBER,TIME,MAC_SOURCE,MAC_DEST,IP_V,TTL,IP_SOURCE,IP_DEST,PORT_SOURCE,PORT_DEST,DNS_ID,OPCODE,RESPONSE,RCODE,QUERY,ANSWERS,REC_DESIRED,REC_AVAI,QUERY NAME,TYPE,CLASS,ANSWERS\n");
	
	fprintf(logfilecsv , "%d,%s,", dns, time_stamp());
	print_ip_header_csv(Buffer,Size);			 
	fprintf(logfilecsv , "%d,%d," , ntohs(udph->source), ntohs(udph->dest));
	
	struct DNS_HEADER *dnsh = (struct DNS_HEADER*)(Buffer + header_size);
	
	fprintf(logfilecsv , "%d,%d,%d,%d,%d,%d,%d,%d," , ntohs(dnsh->id), (unsigned int)dnsh->opcode, (unsigned int)dnsh->qr, (unsigned int)dnsh->rcode, ntohs(dnsh->q_count),ntohs(dnsh->ans_count),(unsigned int)dnsh->rd,(unsigned int)dnsh->ra);
	
	int header_size1 =  sizeof(struct ethhdr) + iphdrlen + udprlen;
	
	struct DNS_HEADER *dns = NULL;	
	struct QUESTION *qinfo = NULL;	
	
	struct sockaddr_in a;	
	
	//move ahead of the dns header and the query field	
	strcpy(buf, Buffer);
	
	dns = (struct DNS_HEADER*)(Buffer + header_size);	
	
	//point to the query portion
	qname =(unsigned char*)(Buffer + header_size + sizeof(struct DNS_HEADER));
	
	//get the query name
	int stop=0;
	char *s = ReadName(qname, buf, &stop);
	
	//point to the question portion - type and class
	qinfo =(struct QUESTION*)(Buffer + header_size + sizeof(struct DNS_HEADER)+(strlen((const char*)qname))+2);
	
	//Print name, type, class
	fprintf(logfilecsv , "%s,%d,%d," , s, (unsigned char)qinfo->qtype,(unsigned char)qinfo->qclass );

	//print answers
	if((unsigned int)dnsh->qr == 1){
		
		struct RES_RECORD answers[20];
		if((unsigned char)qinfo->qtype==1)
		reader = (unsigned char*)(Buffer + header_size + sizeof(struct DNS_HEADER) + sizeof(struct QUESTION) + (strlen((const char*)qname))+1);
		if((unsigned char)qinfo->qtype==12)
		reader = (unsigned char*)(Buffer + header_size + sizeof(struct DNS_HEADER) + sizeof(struct QUESTION) + (strlen((const char*)qname))+1);
		//Start reading answers
		int stop1=0;
		for(i=0;i<ntohs(dns->ans_count);i++)
		{
			answers[i].name=ReadName(reader,buf,&stop1);
			reader = reader + stop1;
			answers[i].resource = (struct R_DATA*)(reader);
			reader = reader + sizeof(struct R_DATA);

			if(ntohs(answers[i].resource->type) == 1) //if its an ipv4 address
			{
				answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));

				for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
				{
					answers[i].rdata[j]=reader[j];
				}

				answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

				reader = reader + ntohs(answers[i].resource->data_len);
			}
			else
			{
				answers[i].rdata = ReadName(reader,buf,&stop1);
				reader = reader + stop1;
			}
		}
		/////////////////////////////////////////////////////////////////////////////
		if(ntohs(dns->ans_count)>0){ 	
			for(i=0 ; i < ntohs(dns->ans_count) ; i++)
			{
			if( ntohs(answers[i].resource->type) == T_A) //IPv4 address
			{
				long *p;
				p=(long*)answers[i].rdata;
				a.sin_addr.s_addr=(*p); //working without ntohl
				fprintf(logfilecsv, "%s,", inet_ntoa(a.sin_addr));
			}
			
			if(ntohs(answers[i].resource->type)==12) {
				//Canonical name for an alias
				fprintf(logfilecsv, "%s,", answers[i].rdata);
			}
			}
		}
		
    }
				fprintf(logfilecsv,"\n");
	}//enf if dns port == 53
if(stopApp==1){
	fclose(logfilecsv);
	main();
	}
}

//Print hex and alphabet data - only for txt file
void PrintData(const u_char * data , int Size)
{ 

	int i , j;
	for(i=0 ; i < Size ; i++)
	{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			fprintf(logfile , "         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
					fprintf(logfile , "%c",(unsigned char)data[j]); //if its a number or alphabet
				
				else fprintf(logfile , "."); //otherwise print a dot
			}
			fprintf(logfile , "\n");

		} 
		
		if(i%16==0) fprintf(logfile , "   ");
			fprintf(logfile , " %02X",(unsigned int)data[i]);
				
		if( i==Size-1)  //print the last spaces
		{
			for(j=0;j<15-i%16;j++) 
			{
			  fprintf(logfile , "   "); //extra spaces
			}
			
			fprintf(logfile , "         ");
			
			for(j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) 
				{
				  fprintf(logfile , "%c",(unsigned char)data[j]);
				}
				else 
				{
				  fprintf(logfile , ".");
				}
			}
			
			fprintf(logfile ,  "\n" );
		}
	}
	
   
}

//read the names in 3www6google3com format
u_char* ReadName(unsigned char* reader, unsigned char* buffer, int* count)
{
	unsigned char *name;
	unsigned int p=0,jumped=0,offset;
	int i , j;

	*count = 1;
	name = (unsigned char*)malloc(256);

	name[0]='\0';

	//read the names in 3www6google3com format
	while(*reader!=0)
	{
		if(*reader>=192)
		{
			offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
			reader = buffer + offset - 1;
			jumped = 1; //we have jumped to another location so counting wont go up!
		}
		else
		{
			name[p++]=*reader;
		}

		reader = reader+1;

		if(jumped==0)
		{
			*count = *count + 1; //if we havent jumped to another location then we can count up
		}
	}

	name[p]='\0'; //string complete
	if(jumped==1)
	{
		*count = *count + 1; //number of steps we actually moved forward in the packet
	}

	//now convert 3www6google3com0 to www.google.com
	for(i=0;i<(int)strlen((const char*)name);i++) 
	{
		p=name[i];
		for(j=0;j<(int)p;j++) 
		{
			name[i]=name[i+1];
			i=i+1;
		}
		name[i]='.';
	}
	name[i-1]='\0'; //remove the last dot
	return name;
}

//get the timestamp
char *time_stamp()
{
	if(dns==1)
	{
		gettimeofday(&tempo1, NULL);	//Get the time of the day
	}
	char *timestamp = (char *)malloc(sizeof(char) * 16);
	gettimeofday(&tempo2, NULL);
	elapsed_seconds  = tempo2.tv_sec  - tempo1.tv_sec;
    elapsed_useconds = tempo2.tv_usec - tempo1.tv_usec;
    if(dns==1)
	{
		temp = elapsed_useconds;
		elapsed_useconds = tempo2.tv_usec - tempo1.tv_usec - temp;
		sprintf(timestamp,"%ld.%.8ld", elapsed_seconds, elapsed_utime);
		return timestamp;
		
	}
	
		elapsed_utime = (elapsed_seconds) * 1000000 + elapsed_useconds - temp;
		sprintf(timestamp,"%ld.%.8ld", elapsed_seconds, elapsed_utime);
		return timestamp;
	
}

//aux to call stats functions
void statistics(char stat)
{
	if(stopApp==1)main();
	char tmp[1024]={0x0};
	int fldcnt=0;
	char arr[MAXFLDS][MAXFLDSIZE]={0x0};
	int recordcnt=0;
		
		if(stat=='a') strcpy(filename,"");
		
		if (!strcmp(filename,""))
		{
			printf("Enter key [d] to assume defaults [logcsv.csv],\n"); 
			printf("or insert the name of the CSV file [file.csv]: ");
			scanf("%s", filename);
		}
		if (!strcmp(filename,"d"))
			strcpy(filename,"logcsv.csv");
			
		in = fopen(filename,"r");/* open file on command line */
		
		if(checkFileIn()==-1)
		{
			optionSaveStats='3';
			printf("Error loading file...[%s]\n\n", filename);
			statistics('a');
		}
		if(checkFileIn()==0)
		{
			if(stat=='a')printf("Loading file...[%s]\n\n", filename);
			fgets(tmp,sizeof(tmp),in); /*jump over header*/
			while(fgets(tmp,sizeof(tmp),in)!=0) /* read a record */
			{
					i=0;
					j=0;
					recordcnt++;
					parse(tmp,",",arr,&fldcnt);    /* whack record into fields */
					for(i;i<fldcnt;i++)
					{   
						//copy all records to strs
						strcpy(strs[recordcnt-1][i],arr[i]);
					}
		
			}
			if(stat=='a')printf("Done!!!\n", filename);
			if(stat=='a')PressEnterToReturn();
		}

	if (stat=='b'){
		system("clear");
		print_all_macip(recordcnt, 2,"Source devices:\n"); //list of all source devices - print mac and ip
		PressEnterToReturn();
		fclose(in);
		optionSaveStats='3';
		system("clear");
		statsMenu();
	}
	if (stat=='c'){
		system("clear");
		print_all(recordcnt, 8, "Source ports:\n"); //list of all source ports
		PressEnterToReturn();
		fclose(in);
		optionSaveStats='3';
		system("clear");
		statsMenu();
	}
	if (stat=='d'){
		system("clear");
		print_all_macip(recordcnt, 3,"\nDestination devices:\n"); //list of all destination devices - print mac and ip
		PressEnterToReturn();
		fclose(in);
		optionSaveStats='3';
		system("clear");
		statsMenu();
	}
	if (stat=='e'){
		system("clear");
		print_all(recordcnt, 9, "Destination ports:\n"); //list of all destination ports
		PressEnterToReturn();
		fclose(in);
		optionSaveStats='3';
		system("clear");
		statsMenu();
	}
	if (stat=='f'){
		system("clear");
		rep_count(recordcnt, 12, "0", "\nNÂº of Queries: "); //count number of queries, verifying the flag response=o
		PressEnterToReturn();
		fclose(in);
		optionSaveStats='3';
		system("clear");
		statsMenu();
	}
	if (stat=='g'){
		system("clear");
		rep_count(recordcnt, 12, "1", "\nNÂº of Responses: "); //count number of responses, verifying the flag response=1
		PressEnterToReturn();
		fclose(in);
		optionSaveStats='3';
		system("clear");
		statsMenu();
	}
	if (stat=='h'){
		system("clear");
		rep_count(recordcnt, 13, "3", "\nNÂº of Rcodes: "); //count number of Rcodes errors
		PressEnterToReturn();
		fclose(in);
		optionSaveStats='3';
		system("clear");
		statsMenu();
	}
	if (stat=='i'){
		system("clear");
		check_times(recordcnt, 10); //verify delay between question and answer
		PressEnterToReturn();
		fclose(in);
		optionSaveStats='3';
		system("clear");
		statsMenu();
	}
	if (stat=='j'){
		system("clear");
		print_all_stats(recordcnt, 2, "\nMAC source:"); //stats MAC Source
		PressEnterToReturn();
		fclose(in);
		optionSaveStats='3';
		system("clear");
		statsMenu();
	}
	if (stat=='k'){
		system("clear");
		print_all_stats(recordcnt, 3, "\nMAC destination:");//stats MAC destination
		PressEnterToReturn();
		fclose(in);
		optionSaveStats='3';
		system("clear");
		statsMenu();
	}
	if (stat=='l'){
		system("clear");
		print_all_stats(recordcnt, 18, "\nNames:");//stats Name
		PressEnterToReturn();
		fclose(in);
		optionSaveStats='3';
		system("clear");
		statsMenu();
	}
	if (stat=='m'){
		system("clear");
		string keyword;
		printf("Insert the keyword to search in all queries: ");
		scanf("%s", keyword);
		count_occurrences(recordcnt, 18, "\nThe selected keyword:", keyword);
		PressEnterToReturn();
		fclose(in);
		optionSaveStats='3';
		system("clear");
		statsMenu();
	}
	if (stat=='n'){
		system("clear");
		check_blacklisted(recordcnt, 21, "\nCheck queries responses:\n");//Check queries responses
		PressEnterToReturn();
		fclose(in);
		optionSaveStats='3';
		system("clear");
		statsMenu();
	}
	
	statsMenu();
}

//Print the MAC SRC DST and IP SRC DST
void print_all_macip(int records, int pos, string name)
{
			string strmac[records];
			string strip[records];
			string strttl[records];
			count=0;
			printf("%s", name);
			for(i=0;i<records;i++)
			{
				for(j=0;j<count;j++)
				{
					if(!strcmp(strs[i][pos],strmac[j]))
					break;
				}
				if(j==count)
				{
					strcpy(strmac[count],strs[i][pos]);
					strcpy(strip[count],strs[i][pos+4]); //More 4 to position of column IP
			        if(pos==2)
					strcpy(strttl[count],strs[i][5]); //5 is the position of column TTL			
					count++;
				}
			}
			
			for(i=0;i<count; i++)
			{
				printf("MAC:%s  - IP:%s ", strmac[i], strip[i]);
				if(pos==2)
				printf("- TTL:%s\n", strttl[i]);
				else
				printf("\n");
								
			}
			printf("");
}

//print all record of certain position - deleted the repeated records
void print_all(int records, int pos, string name)
{
			string str[records];
			count=0;
			printf("%s", name);
			for(i=0;i<records;i++)
			{
				for(j=0;j<count;j++)
				{
					if(!strcmp(strs[i][pos],str[j]))
					break;
				}
				if(j==count)
				{
					strcpy(str[count],strs[i][pos]);
					count++;
				}
			}
			
			for(i=0;i<count; i++)
			{
				printf("[%s]", str[i]);					
			}
			printf("\n");
}

//Count the occurrences of certain position
void rep_count(int records, int pos, string verify, string name)
{
	count=0;
	for(i=0; i<records; i++){ 
		if(!strcmp(strs[i][pos],verify)){
			count++;	
		}
	}
		
		printf("%s %d of %d packets captured!\n\n", name, count, records);
}

//check times between queries and answers
void check_times(int records, int posid)
{
	string dnsid[records];
	double time1, time2;
	for(i=0;i<records;i++)
	{
		for(j=0;j<count;j++)
		{
			if(!strcmp(strs[i][posid],dnsid[j]))
			break;
		}
		if(j==count)
		{
			strcpy(dnsid[count],strs[i][posid]);
			count++;
		}
	}
	printf("\n\n");
	int n;
	for(i=0;i<records;i++)
	{
		n=0;
		for(j=0;j<records;j++)
		{
			if (n==0){
				if(!strcmp(strs[j][posid], dnsid[i])){
					time1=strtod(strs[j][1], (char **) NULL);
					n=1;
				}	
			}
			if (n==1){
				if(!strcmp(strs[j][posid],dnsid[i])){
					time2=strtod(strs[j][1], (char **) NULL);
					if(time2!=time1){
					time2=strtod(strs[j][1], (char **) NULL);
					printf("DNS id: %8s - delay: %.8f\n", strs[j][posid],time2-time1);	
					}
				}
			}
			
		}
	}
}

//print all stats for certain column position
void print_all_stats(int records, int pos, string name)
{
			string names[records];
			count=0;
			float rf;
			printf("%s", name);
			for(i=0;i<records;i++)
			{
				for(j=0;j<count;j++)
				{
					if(!strcmp(strs[i][pos],names[j]))
					
					break;
				}
				if(j==count)
				{
					strcpy(names[count],strs[i][pos]);
					count++;
				}
			}
			
			float count1;
			for(i=0;i<count;i++)
			{
				for(j=0;j<records;j++)
				{
					if(!strcmp(strs[j][pos],names[i])){
					count1++;
					}
					if(j==records){
						count1=0;
						}
				}
				rf=(count1/records)*100;
				printf("\n%30s - Absolute Freq.: %2.0f - Relative Freq.: %3.2f%%", names[i], count1, rf);
				count1=0;
		    }
		    printf("\n                                                              Total: 100.00%%\n");
}

//Count occurrences on field query name of some keyword
void count_occurrences(int records, int pos, string name, string keyword)
{
	string dnsid[records];
	string ipsrc[records];
	string ipdst[records];
	string querynames[records];
	string flagresponse[records];
	string response[records];
	string flag="0";
	int ntimes=0;
	for(i=0;i<records;i++)
	{
		
		if(strstr(strs[i][pos],keyword))
		{
			strcpy(dnsid[ntimes],strs[i][10]);//10 column of dns id
			strcpy(ipsrc[ntimes],strs[i][6]);//6 column of ip src
			strcpy(ipdst[ntimes],strs[i][7]);//7 column of ip dst
			strcpy(querynames[ntimes],strs[i][pos]);//18 column of queries names
			strcpy(flagresponse[ntimes],strs[i][12]);//12 column of flag response
			strcpy(response[ntimes],strs[i][21]);//21 column of response
			ntimes++;
		}
	}
		
	printf("%s [%s] ...\n...appears %i time(s) in the field query name (question+response)!!!\n\n", name, keyword, ntimes);
	int x;
	for(x=0; x<ntimes; x++){
		if(!strcmp(flagresponse[x], flag))
			printf("#QUERY----ID=%s##\nIP SRC=%s | IP DST=%s ---> Query name= %s\n",dnsid[x] ,ipsrc[x], ipdst[x], querynames[x]);
		if(strcmp(flagresponse[x], flag))
			printf("#RESPONSE-ID=%s##\nIP SRC=%s | IP DST=%s ---> Query name= %s - Response= %s\n\n",dnsid[x] ,ipsrc[x], ipdst[x], querynames[x], response[x]);
	}
}
 
//check if any record is at blacklist
void check_blacklisted(int records, int pos, string name)
{
	string flag="1";
	string forcheck[records];
	string hostname, reversename;
	int x,k;
	count=0;
	
	for(k=0; k<records; k++){ 
		if(!strcmp(strs[k][12],flag)){
		    for(i=k;i<records;i++)
			{
				for(j=0;j<count;j++)
				{
					if(!strcmp(strs[k][pos],forcheck[j])){
					break;
					}
				}
				if(j==count)
				{
					strcpy(forcheck[count],strs[i][pos]);
					count++;
				}			
			}
		}
			
	}

	
	for(x=0;x<count; x++)
	{
		printf("###################################################");

		strcpy(reversename,"");
		printf("\nChecking... %24s", forcheck[x]);
		get_dns_servers();	//Get the DNS servers from the resolv.conf file
		strcpy(hostname,forcheck[x]);//for check 240.10.160.1.zen.spamhaus.org
		char separator='.';
		char*p=strtok(hostname,".");
		string namehost[100];
		int fld=0;
		while(p)
		{
			strcpy(namehost[fld],p);
			fld++;
			p=strtok('\0',".");
		} 
	
		//int part=fld;
		strcpy(reversename, namehost[fld]);
		for(i=fld; i>0; i--)
		{
			strcat(reversename, namehost[i-1]);
			if(i!=0)
			strcat(reversename, ".");
		}
	    strcat(reversename, "zen.spamhaus.org"); //strcat(reversename, "blacklist.domain.tld");
	        
		printf("\nReversed for check: %s\n", reversename);
		ngethostbyname(reversename, T_A);//Now get the ip of this hostname , A record
	
	}
	
			
}

//Perform a DNS query by sending a packet
void ngethostbyname(unsigned char *host , int query_type)
{
	unsigned char buf[65536],*qname,*reader;
	int i , j , stop , s;

	struct sockaddr_in a;

	struct RES_RECORD answers[20]; //the replies from the DNS server
	struct sockaddr_in dest;

	struct DNS_HEADER *dns = NULL;
	struct QUESTION *qinfo = NULL;

	s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries

	dest.sin_family = AF_INET;
	dest.sin_port = htons(53);
	dest.sin_addr.s_addr = inet_addr(dns_servers[0]); //dns servers

	//Set the DNS structure to standard queries
	dns = (struct DNS_HEADER *)&buf;

	dns->id = (unsigned short) htons(getpid());
	dns->qr = 0; //This is a query
	dns->opcode = 0; //This is a standard query
	dns->aa = 0; //Not Authoritative
	dns->tc = 0; //This message is not truncated
	dns->rd = 1; //Recursion Desired
	dns->ra = 0; //Recursion not available! hey we dont have it (lol)
	dns->z = 0;
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 0;
	dns->q_count = htons(1); //we have only 1 question
	dns->ans_count = 0;
	dns->auth_count = 0;
	dns->add_count = 0;

	//point to the query portion
	qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];

	ChangetoDnsNameFormat(qname , host);
	qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it

	qinfo->qtype = htons( query_type ); //type of the query , A , MX , CNAME , NS etc
	qinfo->qclass = htons(1); //its internet (lol)

	if( sendto(s,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
	{
		perror("Check failed");
	}
	
	//Receive the answer
	i = sizeof dest;
	if(recvfrom (s,(char*)buf , 65536 , 0 , (struct sockaddr*)&dest , (socklen_t*)&i ) < 0)
	{
		perror("Recvfrom failed");
	}

	dns = (struct DNS_HEADER*) buf;

	//move ahead of the dns header and the query field
	reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];

	if(ntohs(dns->ans_count)>=1)
	{
		printf("\x1b[31m####------> ATTENTION this address is BLACKLISTED!\x1b[0m\n");
	}
	else
		printf("\x1b[32m#### OK - This address is not blacklisted!\x1b[0m\n");
}

//Get the DNS servers from /etc/resolv.conf file on Linux
void get_dns_servers()
{
	FILE *fp;
	char line[200] , *p;
	if((fp = fopen("/etc/resolv.conf" , "r")) == NULL)
	{
		printf("Failed opening /etc/resolv.conf file \n");
	}
	
	while(fgets(line , 200 , fp))
	{
		if(line[0] == '#')
		{
			continue;
		}
		if(strncmp(line , "nameserver" , 10) == 0)
		{
			p = strtok(line , " ");
			p = strtok(NULL , " ");
		}
	}
	
	//strcpy(dns_servers[0] , "193.136.192.45"); //resolver ipbeja.pt
	strcpy(dns_servers[0] , "192.168.68.2"); //resolver ipbeja.pt
	//strcpy(dns_servers[0] , "208.67.222.222"); //resolver1.opendns.com
	strcpy(dns_servers[1] , "208.67.220.220"); //resolver1.opendns.com
	//strcpy(dns_servers[1] , "8.8.8.8"); //resolver google.com
}

//This will convert www.google.com to 3www6google3com 
void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host) 
{
	int lock = 0 , i;
	strcat((char*)host,".");
	
	for(i = 0 ; i < strlen((char*)host) ; i++) 
	{
		if(host[i]=='.') 
		{
			*dns++ = i-lock;
			for(;lock<i;lock++) 
			{
				*dns++=host[lock];
			}
			lock++; //or lock=i+1;
		}
	}
	*dns++='\0';
}

//parse the line with certain delim
void parse( char *record, char *delim, char arr[][MAXFLDSIZE],int *fldcnt)
{
	char*p=strtok(record,delim);
	int fld=0;
	while(p)
	{
		strcpy(arr[fld],p);
		fld++;
		p=strtok('\0',delim);
	}   
	*fldcnt=fld;
}

//Press Key enter to return menu
void PressEnterToReturn(void)
{ 
	printf("\nPress ENTER to return...");
	char c=getchar();
	getchar();
    while (c != '\n')
    c=getchar(); 
}

//check file in
int checkFileIn(void)
{
	if(in==NULL) 
	{
		printf("Not selected any avaiable file.\n\n");
		sleep(1);
		return -1;
	}
	return 0;
}

void catFile()
{
	system("clear");
	FILE *cat;
	char ch;
	string file;
	string catfile;
	strcpy(file,"");	
	
	if (!strcmp(file,""))
	{
			printf("Enter key [d] to assume defaults [log.txt],\n"); 
			printf("or insert the name of the txt file [file.txt]: ");
			scanf("%s", file);
	}
	if (!strcmp(file,"d"))
			strcpy(file,"log.txt");
	
	cat = fopen(file, "r");
	if (!cat) {
		printf("Error loading file...[%s]\n\n", filename);
		sleep(2);
		mainMenu();
		}
	else{
		strcpy(catfile,"cat ");
		strcat(catfile,file);
		strcat(catfile," |more");
		system(catfile);
	}
	
	fclose(cat);
	PressEnterToReturn();
	mainMenu();

}

//Stop capture with CTRL-C
void ex_program(int sig) 
{
         if(stopApp == 1)main();
         printf("\nTerminated... Press ENTER to return...\n");
        //(void) signal(SIGINT, SIG_DFL);
         signal(SIGKILL, SIG_DFL);
         stopApp = 1;
}
