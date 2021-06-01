#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

struct node { 
    bpf_u_int32 data; 
    struct node* next; 
}; 

struct network_flow {
    bpf_u_int32 source_ip;
    u_short source_port;
    bpf_u_int32 destination_ip;
    u_short destination_port;
    u_char protocol;
    struct network_flow *next;
};

struct my_ip {
    u_int8_t    ip_vhl;     /* header length, version */
#define IP_V(ip)    (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)   ((ip)->ip_vhl & 0x0f)
    u_int8_t    ip_tos;     /* type of service */
    u_int16_t   ip_len;     /* total length */
    u_int16_t   ip_id;      /* identification */
    u_int16_t   ip_off;     /* fragment offset field */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_int8_t    ip_ttl;     /* time to live */
    u_int8_t    ip_p;       /* protocol */
    u_int16_t   ip_sum;     /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

void my_packet_handler(u_char *args,const struct pcap_pkthdr *header,const u_char *packet);
struct node *addNewNode(struct node *, bpf_u_int32);
void freeNode(struct node *);
int isInsideThisData(struct node *,bpf_u_int32);
struct network_flow *addNewNetworkFlow(struct network_flow *,bpf_u_int32 ,u_short ,bpf_u_int32 ,u_short ,u_char);
void freeNetworkFlow(struct network_flow *);
int doesExistThisNetworkFlow(struct network_flow *,bpf_u_int32 ,u_short ,bpf_u_int32 ,u_short ,u_char);

struct network_flow *addNewNetworkFlow(struct network_flow *head,bpf_u_int32 source_ip,u_short source_port,bpf_u_int32 destination_ip,u_short destination_port,u_char protocol){
    if(head==NULL){
        head = malloc(sizeof(struct network_flow));
        head->source_ip = source_ip;
        head->source_port = source_port;
        head->destination_ip = destination_ip;
        head->destination_port = destination_port;
        head->protocol = protocol;
        head->next = NULL;
        return head;
    }else{
        struct network_flow *cur;
        cur = head;
        while(cur->next!=NULL){
            cur = cur->next;
        }
        cur->next = malloc(sizeof(struct network_flow));
        cur->source_ip = source_ip;
        cur->source_port = source_port;
        cur->destination_ip = destination_ip;
        cur->destination_port = destination_port;
        cur->protocol = protocol;
        cur->next = NULL;
        return head;
    }
}


struct node *addNewNode(struct node *head, bpf_u_int32 newData){
    if(head==NULL){
        struct node *curNode = malloc(sizeof(struct node));
        curNode->data = newData;
        curNode->next = NULL;
        return curNode;
    }else{
        struct node *cur;
        cur = head;
        while(cur->next!=NULL){
            cur = cur->next;
        }
        cur->next = malloc(sizeof(struct node));
        cur = cur->next;
        cur->data = newData;
        cur->next = NULL;
        return head;
    }
}

void freeNetworkFlow(struct network_flow *head){
    struct network_flow *prev;
    while(head!=NULL){
        prev = head;
        head = head->next;
        free(prev);
    }
}
void freeNode(struct node *head){
    struct node *prev;
    while(head!=NULL){
        prev = head;
        head = head->next;
        free(prev);
    }
}
int doesExistThisNetworkFlow(struct network_flow *head,bpf_u_int32 source_ip,u_short source_port,bpf_u_int32 destination_ip,u_short destination_port,u_char protocol){
    while(head!=NULL){
        if(head->source_ip==source_ip&&head->source_port==source_port&&head->destination_ip==destination_ip&&head->destination_port==destination_port&&head->protocol==protocol){
            return 1;
        }
        head=head->next;
    }
    return 0;
}

int isInsideThisData(struct node *head,bpf_u_int32 data){
    while(head!=NULL){
        if(head->data==data){
            return 1;
        }
        head = head->next;
    }
    return 0;
}


void networkInterfaceName(char *device){
    char error_buffer[PCAP_ERRBUF_SIZE];
    char ip[13];
    char subnet_mask[13];
    bpf_u_int32 ip_raw; // IP address as integer 
    bpf_u_int32 subnet_mask_raw; // Subnet mask as integer 
    struct in_addr address; // Used for both ip & subnet 

    // Live Capture...
    pcap_t *handle;   //  pcap_t is the device handle from where we want to capture.
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    int packet_count_limit = 0;
    int timeout_limit = 10000; // In milliseconds 

    handle = pcap_open_live(device,BUFSIZ,packet_count_limit,timeout_limit,error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
        return;
    }
    printf("Monitoring the network traffic...\n");
    time_t rawtime_now;
    time_t rawtime_later;
    //struct tm * timeinfo;
    time ( &rawtime_now );
    //timeinfo = localtime ( &rawtime );
    //printf ( "Current local time and date: %s", asctime (timeinfo) );

    int counter = 0;
    int networkFlowCounter = 0;
    int tcpNetworkFlows = 0;
    int udpNetworkFlows = 0;
    int tcpPackets = 0;
    int udpPackets = 0;
    int byteOfTcpPackets = 0;
    int byteOfUdpPackets = 0;
    int timer = 0;
    struct node *head = NULL;
    struct network_flow *head2 = NULL;
    while(1){
        packet = pcap_next(handle, &packet_header);
        time ( &rawtime_later );
        if(rawtime_later-rawtime_now>120){
            break;
        }
        if(packet!=NULL){
            struct ether_header *eth_header;
            eth_header = (struct ether_header *) packet;
            counter++;
            if (ntohs(eth_header->ether_type) != ETHERTYPE_IP){
                //Not an IP packet. Skipping...
                continue;
            }
            const struct my_ip* ip;
            ip = (struct my_ip*)(packet + sizeof(struct ether_header));
            u_int version;
            version = IP_V(ip); // ip version 
            printf("We have an IP packet, version = %d\n",version);
             // Pointers to start point of various headers
            const u_char *ip_header;
            const u_char *tcp_header;
            const u_char *udp_header;
            const u_char *payload;
            int ethernet_header_length = 14; // Doesn't change 
            int ip_header_length;
            int tcp_header_length;
            int payload_length;
            struct in_addr address;
            // Find start of IP header
            ip_header = packet + ethernet_header_length;
            // The second-half of the first byte in ip_header
            //contains the IP header length (IHL). 
            ip_header_length = ((*ip_header) & 0x0F);
            // The ip_header_length is number of 32-bit segments. Multiply
            //by four to get a byte count 
            ip_header_length = ip_header_length * 4;
            printf("IP header length (IHL) in bytes: %d\n", ip_header_length);
            u_char protocol = *(ip_header + 9);
            // the  Source Address  is alwayes the 13th byte of the IP header
            bpf_u_int32 source = *(ip_header + 12);
            // Get ip source in human readable form 
            address.s_addr = source;
            char source_ip[20];
            strcpy(source_ip, inet_ntoa(address));
            if(source_ip == NULL){
               perror("inet_ntoa");}
            else{
                printf("Source IP address: %s\n", source_ip);}
            // the  Source Address  is alwayes the 17th byte of the IP header
            bpf_u_int32 destination = *(ip_header + 16);
            // Get ip destination in human readable form 
            address.s_addr = destination;
            char destination_ip[13];
            strcpy(destination_ip, inet_ntoa(address));
            if(destination_ip==NULL){
                perror("inet_ntoa");}
            else{
                printf("Source IP address: %s\n", destination_ip);}




            if (protocol == IPPROTO_TCP) {
                tcpPackets++;
                timer++;
                if(timer>3){
                    freeNode(head);
                    head = NULL;
                    timer = 0;
                }
                // Add the ethernet and ip header length to the start of the packet
                //to find the beginning of the TCP header 
                tcp_header = packet + ethernet_header_length + ip_header_length;
                // the source port is the first 2 bytes of the tcp header
                u_short source_port = *(tcp_header);
                printf("source port: .%d\n",source_port);
                // the destination port is the 3th and 4th byte of the tcp header
                u_short destination_port = *(tcp_header+2);
                printf("destination port: .%d\n",destination_port);
                printf(" TCP packet.\n");
                bpf_u_int32 sequence_number = *(tcp_header+4);
                printf("sequence_number = %d\n", sequence_number);
                if(isInsideThisData(head, sequence_number)){
                    // it is already stored in the list
                    printf("Retransmitted\n");
                }
                else{
                    head = addNewNode(head,sequence_number);
                    printf("No Retransmitted\n");
                }
                printf("outside of add new node\n");
                tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
                tcp_header_length = tcp_header_length * 4;
                printf("TCP header length in bytes: %d\n", tcp_header_length);
                // Add up all the header sizes to find the payload offset 
                int total_headers_size = ethernet_header_length + ip_header_length + tcp_header_length;
                //printf("Size of all headers combined: %d bytes\n", total_headers_size);
                payload_length = packet_header.caplen - total_headers_size;
                byteOfTcpPackets+=packet_header.caplen;
                printf("Payload size: %d bytes\n", payload_length);
                payload = packet + total_headers_size;
                //printf("Memory address where payload begins: %p\n\n", payload);
                if(doesExistThisNetworkFlow(head2,source_ip,source_port,destination_ip,destination_port,protocol)){
                    // this networkflow already exists
                }else{
                    head2 = addNewNetworkFlow(head2,source_ip,source_port,destination_ip,destination_port,protocol);
                    networkFlowCounter++;
                    tcpNetworkFlows++;
                }
                printf("========================================\n");
                continue;
            }
            else if(protocol == IPPROTO_UDP){
                udpPackets++;
                // Add the ethernet and ip header length to the start of the packet
                //to find the beginning of the UDP header 
                udp_header = packet + ethernet_header_length + ip_header_length;
                u_short source_port = *(udp_header);
                printf("source port: .%d\n",source_port);
                u_short destination_port = *(udp_header+2);
                printf("destination port: .%d\n",destination_port);
                printf(" UDP packet.\n");
                printf("UDP header length is 8 bytes\n");
                int total_headers_size = ethernet_header_length + ip_header_length + 8;
                payload_length = packet_header.caplen - total_headers_size;
                byteOfUdpPackets+=packet_header.caplen;
                //u_short length = *(udp_header+4);
                printf("The UDP payload length in bytes is: %d\n",payload_length );
                if(doesExistThisNetworkFlow(head2,source_ip,source_port,destination_ip,destination_port,protocol)){
                    // this networkflow already exists
                }else{
                    head2 = addNewNetworkFlow(head2,source_ip,source_port,destination_ip,destination_port,protocol);
                    networkFlowCounter++;
                    udpNetworkFlows++;
                }
                printf("========================================\n");
                continue;
            }
            else{
                //printf("Not a TCP/UDP packet. Skipping...\n");
                continue;
            }

        }
    }
    freeNode(head);
    freeNetworkFlow(head2);


    printf("Total number of network flows captured: %d\n",networkFlowCounter);
    printf("Number of TCP network flows captured: %d\n",tcpNetworkFlows);
    printf("Number of UDP network flows captured: %d\n",udpNetworkFlows);
    printf("Total number of packets received: %d\n",counter);
    printf("Total number of TCP packets received: %d\n",tcpPackets);
    printf("Total number of UDP packets received: %d\n",udpPackets);
    printf("Total bytes of TCP packets received: %d\n",byteOfTcpPackets);
    printf("Total bytes of UDP packets received: %d\n",byteOfUdpPackets);



    return;
}

void pcapFilename(char *filename){
    pcap_t *handle;
    char error_buffer[PCAP_ERRBUF_SIZE];
    char ip[13];
    char subnet_mask[13];
    bpf_u_int32 ip_raw; // IP address as integer 
    bpf_u_int32 subnet_mask_raw; // Subnet mask as integer 
    struct in_addr address; // Used for both ip & subnet 
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    int packet_count_limit = 0;
    int timeout_limit = 10000; // In milliseconds 

    handle = pcap_open_offline(filename,error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "Could not open the pcap file %s: %s\n", filename, error_buffer);
        return;
    }

    int counter = 0;
    int networkFlowCounter = 0;
    int tcpNetworkFlows = 0;
    int udpNetworkFlows = 0;
    int tcpPackets = 0;
    int udpPackets = 0;
    int byteOfTcpPackets = 0;
    int byteOfUdpPackets = 0;
    int timer = 0;
    struct node *head = NULL;
    struct network_flow *head2 = NULL;

    while( (packet = pcap_next(handle, &packet_header)) !=  NULL){
        if(packet!=NULL){
            struct ether_header *eth_header;
            eth_header = (struct ether_header *) packet;
            counter++;
            if (ntohs(eth_header->ether_type) != ETHERTYPE_IP){
                //Not an IP packet. Skipping...
                continue;
            }
            const struct my_ip* ip;
            ip = (struct my_ip*)(packet + sizeof(struct ether_header));
            u_int version;
            version = IP_V(ip); // ip version 
            printf("We have an IP packet, version = %d\n",version);
             // Pointers to start point of various headers
            const u_char *ip_header;
            const u_char *tcp_header;
            const u_char *udp_header;
            const u_char *payload;
            int ethernet_header_length = 14; // Doesn't change 
            int ip_header_length;
            int tcp_header_length;
            int payload_length;
            struct in_addr address;
            // Find start of IP header
            ip_header = packet + ethernet_header_length;
            // The second-half of the first byte in ip_header
            //contains the IP header length (IHL). 
            ip_header_length = ((*ip_header) & 0x0F);
            // The ip_header_length is number of 32-bit segments. Multiply
            //by four to get a byte count 
            ip_header_length = ip_header_length * 4;
            printf("IP header length (IHL) in bytes: %d\n", ip_header_length);
            u_char protocol = *(ip_header + 9);
            // the  Source Address  is alwayes the 13th byte of the IP header
            bpf_u_int32 source = *(ip_header + 12);
            // Get ip source in human readable form 
            address.s_addr = source;
            char source_ip[20];
            strcpy(source_ip, inet_ntoa(address));
            if(source_ip == NULL){
               perror("inet_ntoa");}
            else{
                printf("Source IP address: %s\n", source_ip);}
            // the  Source Address  is alwayes the 17th byte of the IP header
            bpf_u_int32 destination = *(ip_header + 16);
            // Get ip destination in human readable form 
            address.s_addr = destination;
            char destination_ip[13];
            strcpy(destination_ip, inet_ntoa(address));
            if(destination_ip==NULL){
                perror("inet_ntoa");}
            else{
                printf("Source IP address: %s\n", destination_ip);}




            if (protocol == IPPROTO_TCP) {
                tcpPackets++;
                timer++;
                if(timer>3){
                    freeNode(head);
                    head = NULL;
                    timer = 0;
                }
                // Add the ethernet and ip header length to the start of the packet
                //to find the beginning of the TCP header 
                tcp_header = packet + ethernet_header_length + ip_header_length;
                // the source port is the first 2 bytes of the tcp header
                u_short source_port = *(tcp_header);
                printf("source port: .%d\n",source_port);
                // the destination port is the 3th and 4th byte of the tcp header
                u_short destination_port = *(tcp_header+2);
                printf("destination port: .%d\n",destination_port);
                printf(" TCP packet.\n");
                bpf_u_int32 sequence_number = *(tcp_header+4);
                printf("sequence_number = %d\n", sequence_number);
                if(isInsideThisData(head, sequence_number)){
                    // it is already stored in the list
                    printf("Retransmitted\n");
                }
                else{
                    head = addNewNode(head,sequence_number);
                    printf("No Retransmitted\n");
                }
                printf("outside of add new node\n");
                tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
                tcp_header_length = tcp_header_length * 4;
                printf("TCP header length in bytes: %d\n", tcp_header_length);
                // Add up all the header sizes to find the payload offset 
                int total_headers_size = ethernet_header_length + ip_header_length + tcp_header_length;
                //printf("Size of all headers combined: %d bytes\n", total_headers_size);
                payload_length = packet_header.caplen - total_headers_size;
                byteOfTcpPackets+=packet_header.caplen;
                printf("Payload size: %d bytes\n", payload_length);
                payload = packet + total_headers_size;
                //printf("Memory address where payload begins: %p\n\n", payload);
                if(doesExistThisNetworkFlow(head2,source_ip,source_port,destination_ip,destination_port,protocol)){
                    // this networkflow already exists
                }else{
                    head2 = addNewNetworkFlow(head2,source_ip,source_port,destination_ip,destination_port,protocol);
                    networkFlowCounter++;
                    tcpNetworkFlows++;
                }
                printf("========================================\n");
                continue;
            }
            else if(protocol == IPPROTO_UDP){
                udpPackets++;
                // Add the ethernet and ip header length to the start of the packet
                //to find the beginning of the UDP header 
                udp_header = packet + ethernet_header_length + ip_header_length;
                u_short source_port = *(udp_header);
                printf("source port: .%d\n",source_port);
                u_short destination_port = *(udp_header+2);
                printf("destination port: .%d\n",destination_port);
                printf(" UDP packet.\n");
                printf("UDP header length is 8 bytes\n");
                int total_headers_size = ethernet_header_length + ip_header_length + 8;
                payload_length = packet_header.caplen - total_headers_size;
                byteOfUdpPackets+=packet_header.caplen;
                //u_short length = *(udp_header+4);
                printf("The UDP payload length in bytes is: %d\n",payload_length );
                if(doesExistThisNetworkFlow(head2,source_ip,source_port,destination_ip,destination_port,protocol)){
                    // this networkflow already exists
                }else{
                    head2 = addNewNetworkFlow(head2,source_ip,source_port,destination_ip,destination_port,protocol);
                    networkFlowCounter++;
                    udpNetworkFlows++;
                }
                printf("========================================\n");
                continue;
            }
            else{
                //printf("Not a TCP/UDP packet. Skipping...\n");
                continue;
            }

        }
    }
    freeNode(head);
    freeNetworkFlow(head2);


    printf("Total number of network flows captured: %d\n",networkFlowCounter);
    printf("Number of TCP network flows captured: %d\n",tcpNetworkFlows);
    printf("Number of UDP network flows captured: %d\n",udpNetworkFlows);
    printf("Total number of packets received: %d\n",counter);
    printf("Total number of TCP packets received: %d\n",tcpPackets);
    printf("Total number of UDP packets received: %d\n",udpPackets);
    printf("Total bytes of TCP packets received: %d\n",byteOfTcpPackets);
    printf("Total bytes of UDP packets received: %d\n",byteOfUdpPackets);



    return;
}
/*
int main(int argc, char **argv){
    char *device; // name of the device (e.g. etho , wlo1)
    char error_buffer[PCAP_ERRBUF_SIZE];

    // find the current device
    device = pcap_lookupdev(error_buffer);
    if (device == NULL) {
        printf("The device: %s didn't found.\n", error_buffer);
        return 1;
    }
    printf("The network device is: %s\n",device);


    char ip[13];
    char subnet_mask[13];
    bpf_u_int32 ip_raw; // IP address as integer 
    bpf_u_int32 subnet_mask_raw; // Subnet mask as integer 
    struct in_addr address; // Used for both ip & subnet 

    int lookup_return_code = pcap_lookupnet(device,&ip_raw,&subnet_mask_raw,error_buffer);
    if (lookup_return_code == -1) {
        printf("%s\n", error_buffer);
        return 1;                           
    }

    // Get ip in human readable form 
    address.s_addr = ip_raw;
    strcpy(ip, inet_ntoa(address));
    if (ip == NULL) {
        perror("inet_ntoa"); // print error 
        return 1;
    }
    printf("IP address: %s\n", ip);
    
    // Get subnet mask in human readable form 
    address.s_addr = subnet_mask_raw;
    strcpy(subnet_mask, inet_ntoa(address));
    if (subnet_mask == NULL) {
        perror("inet_ntoa");
        return 1;
    }
    printf("Subnet mask: %s\n", subnet_mask);


    // Live Capture...
    pcap_t *handle;   //  pcap_t is the device handle from where we want to capture.
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    int packet_count_limit = 0;
    int timeout_limit = 10000; // In milliseconds 

    handle = pcap_open_live(device,BUFSIZ,packet_count_limit,timeout_limit,error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
        return 2;
    }
    printf("Monitoring the network traffic...\n");
    time_t rawtime_now;
    time_t rawtime_later;
    //struct tm * timeinfo;
    time ( &rawtime_now );
    //timeinfo = localtime ( &rawtime );
    //printf ( "Current local time and date: %s", asctime (timeinfo) );

    int counter = 0;
    int networkFlowCounter = 0;
    int tcpNetworkFlows = 0;
    int udpNetworkFlows = 0;
    int tcpPackets = 0;
    int udpPackets = 0;
    int byteOfTcpPackets = 0;
    int byteOfUdpPackets = 0;
    int timer = 0;
    struct node *head = NULL;
    struct network_flow *head2 = NULL;
    while(1){
        packet = pcap_next(handle, &packet_header);
        time ( &rawtime_later );
        if(rawtime_later-rawtime_now>120){
            break;
        }
        if(packet!=NULL){
            struct ether_header *eth_header;
            eth_header = (struct ether_header *) packet;
            counter++;
            if (ntohs(eth_header->ether_type) != ETHERTYPE_IP){
                //Not an IP packet. Skipping...
                continue;
            }
            const struct my_ip* ip;
            ip = (struct my_ip*)(packet + sizeof(struct ether_header));
            u_int version;
            version = IP_V(ip); // ip version 
            printf("We have an IP packet, version = %d\n",version);
             // Pointers to start point of various headers
            const u_char *ip_header;
            const u_char *tcp_header;
            const u_char *udp_header;
            const u_char *payload;
            int ethernet_header_length = 14; // Doesn't change 
            int ip_header_length;
            int tcp_header_length;
            int payload_length;
            struct in_addr address;
            // Find start of IP header
            ip_header = packet + ethernet_header_length;
            // The second-half of the first byte in ip_header
            //contains the IP header length (IHL). 
            ip_header_length = ((*ip_header) & 0x0F);
            // The ip_header_length is number of 32-bit segments. Multiply
            //by four to get a byte count 
            ip_header_length = ip_header_length * 4;
            printf("IP header length (IHL) in bytes: %d\n", ip_header_length);
            u_char protocol = *(ip_header + 9);
            // the  Source Address  is alwayes the 13th byte of the IP header
            bpf_u_int32 source = *(ip_header + 12);
            // Get ip source in human readable form 
            address.s_addr = source;
            char source_ip[20];
            strcpy(source_ip, inet_ntoa(address));
            if(source_ip == NULL){
               perror("inet_ntoa");}
            else{
                printf("Source IP address: %s\n", source_ip);}
            // the  Source Address  is alwayes the 17th byte of the IP header
            bpf_u_int32 destination = *(ip_header + 16);
            // Get ip destination in human readable form 
            address.s_addr = destination;
            char destination_ip[13];
            strcpy(destination_ip, inet_ntoa(address));
            if(destination_ip==NULL){
                perror("inet_ntoa");}
            else{
                printf("Source IP address: %s\n", destination_ip);}




            if (protocol == IPPROTO_TCP) {
                tcpPackets++;
                timer++;
                if(timer>3){
                    freeNode(head);
                    head = NULL;
                    timer = 0;
                }
                // Add the ethernet and ip header length to the start of the packet
                //to find the beginning of the TCP header 
                tcp_header = packet + ethernet_header_length + ip_header_length;
                // the source port is the first 2 bytes of the tcp header
                u_short source_port = *(tcp_header);
                printf("source port: .%d\n",source_port);
                // the destination port is the 3th and 4th byte of the tcp header
                u_short destination_port = *(tcp_header+2);
                printf("destination port: .%d\n",destination_port);
                printf(" TCP packet.\n");
                bpf_u_int32 sequence_number = *(tcp_header+4);
                printf("sequence_number = %d\n", sequence_number);
                if(isInsideThisData(head, sequence_number)){
                    // it is already stored in the list
                    printf("Retransmitted\n");
                }
                else{
                    head = addNewNode(head,sequence_number);
                    printf("No Retransmitted\n");
                }
                printf("outside of add new node\n");
                tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
                tcp_header_length = tcp_header_length * 4;
                printf("TCP header length in bytes: %d\n", tcp_header_length);
                // Add up all the header sizes to find the payload offset 
                int total_headers_size = ethernet_header_length + ip_header_length + tcp_header_length;
                //printf("Size of all headers combined: %d bytes\n", total_headers_size);
                payload_length = packet_header.caplen - total_headers_size;
                byteOfTcpPackets+=packet_header.caplen;
                printf("Payload size: %d bytes\n", payload_length);
                payload = packet + total_headers_size;
                //printf("Memory address where payload begins: %p\n\n", payload);
                if(doesExistThisNetworkFlow(head2,source_ip,source_port,destination_ip,destination_port,protocol)){
                    // this networkflow already exists
                }else{
                    head2 = addNewNetworkFlow(head2,source_ip,source_port,destination_ip,destination_port,protocol);
                    networkFlowCounter++;
                    tcpNetworkFlows++;
                }
                printf("========================================\n");
                continue;
            }
            else if(protocol == IPPROTO_UDP){
                udpPackets++;
                // Add the ethernet and ip header length to the start of the packet
                //to find the beginning of the UDP header 
                udp_header = packet + ethernet_header_length + ip_header_length;
                u_short source_port = *(udp_header);
                printf("source port: .%d\n",source_port);
                u_short destination_port = *(udp_header+2);
                printf("destination port: .%d\n",destination_port);
                printf(" UDP packet.\n");
                printf("UDP header length is 8 bytes\n");
                int total_headers_size = ethernet_header_length + ip_header_length + 8;
                payload_length = packet_header.caplen - total_headers_size;
                byteOfUdpPackets+=packet_header.caplen;
                //u_short length = *(udp_header+4);
                printf("The UDP payload length in bytes is: %d\n",payload_length );
                if(doesExistThisNetworkFlow(head2,source_ip,source_port,destination_ip,destination_port,protocol)){
                    // this networkflow already exists
                }else{
                    head2 = addNewNetworkFlow(head2,source_ip,source_port,destination_ip,destination_port,protocol);
                    networkFlowCounter++;
                    udpNetworkFlows++;
                }
                printf("========================================\n");
                continue;
            }
            else{
                //printf("Not a TCP/UDP packet. Skipping...\n");
                continue;
            }

        }
    }
    freeNode(head);
    freeNetworkFlow(head2);


    printf("Total number of network flows captured: %d\n",networkFlowCounter);
    printf("Number of TCP network flows captured: %d\n",tcpNetworkFlows);
    printf("Number of UDP network flows captured: %d\n",udpNetworkFlows);
    printf("Total number of packets received: %d\n",counter);
    printf("Total number of TCP packets received: %d\n",tcpPackets);
    printf("Total number of UDP packets received: %d\n",udpPackets);
    printf("Total bytes of TCP packets received: %d\n",byteOfTcpPackets);
    printf("Total bytes of UDP packets received: %d\n",byteOfUdpPackets);



    return 0;
}*/

void
usage(void)
{
    printf(
           "\n"
           "usage:\n"
           "\t./monitor \n"
           "Options:\n"
           "-i <network interface name> Monitors the network traffic for 2 mins\n"
           "-r <packet capture file name> Monitors a pcap file\n"
           "-h, Help message\n\n"
           );

    exit(1);
}



int 
main(int argc, char *argv[])
{

    int ch;
    FILE *log;
    int x;

    if (argc < 2)
        usage();

    while ((ch = getopt(argc, argv, "hi:r:")) != -1) {
        switch (ch) {       
        case 'i':
            printf("i option value = %s\n",optarg);
            networkInterfaceName(optarg);
            break;
        case 'r':
            printf("r option value = %s\n",optarg);
            pcapFilename(optarg);
            break;
        default:
            usage();
        }

    }

    argc -= optind;
    argv += optind; 
    
    return 0;
}


