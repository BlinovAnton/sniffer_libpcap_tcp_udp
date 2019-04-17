#include <stdio.h>
#include <pcap.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAC_ADDR_LEN 6
#define ETHERNET_HDR_LEN 14
#define ADVISED_MAX_PACKET_SIZE 65535
#define MIN_IP_HDR_LEN 20
#define UDP_HDR_LEN 8

struct ethernet_header {
    u_char dest_mac[MAC_ADDR_LEN];
    u_char sour_mac[MAC_ADDR_LEN];
    u_short proto_type;
};

struct ip_header {
    u_char ver_hdr_len;
    u_char tos;
    u_short pack_len;
    u_short ident;
    u_short flags_offset;
    u_char ttl;
    u_char protocol;
    u_short hdr_chck_sum;
    struct in_addr dest_ip;
    struct in_addr src_ip;
};

struct udp_header {
    u_short src_port;
    u_short dest_port;
    u_short length;
    u_short chck_sum;
};
//fgh
struct tcp_header {
    u_short src_port;
    u_short dest_port;
    u_int seq_num;
    u_int ack_num;
    u_short offset_flags;
    u_short win_size;
    u_short chck_sum;
    u_short urg_p;
};

void print_ethernet_header (const u_char *packet) {
    int i;
    struct ethernet_header *ethhdr = (struct ethernet_header *)packet;

    printf("destination MAC:  ");
    for (i = 0; i < MAC_ADDR_LEN; i++) {
	printf("%.2x ", ethhdr->dest_mac[i]);
    }
    printf("\n");

    printf("source MAC:       ");
    for (i = 0; i < MAC_ADDR_LEN; i++) {
	printf("%.2x ", ethhdr->sour_mac[i]);
    }
    printf("\n");

    printf("Protocol type:    %d\n", ethhdr->proto_type);
}

u_char print_ip_header(const u_char *packet) {
    int i, start_option_pos;
    struct ip_header *ip_hdr = (struct ip_header *)(packet + ETHERNET_HDR_LEN);
    int ip_hdr_len = ip_hdr->ver_hdr_len & 15, ip_ver = ip_hdr->ver_hdr_len >> 4;
    int ip_hdr_flags = ip_hdr->flags_offset >> 13, ip_hdr_offset = ip_hdr->flags_offset & 8191;
    printf("Version:          %d", ip_ver);
    if (ip_ver == 4) printf(" (IPv4)");
    printf("\nIP Header Length: %d (%d bytes)\n", ip_hdr_len, ip_hdr_len * 4);
    printf("Type of Service:  %d-%d\n", ip_hdr->tos, ntohs(ip_hdr->tos));
    printf("Packet Length:    %d\n", ntohs(ip_hdr->pack_len));
    printf("Identificator:    %d-%d\n", ip_hdr->ident, ntohs(ip_hdr->ident));
    printf("Flags:            %d-%d\n", ip_hdr_flags, ntohs(ip_hdr_flags));
    printf("Offset:           %d-%d\n", ip_hdr_offset, ntohs(ip_hdr_offset));
    printf("TTL:              %d\n", ip_hdr->ttl);
    printf("Protocol:         %d\n", ip_hdr->protocol);
    printf("Hdr check sum:    %d-%d\n", ip_hdr->hdr_chck_sum, ntohs(ip_hdr->hdr_chck_sum));
    printf("Source IP-address %s\n", inet_ntoa(ip_hdr->dest_ip));
    printf("Dest.  IP-address %s\n", inet_ntoa(ip_hdr->src_ip));
    if (ip_hdr_len * 4 > MIN_IP_HDR_LEN) printf("Options:\n");
    start_option_pos = ETHERNET_HDR_LEN + MIN_IP_HDR_LEN;
    for (i = start_option_pos; i < start_option_pos + ip_hdr_len * 4 - MIN_IP_HDR_LEN; i++) {
	printf("%d ", packet[i]);
    }
    return ip_hdr->protocol;
}

int print_udp_header(const u_char *packet) {
    int i = 14, ip_hdr_len, udp_hdr_n_data_len;
    ip_hdr_len = (packet[i] & 15) * 4; // 1st 4 bits of 1st byte at ip_header (*4 for trans words to bytes)
    struct udp_header *udp_hdr = (struct udp_header *)(packet + ETHERNET_HDR_LEN + ip_hdr_len);
    printf("Source port:      %d\n", ntohs(udp_hdr->src_port));
    printf("Dest. port:       %d\n", ntohs(udp_hdr->dest_port));
    udp_hdr_n_data_len = ntohs(udp_hdr->length);
    printf("Length:           %d bytes\n", udp_hdr_n_data_len);
    printf("Check sum:        %d-%d\n", udp_hdr->chck_sum, ntohs(udp_hdr->chck_sum));
    return udp_hdr_n_data_len;
}

int print_tcp_header(const u_char *packet) {
    int i = 14, ip_hdr_len, tcp_hdr_len;
    ip_hdr_len = (packet[i] & 15) * 4; // 1st 4 bits of 1st byte at ip_header (*4 for trans words to bytes)
    struct tcp_header *tcp_hdr = (struct tcp_header *)(packet + ETHERNET_HDR_LEN + ip_hdr_len);
    printf("Source port:      %d\n", ntohs(tcp_hdr->src_port));
    printf("Dest. port:       %d\n", ntohs(tcp_hdr->dest_port));
    printf("Sequence num:     %u\n", ntohl(tcp_hdr->seq_num));
    printf("Acknowledge num:  %u\n", ntohl(tcp_hdr->ack_num));
    printf("Offset-Reserved-Flags: %d\n", ntohs(tcp_hdr->offset_flags));
    tcp_hdr_len = ntohs(tcp_hdr->offset_flags) >> 12;
    printf("Offset:           %d\n", tcp_hdr_len);
    printf("Reserved:         %d\n", ntohs(tcp_hdr->offset_flags) & 3584);
    printf("Flags:            %d\n", ntohs(tcp_hdr->offset_flags) & 511);
    printf("Window size:      %d\n", tcp_hdr->win_size);
    printf("Check sum:        %d-%d\n", tcp_hdr->chck_sum, ntohs(tcp_hdr->chck_sum));
    printf("Urgent pointer:   %d-%d\n", tcp_hdr->urg_p, ntohs(tcp_hdr->urg_p));
    return tcp_hdr_len * 4;
}

void print_char_data (const u_char *packet, int end_point) {
    int i = 0;
    for (; i < end_point; i++) {
	if (isprint(packet[i])) {
	    printf("%c", packet[i]);
	} else {
	    printf(".");
	}
	if (i > 0 && i % 30 == 0) printf("\n");
    }
}

void print_hex_data (const u_char *packet, int end_point) {
    int i = 0;
    for (; i < end_point; i++) {
	printf("%.2x ", packet[i]);
	if (i > 0 && i % 30 == 0) printf("\n");
    }
}

void packet_processing (u_char* args, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    static int packet_number = 0;
    int i, lv4_proto, udp_len, ip_hdr_len, hdrs_offset, tcp_hdr_len;
    unsigned short total_length;
    printf("\n-----------------------------------packet #%d\n", ++packet_number);
    print_ethernet_header(packet);
    lv4_proto = print_ip_header(packet);
    struct ip_header *ip_hdr = (struct ip_header *)(packet + ETHERNET_HDR_LEN);
    ip_hdr_len = (ip_hdr->ver_hdr_len & 15) * 4;
    total_length = ntohs(ip_hdr->pack_len) + 14;
    switch (lv4_proto) {
	case 1:
	    printf("ICMP (%d)\n", lv4_proto);
	    break;
	case 2:
	    printf("IGMP (%d)\n", lv4_proto);
	    break;
	case 6:
	    printf("TCP (%d)\n", lv4_proto);
	    tcp_hdr_len = print_tcp_header(packet);
	    printf("Payload:\n");
	    hdrs_offset = ETHERNET_HDR_LEN + ip_hdr_len + tcp_hdr_len;
	    print_char_data(packet + hdrs_offset, total_length - (hdrs_offset));
	    printf("\n");
	    break;
	case 17:
	    printf("UDP (%d)\n", lv4_proto);
	    udp_len = print_udp_header(packet);
	    printf("Payload:\n");
	    hdrs_offset = ETHERNET_HDR_LEN + ip_hdr_len + UDP_HDR_LEN;
	    print_char_data(packet + hdrs_offset, udp_len - UDP_HDR_LEN);
	    printf("\n");
	    break;
	case 41:
	    printf("ENCAP (%d)\n", lv4_proto);
	    break;
	case 89:
	    printf("OSPF (%d)\n", lv4_proto);
	    break;
	case 132:
	    printf("SCTP (%d)\n", lv4_proto);
	    break;
	default:
	    printf("Unknown proto (%d)\n", lv4_proto);
	    break;
    }
    printf("\npacket in char:\n");
    print_char_data(packet, total_length);
    printf("\npacket in hex:\n");
    print_hex_data(packet, total_length);
    printf("\n");
}

int main () {
    char *dev;
    pcap_t *openned_dev;
    struct bpf_program filter;
    struct in_addr in_addr_address;
    bpf_u_int32 uint_net_ip, uint_net_mask;
    char pcap_error_buff[PCAP_ERRBUF_SIZE];
    dev = pcap_lookupdev(pcap_error_buff);
    if (dev == NULL) {
	perror("error in function \"lookupdev()\"");
	return 0;
    }
    if (pcap_lookupnet(dev, &uint_net_ip, &uint_net_mask, pcap_error_buff) != 0) {
	perror("error in function \"lookupnet\"");
    }

    printf("dev %s, ", dev);
    in_addr_address.s_addr = uint_net_ip;
    printf("net %s, ", inet_ntoa(in_addr_address));
    in_addr_address.s_addr = uint_net_mask;
    printf("mask %s\n", inet_ntoa(in_addr_address));

    openned_dev = pcap_open_live(dev, ADVISED_MAX_PACKET_SIZE, 1, 0, pcap_error_buff);
    if (openned_dev == NULL) {
	perror("error in function \"pcap_open_live()\"");
	return 0;
    }

    /*if (pcap_compile(openned_dev, &filter, "", 0, uint_net_mask) == -1) {
	perror("error in function \"pcap_compile()\"");
	return 0;
    }
    if (pcap_setfilter(openned_dev, &filter) == -1) {
	perror("error in function \"pcap_setfilter()\"");
	return 0;
    }*/

    pcap_loop(openned_dev, 20, packet_processing, NULL);
    return 0;
}
