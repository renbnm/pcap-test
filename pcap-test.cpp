#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <algorithm>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

#pragma pack(push, 1)

typedef struct {
	uint8_t dmac_[6];
        uint8_t smac_[6];
	uint16_t type_;
} EthHdr;

typedef struct {
	uint8_t v_hl_;
	uint8_t tos_;
	uint16_t tlen_;
	uint16_t id_;
	uint16_t frag_off_;
        uint8_t ttl_;
        uint8_t proto_;
        uint16_t checksum_;
        uint32_t sip_;
	uint32_t dip_;
} IpHdr;

typedef struct {
        uint16_t sport_;
        uint16_t dport_;
        uint32_t seq_;
        uint32_t ack_;
        uint8_t offset_;
        uint8_t flags_;
        uint16_t window_;
        uint16_t checksum_;
        uint16_t urg_ptr_;
} TcpHdr;

#pragma pack(pop)

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		
		if (header->caplen < sizeof(EthHdr)) continue;

		EthHdr* eth = (EthHdr*)packet;

		if (ntohs(eth->type_) != 0x0800) continue;

		if (header->caplen < sizeof(EthHdr) + sizeof(IpHdr)) continue;
		
		IpHdr* ip = (IpHdr*)(packet + sizeof(EthHdr));
		int ip_hdr_len = (ip->v_hl_ & 0x0F) * 4;

		if (ip->proto_ != 0x06) continue;

		if (header->caplen < sizeof(EthHdr) + ip_hdr_len + sizeof(TcpHdr)) continue;

		TcpHdr* tcp = (TcpHdr*)((uint8_t*)ip + ip_hdr_len);
		int tcp_hdr_len = ((tcp->offset_ >> 4) & 0x0F) * 4;
		
		int total_hdr_len = sizeof(EthHdr) + ip_hdr_len + tcp_hdr_len;
		if (header->caplen < total_hdr_len) continue;

		const uint8_t* payload = packet + total_hdr_len;
		int payload_len = header->caplen - total_hdr_len;

		struct in_addr sip, dip;
		sip.s_addr = ip->sip_;
		dip.s_addr = ip->dip_;
		
		printf("*****Ethernet Header*****\n");
		printf("src mac : %02X", eth->smac_[0]);
		for(int i = 1; i < 6; i++)
			printf(":%02X", eth->smac_[i]);
		printf("\n");
		printf("dst mac : %02X", eth->dmac_[0]);
		for(int i = 1; i < 6; i++)
			printf(":%02X", eth->dmac_[i]);
		printf("\n\n");

		printf("*****IP Header*****\n");
		printf("src ip : %s\n", inet_ntoa(sip));
		printf("dst ip : %s\n\n", inet_ntoa(dip));
		
		printf("*****TCP Header*****\n");
		printf("src port : %u\n", ntohs(tcp->sport_));
		printf("dst port : %u\n\n", ntohs(tcp->dport_));

		printf("*****Payload*****\n");
		for(int i = 0; i < std::min(8, payload_len); i++)
			printf("%02X ", payload[i]);
		printf("\n\n\n");
		
	}

	pcap_close(pcap);
	return 0;
}

