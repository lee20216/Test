// 네트워크 인턴페이스 정보 패킷 캡쳐
// ip 주소 출력 추가

#include <stdio.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <pcap.h>

//struct pcap_pkthdr *header; //패킷 관련 정보
//const u_char *packet; // 실제 패킷
//struct in_addr addr; // 주소정보



////////////////////// mac ////////////////////////////////
#define ETHER_ADDR_LEN 6 

struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN]; // 목적지 MAC 주소
        u_char ether_shost[ETHER_ADDR_LEN]; // 출발지 MAC 주소
        u_short ether_type;
};


////////////////////// port ///////////////////////////////
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport; // 출발지 TCP 주소
        u_short th_dport; // 목적지 TCP 주소
        tcp_seq th_seq;
        tcp_seq th_ack;
        u_char th_offx2;
        #define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
        u_char th_flags;
        #define TH_FIN 0x01
        #define TH_SYN 0x02
        #define TH_RST 0x04
        #define TH_PUSH 0x08
        #define TH_ACK 0x10
        #define TH_URG 0x20
        #define TH_ECE 0x40
        #define TH_CWR 0x80
        #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;
        u_short th_sum;
        u_short th_urp;
};

/////////////////////// ip /////////////////////// 
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

//bpf_u_int32 net; // 아이피 주소



#define SIZE_ETHERNET 14 //ip

struct sniff_ip {
        u_char ip_vhl;
        u_char ip_tos;
        u_short ip_len;
        u_short ip_id;
        u_short ip_off;
        #define IP_RF 0x8000
        #define IP_DF 0x4000
        #define IP_MF 0x2000
        #define IP_OFFMASK 0x1fff
        u_char ip_ttl;
        u_char ip_p; // IP 프로토콜 유형
        u_short ip_sum;
        struct in_addr ip_src; // 출발지 IP 주소
        struct in_addr ip_dst; // 목적지 IP 주소
};


struct sniff_ip *ip; // IP 헤더
struct sniff_ethernet *ethernet; // 이더넷 헤더(mac 출력)
struct sniff_tcp *tcp; // TCP 혜더(port 출력)

u_int size_ip;
u_int size_tcp;


//packet_handler(사용자가 파라미터로 넘겨받은 값, 캡쳐된 패킷의 정보 구조체, 캡쳐된 패킷의 시작 주소) 
void packet_handler(u_char *param,
  const struct pcap_pkthdr *header, const u_char *pkt_data) {
 // printf("caplen : %d\n", header->caplen); //실제 읽은 길이
 // printf("len : %d\n", header->len); // 캡쳐한 패킷의 길
 
//void parsing(){

    int i;

    ethernet = (struct sniff_ethernet*)(pkt_data);
        printf("MAC 출발지 주소 :");
        for(i = 0; i < ETHER_ADDR_LEN; i++) {
                printf("%02x ", ethernet->ether_shost[i]);
        }
        printf("\nMAC 목적지 주소 :");
        for(i = 0; i < ETHER_ADDR_LEN; i++) {
                printf("%02x ", ethernet->ether_dhost[i]);
        }
        // printf("\n이더넷 타입 : ");
        // for(i = 0; i < ETHER_ADDR_LEN; i++) {
        //         printf("%s ", ntohs(ethernet->ether_type)); //ntohs() 네트워크 바이트 순서를 호스트의 바이트 순서로 변경)
        // }


    ip = (struct sniff_ip*)(pkt_data + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        printf("\nIP 출발지 주소: %s\n", inet_ntoa(ip->ip_src));//inet_ntoa() 네트워크 바이트 정렬 방식의 4바이트 정수의 IPv4 주소를문자열 주소로 표현
        printf("IP 목적지 주소: %s\n", inet_ntoa(ip->ip_dst));

     tcp = (struct sniff_tcp*)(pkt_data + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        printf("출발지 포트: %d\n", ntohs(tcp->th_sport));
        printf("목적지 포트: %d\n", ntohs(tcp->th_dport));
        printf("\n");
}

int main(int argc, char **argv) {
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *d;
    struct pcap_addr *a;
    int i = 0;
    int no;

    bpf_u_int32 net; // 아이피 주소
   // struct sniff_ip *ip; // IP 헤더
   // u_int size_ip;

    if (pcap_findalldevs(&alldevs, errbuf) < 0) { //디바이스 검색
        printf("pcap_findalldevs error\n");
        return 1;
    }

    for (d=alldevs; d; d=d->next) { 
        printf("%d :  %s\n", ++i, (d->description)?(d->description):(d->name));
    }

    printf("number : ");
    scanf("%d", &no);

    if (!(no > 0 && no <= i)) {
        printf("number error\n");
        return 1;
    }

    for (d=alldevs, i=0; d; d=d->next) {
        if (no == ++i)  break;
    }

    if (!(adhandle= pcap_open_live(d->name, 65536, 1, 1000, errbuf))) { //패킷 캡처
       //pcap_open_live(장치이름, 패킷 길이, 모든 패킷을 잡을 수 있는 promisc 모드로설정, 패킷을읽는 시간, 에러버퍼)
        printf("pcap_open_live error %s\n", d->name);
        pcap_freealldevs(alldevs);
        return -1;
    }

    pcap_freealldevs(alldevs); //디바이스 해제

    pcap_loop(adhandle, 0, packet_handler, NULL);//0 무한루프 패킷이 감지되면 packet_handler 호출

    pcap_close(adhandle);

    return 0;
}
