//#ifdef _MSC_VER
///*
//* we do not want the warnings about the old deprecated and unsecure CRT functions
//* since these examples can be compiled under *nix as well
//*/
//#define _CRT_SECURE_NO_WARNINGS
//#endif

#include<iostream>
#include<string>
#include<pcap.h>
#include<time.h>
#include<sstream>
#include<fstream>
#include<map>
#pragma warning(disable:4996)
using namespace std;
map<string, string[3]> ftp;
ofstream out("csv.txt");

//定义Mac地址
struct mac_header
{
	unsigned char arp_tha[6];//目标mac地址
	unsigned char arp_sha[6];//发送者mac地址
	unsigned char type[2];
};

//IP报文头
typedef struct ip_header
{
	unsigned char	ver_ihl;	
	unsigned char	tos;			
	unsigned short tlen;			
	unsigned short identification;
	unsigned short flags_fo;		
	unsigned char	ttl;		
	unsigned char	proto;	
	unsigned short crc;		
	unsigned char	saddr[4];	
	unsigned char	daddr[4];	
	unsigned int	op_pad;			
}ip_header;



/* 回调函数，当收到每一个数据包时会被libpcap所调用 */
string get_request_m_ip_message(const unsigned char* pkt_data)
{
	mac_header *mh;
	ip_header *ih;
	string m_ip_message;
	string str;//empty string
	ostringstream sout;
	int length = sizeof(mac_header) + sizeof(ip_header);
	mh = (mac_header*)pkt_data;
	ih = (ip_header*)(pkt_data + sizeof(mac_header));
	for (int i = 0; i<5; i++)
		sout << hex << (int)(mh->arp_sha[i]) << "-";
	sout << (int)(mh->arp_sha[5]) << ",";
	for (int i = 0; i<3; i++)
		sout << dec << (int)(ih->saddr[i]) << ".";
	sout << (int)(ih->saddr[3]) << ",";
	for (int i = 0; i<5; i++)
		sout << hex << (int)(mh->arp_tha[i]) << "-";
	sout << (int)(mh->arp_tha[5]) << ",";
	for (int i = 0; i < 3; i++)
		sout << dec << (int)(ih->daddr[i]) << ".";
	sout << (int)(ih->daddr[3]);
	m_ip_message = sout.str();
	return m_ip_message;
}
string get_response_m_ip_message(const unsigned char* pkt_data)
{
	mac_header *mh;
	ip_header *ih;
	string m_ip_message;
	string str;//empty string
	ostringstream sout;
	int length = sizeof(mac_header) + sizeof(ip_header);
	mh = (mac_header*)pkt_data;
	ih = (ip_header*)(pkt_data + sizeof(mac_header));
	for (int i = 0; i<5; i++)
		sout << hex << (int)(mh->arp_tha[i]) << "-";
	sout << (int)(mh->arp_tha[5]) << ",";
	for (int i = 0; i < 3; i++)
		sout << dec << (int)(ih->daddr[i]) << ".";
	sout << (int)(ih->daddr[3]) << ",";
	for (int i = 0; i<5; i++)
		sout << hex << (int)(mh->arp_sha[i]) << "-";
	sout << (int)(mh->arp_sha[5]) << ",";
	for (int i = 0; i<3; i++)
		sout << dec << (int)(ih->saddr[i]) << ".";
	sout << (int)(ih->saddr[3]);
	m_ip_message = sout.str();
	return m_ip_message;
}
void print(const struct pcap_pkthdr *header, string m_ip_message)
{
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;
	/* 将时间戳转化为可识别的格式 */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H-%M-%S", ltime);
	/* 打印时间戳*/
	cout << timestr << ",";
	cout << m_ip_message << ",";
	for (int i = 0; i < 2; i++)
		cout << ftp[m_ip_message][i] << ",";
	cout << ftp[m_ip_message][2] << endl;
	out << timestr << ",";
	out << m_ip_message << ",";
	for (int i = 0; i < 2; i++)
		out << ftp[m_ip_message][i] << ",";
	out << ftp[m_ip_message][2] << endl;
	ftp.erase(m_ip_message);
}

void packet_handler(unsigned char *param, const struct pcap_pkthdr *header, const unsigned char *pkt_data)
{
	ip_header *ih;
	unsigned int ip_len;
	unsigned short sport, dport;

	int head = 54;//14位以太网头，20位ip头，20位tcp头  
				  //选择出command为USER和PASS的包，当然这里就简单的以首字母来代表了，反正其他的  
				  //command 没有以U和P开头的  
	string com;
	for (int i = 0; i < 4; i++)
		com += (char)pkt_data[head + i];
	if (com == "USER")
	{
		string m_ip_message = get_request_m_ip_message(pkt_data);
		string user;
		ostringstream sout;
		for (int i = head + 5; pkt_data[i] != 13; i++)
		{
			sout << pkt_data[i];
		}

		user = sout.str();
		ftp[m_ip_message][0] = user;
	}
	if (com == "PASS")
	{
		string m_ip_message = get_request_m_ip_message(pkt_data);
		string pass;
		ostringstream sout;
		for (int i = head + 5; pkt_data[i] != 13; i++)
		{
			sout << pkt_data[i];
		}
		pass = sout.str();
		ftp[m_ip_message][1] = pass;
	}
	if (com == "230 ")
	{
		string m_ip_message = get_response_m_ip_message(pkt_data);
		ftp[m_ip_message][2] = "SUCCEED";
		print(header, m_ip_message);
	}
	if (com == "530 ")
	{
		string m_ip_message = get_response_m_ip_message(pkt_data);
		ftp[m_ip_message][2] = "FAILD";
		print(header, m_ip_message);
	}
}





#define FROM_NIC
int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	unsigned int netmask;
	char packet_filter[] = "tcp";
	struct bpf_program fcode;
#ifdef FROM_NIC	
	/* 获取设备列表Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* 打印列表Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("输入网卡编号 (1-%d):", i);
	scanf("%d", &inum);

	/* 判断编号是否正确Check if the user specified a valid adapter */
	if (inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");

		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 跳到选好的适配器Jump to the selected adapter */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* 打开适配器Open the adapter */
	if ((adhandle = pcap_open_live(d->name,	// 设备名name of the device
		65536,			// 捕捉的数据包部分portion of the packet to capture. 
						// 保证能捕获到不同数据链路层上的每个数据包的全部内容65536 grants that the whole packet will be captured on all the MACs.
		1,				// 混杂promiscuous mode (nonzero means promiscuous)
		1000,			// 超过读取时间read timeout
		errbuf			// 错误缓冲池error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 检查数据链路层是否为以太网Check the link layer. We support only Ethernet for simplicity. */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* 获得网卡的源码Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;


	//编译过滤器compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//设置过滤器set the filter
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\n监听 %s...\n", d->description);

	/* 释放列表的内存空间At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	/* 开始捕获start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);
#else
	/* Open the capture file */
	if ((adhandle = pcap_open_offline(".\\dns.pcap",			// name of the device
		errbuf					// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the file.\n");
		return -1;
	}

	/* read and dispatch packets until EOF is reached */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	pcap_close(adhandle);
#endif
	system("pause");
	return 0;
}