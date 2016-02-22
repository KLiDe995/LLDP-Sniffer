#include <QCoreApplication>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <QTextStream>
#include <QString>

#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <netinet/ip.h>
#include <linux/filter.h>

using namespace std;

#define ARRAY_SIZE(array) \
    (sizeof(array) / sizeof(*array))

QTextStream& qStdOut()
{
    static QTextStream ts( stdout );
    return ts;
}

void ProcessPacket(unsigned char* buffer, int size);

int main(int argc, char *argv[])
{
	QCoreApplication a(argc, argv);

    struct sockaddr saddr;
    int saddr_size,data_size;
    uchar *buf = (uchar*) malloc(65536);

    struct sock_filter code[] = {
        { 0x28,  0,  0, 0x0000000c },
        { 0x15,  0,  1, 0x000088cc },
        { 0x06,  0,  0, 0xffffffff },
        { 0x06,  0,  0, 0000000000 },
    };

    struct sock_fprog bpf = {
        .len = ARRAY_SIZE(code),
        .filter = code
    };

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); //LLDP - 0x88CC
    if(sock<0)
    {
       perror("Socket error!");
       return 1;
    }
    int ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
    if (ret < 0)
    {
        perror("Socket options error!");
        return 2;
    }
    while(1)
    {
        saddr_size = sizeof saddr;
        data_size = recvfrom(sock , buf , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
        if(data_size <0 )
        {
            qStdOut()<<"Recvfrom error , failed to get packets\n" << flush;
            return 1;
        }
        ProcessPacket(buf , data_size);
    }
    return a.exec();
}

void ProcessPacket(unsigned char* buffer, int size)
{
    //Нада перевесети в 16рич
    struct ethhdr *eth = (struct ethhdr*) buffer;
    //if(eth->h_dest[1]==128)
    //{
        qStdOut() << QString::number(eth->h_dest[0])+QString::number(eth->h_dest[1])+QString::number(eth->h_dest[2])+QString::number(eth->h_dest[3])+QString::number(eth->h_dest[4])+QString::number(eth->h_dest[5])<<endl;
    //}
    //else
    //    qStdOut()<<"Other packet"<<endl;
}



