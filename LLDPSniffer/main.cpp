#include <QCoreApplication>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <QTextStream>
#include <QString>

#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <netinet/ip.h>

using namespace std;

#define ETH_P_LLDP 0x88CC

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

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); //LLDP - 0x88CC
    if(sock<0)
    {
       perror("Socket error!");
       return 1;
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



