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

#include <lldpdu.h>

using namespace std;

#define ARRAY_SIZE(array) \
    (sizeof(array) / sizeof(*array))

QTextStream& qStdOut()
{
    static QTextStream ts( stdout );
    return ts;
}

void ProcessPacket(unsigned char* buffer, int size);
void PrintTLVs(unsigned char* buffer, int size);

int main(int argc, char *argv[])
{
	QCoreApplication a(argc, argv);

    struct sockaddr saddr;
    int saddr_size,data_size;
    uchar *buf = (uchar*) malloc(65536);

    struct sock_filter code[] = {
        { 0x28,  0,  0, 0x0000000c },
        { 0x15,  0,  1, 0x000088cc }, //88cc
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
    try
    {
        struct ethhdr *eth = (struct ethhdr*) buffer;
        qStdOut()<<"PACKET:"<<endl;
        qStdOut()<<"Ethertype="<<QString::number(eth->h_proto,16)<<"  Dest: "
                <<QString::number(eth->h_dest[0],16)<<"."
                <<QString::number(eth->h_dest[1],16)<<"."
                <<QString::number(eth->h_dest[2],16)<<"."
                <<QString::number(eth->h_dest[3],16)<<"."
                <<QString::number(eth->h_dest[4],16)<<"."
                <<QString::number(eth->h_dest[5],16)<<"  Src: "
                <<QString::number(eth->h_source[0],16)<<"."
                <<QString::number(eth->h_source[1],16)<<"."
                <<QString::number(eth->h_source[2],16)<<"."
                <<QString::number(eth->h_source[3],16)<<"."
                <<QString::number(eth->h_source[4],16)<<"."
                <<QString::number(eth->h_source[5],16)<<endl;
        PrintTLVs(buffer+sizeof(struct ethhdr), size-sizeof(struct ethhdr));
    }
    catch (QException ex)
    {
        qStdOut()<<"Error! "<<ex.what()<<endl;
    }
}

void PrintTLVs(unsigned char* buffer, int size)
{
    LLDPDU *lldpDU = new LLDPDU();
    QString PolygonOUI("012bb");
    bool isPolygon = false;

    lldpDU->Parse(buffer, size);

    for(int i=0;i<lldpDU->TLVcount(); i++)
    {
        TLV* tmp = lldpDU->GetTLVByIndex(i);
        switch(tmp->type)
        {
        case 0:
            qStdOut()<<"TLV Type: END OF LLDP ("<<tmp->type<<") Length: "<<tmp->length<<endl;
            qStdOut()<<"    END OF LLDP"<<endl<<"================================================="<<endl;
            break;
        case 1:
            qStdOut()<<"TLV Type: CHASSIS ID ("<<tmp->type<<") Length: "<<tmp->length<<endl;
            qStdOut()<<"    Subtype: "<<tmp->value[0]<<" ID: "<<flush;
            for(int j=1;j<tmp->length;j++)
                qStdOut()<<QString::number(tmp->value[j],16)<<"."<<flush;
            qStdOut()<<endl;
            break;
        case 2:
            qStdOut()<<"TLV Type: PORT ID ("<<tmp->type<<") Length: "<<tmp->length<<endl;
            qStdOut()<<"    Subtype: "<<tmp->value[0]<<" ID: "<<flush;
            for(int j=1;j<tmp->length;j++)
                qStdOut()<<QString(tmp->value[j])<<flush;
            qStdOut()<<endl;
            break;
        case 3:
            qStdOut()<<"TLV Type: TIME TO LIVE ("<<tmp->type<<") Length: "<<tmp->length<<endl;
            qStdOut()<<"    Value: "<<QString::number(tmp->value[0],2).append(QString::number(tmp->value[1],2)).toInt(0,2)<<endl;
            break;
        case 5:
            qStdOut()<<"TLV Type: SYSTEM NAME ("<<tmp->type<<") Length: "<<tmp->length<<endl;
            qStdOut()<<"    Value: "<<flush;
            for(int j=0;j<tmp->length;j++)
                qStdOut()<<QString(tmp->value[j])<<flush;
            qStdOut()<<endl;
            break;
        case 6:
            qStdOut()<<"TLV Type: SYSTEM DESCRIPTION ("<<tmp->type<<") Length: "<<tmp->length<<endl;
            qStdOut()<<"    Value: "<<flush;
            for(int j=0;j<tmp->length;j++)
                qStdOut()<<QString(tmp->value[j])<<flush;
            qStdOut()<<endl;
            break;
        default:
            qStdOut()<<"TLV Type: "<<tmp->type<<" Length: "<<tmp->length<<endl;
            qStdOut()<<"    Value: "<<flush;
            for(int j=1;j<tmp->length;j++)
                qStdOut()<<QString::number(tmp->value[j],16)<<" "<<flush;
            qStdOut()<<endl;
            if(tmp->type==127 && QString::compare(QString::number(tmp->value[0],16).append(QString::number(tmp->value[1],16)).append(QString::number(tmp->value[2],16)),PolygonOUI) == 0)
                isPolygon = true;
            break;
        }
    }
    if(isPolygon)
        qStdOut()<<"YES : "<<flush;
    else
        qStdOut()<<"NO : "<<flush;
    TLV* tmp = lldpDU->GetTLVByType(LLDP_TLV_SYS_DESCR);
    for(int i=0; i<tmp->length; i++)
    {
        qStdOut()<<QString(tmp->value[i])<<flush;
    }
    qStdOut()<<" : "<<flush;
    tmp = lldpDU->GetTLVByType(LLDP_TLV_MGMT_ADDR);
    qStdOut()<<tmp->value[2]<<"."
             <<tmp->value[3]<<"."
             <<tmp->value[4]<<"."
             <<tmp->value[5]<<endl;
    qStdOut()<<"================================================="<<endl<<endl;
}



