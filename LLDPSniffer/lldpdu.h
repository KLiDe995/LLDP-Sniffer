#ifndef LLDPDU_H
#define LLDPDU_H

#include <QVector>
#include <QString>
#include <QException>

/*TLV types*/
#define 	LLDP_TLV_END   0    //end of TLV - Length must be zero
#define 	LLDP_TLV_CHID  1 	//Chassis ID
#define 	LLDP_TLV_PID   2    //Port ID
#define 	LLDP_TLV_TTL   3    //Time to Live (seconds)
#define 	LLDP_TLV_PORT_DESCR   4 //Port description
#define 	LLDP_TLV_SYS_NAME     5 //System name
#define 	LLDP_TLV_SYS_DESCR    6 //System description
#define 	LLDP_TLV_SYS_CAPS     7 //System capabilities
#define 	LLDP_TLV_MGMT_ADDR    8 //Managment address
/*END OF TLV TYPES*/

//LLDP TLV structure
struct TLV {
    unsigned int type;
    unsigned int length;
    unsigned char *value;
};

//LLDP Data Unit Class
class LLDPDU
{
private:
    QVector<TLV*> tlvs;
    void ParseTypeAndLength(unsigned char Buffer[2], uint& type, uint& length);
public:
    LLDPDU();
    ~LLDPDU();
    void freeMemory();
    void Parse(unsigned char* Buffer, int size);
    TLV* GetTLVByType(int type);
    TLV* GetTLVByIndex(int index);
    int TLVcount();
};

#endif // LLDPDU_H
