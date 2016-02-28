#include "lldpdu.h"

LLDPDU::LLDPDU() {}


LLDPDU::~LLDPDU()
{
    freeMemory();
}

void LLDPDU::freeMemory()
{
    for(int i=0; i<tlvs.count(); i++)
    {
        delete tlvs[i]->value;
    }
    tlvs.clear();
}

void LLDPDU::ParseTypeAndLength(unsigned char *Buffer,int& type, int& length)
{
    if(sizeof(Buffer)<2)
        return;
    QString typestr = QString::number(Buffer[0],2);
    QString lenstr(typestr[typestr.count()-1]);
    typestr.chop(1);
    type = QString::number(typestr.toInt(0,2),10).toInt();
    lenstr.append(QString::number(Buffer[1],2));
    length=QString::number(lenstr.toInt(0,2),10).toInt();
}

void LLDPDU::Parse(unsigned char* Buffer, int size)
{
    if(tlvs.count() != 0)
    {
        freeMemory();
    }
    if(size == 0 || sizeof(Buffer) == 0)
        return;
    while(size > 0)
    {
        int tmpType;
        int tmpLen;
        ParseTypeAndLength(Buffer,tmpType,tmpLen);
        unsigned char *tmpValue = new unsigned char[tmpLen];
        for(int i=0;i<tmpLen; i++)
        {
            tmpValue[i]=Buffer[i+2];
        }
        tlvs.append(new TLV {tmpType,tmpLen,tmpValue});
        Buffer += 2+tmpLen;
        size -= 2+tmpLen;
    }

}

TLV LLDPDU::GetTLV(int type)
{

}

