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

void LLDPDU::ParseTypeAndLength(unsigned char *Buffer,uint& type, uint& length)
{
    if(sizeof(Buffer)<2)
        throw new QException();
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
        throw new QException();
    while(size > 0)
    {
        uint tmpType;
        uint tmpLen;
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

TLV* LLDPDU::GetTLVByType(int type)
{
    for(int i=0;i<tlvs.count(); i++)
    {
        if(tlvs[i]->type==type)
            return tlvs[i];
    }
    return Q_NULLPTR;
}

TLV* LLDPDU::GetTLVByIndex(int index)
{
    if(index<0 || index >=tlvs.count())
        throw new QException();
    return tlvs[index];
}

int LLDPDU::TLVcount()
{
    return tlvs.count();
}

