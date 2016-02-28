#ifndef LLDPDU_H
#define LLDPDU_H

#include <QVector>
#include <QString>

#define TLV_TLEN 7
#define TLV_LLEN 9

struct TLV {
    unsigned char type;
    unsigned char length;
    unsigned char *value;
};

class LLDPDU
{
private:
    QVector<TLV*> tlvs;
    void ParseTypeAndLength(unsigned char Buffer[2],int& type, int& length);
public:
    LLDPDU();
    ~LLDPDU();
    void freeMemory();
    void Parse(unsigned char* Buffer, int size);
    TLV GetTLV(int type);
};

#endif // LLDPDU_H
