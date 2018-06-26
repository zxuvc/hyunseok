#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> /* if this gives you an error try pcap/pcap.h */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <iostream>
#include <string.h>

//ENC
#define WEP 1
#define WPA1 10
#define WPA2 20
//Cipher
#define OPEN 0
#define GROUP_CIPHER_SUITE 11
#define WEP40 12
#define TKIP 13
#define C_RESERVATON 14//예약사용
#define CCMP 15
#define WEP104 16
//Auth
#define A_RESERVATON 17//예약사용
#define A_8021X 18//802.1X
#define PSK 19


using std::cout;
using std::endl;
#pragma pack(push, 1)

struct SecurityFlag
{
   int8_t enc;//Encrypt
   int8_t groupCipher; //GroupCypher
   int8_t pairwiseCipher; //PairwiseCipher
   int8_t auth; //Authentication
};

struct SecurityMethod
{
    uint8_t wep:1;//WEP
    uint8_t gCSS[4]; //Group Cipher Suite Selector gcss[3] = type; ID=48
    uint8_t pCSS[4]; //Pairwise Cipher Suite Selector 4x가변길이.. pcss[3] = type ID=48
    uint8_t aSS[4]; //AKM Suite Selector 4x가변길이.. akmss[3] = type ID=48
    uint8_t oUI[3]; //Organizationally unique identifier ID=221
    uint8_t mCSS[4]; //Group Cipher Suite Selector gcss[3] = type; ID=48 //필요없을듯?
    uint8_t uCSS[4]; //unicast Cipher Suite Select OUI 4x가변길이 uCSS[3] = type ID=221
    uint8_t aKMS[4]; //AKM Suite Selector1 4x가변길이.. aSS[3] = type
    uint8_t vST; //Vendor Specific (OUI) Type 필요없음??
};

struct FrameCtrl //Management Frame Control
{
    uint8_t   protocolVer    : 2;
    uint8_t   type           : 2;
    uint8_t   subType        : 4;
    uint8_t   toDs           : 1;
    uint8_t   fromDs         : 1;
    uint8_t   moreFlag       : 1;
    uint8_t   retry          : 1;
    uint8_t   powerMgmt      : 1;
    uint8_t   moreData       : 1;
    uint8_t   protectedFrame : 1;
    uint8_t   order          : 1;
};

struct ManagementFrame
{
    struct FrameCtrl  frameCtrl;  //2 bytes
           uint16_t   duration;   //2 bytes
           uint8_t    addr1[6];   //6 bytes
           uint8_t    addr2[6];   //6 bytes
           uint8_t    addr3[6];   //6 bytes BSS = AP MAC
           uint16_t   seq_ctrl;   //2 bytes
};

struct RadiotapHeaderFlag
{
    uint8_t cfp:1;
    uint8_t preamble:1;
    uint8_t wep:1;
    uint8_t fragmentation:1;
    uint8_t fcs:1;
    uint8_t data_pad:1;
    uint8_t bad_fcs:1;
    uint8_t short_gi:1;
};

struct RadiotapHeader
{
           uint8_t    version;
           uint8_t    pad;
           uint16_t   length;
           uint64_t   presentFlags;
    struct RadiotapHeaderFlag    flags;
           uint8_t    dataRate;
           uint16_t   channelFrequency;
           uint16_t   channelFlags;
           uint8_t    ssiSignal_1;
           uint8_t    wtfTrash;   //strange stuff
           uint16_t   rxFlags;
           uint8_t    ssiSignal_2;
           uint8_t    antenna;
};

struct Rsn
{
    uint8_t elementId; //Element_ID
    uint8_t length; //Length
    uint16_t version;
    uint8_t gCSS[4]; //Group Cipher Suite Selector gcss[3] = type
    uint16_t pCSC; //Pairwise Cipher Suite Count
    uint8_t pCSS[4]; //Pairwise Cipher Suite Selector 4x가변길이.. pcss[3] = type
    uint16_t aSC; //AKM Suite Count
    uint8_t aSS[4]; //AKM Suite Selector 4x가변길이.. aSS[3] = type
    uint16_t rsnC; //RSN Capabilities
    uint16_t pmkC; //PMK Count
    uint16_t pmkL; //PMK List
};

struct VendorSpecific
{
    uint8_t elementId; //Element_ID
    uint8_t length; //Length
    uint8_t oUI[3]; //Organizationally unique identifier
    uint8_t vST; //Vendor Specific (OUI) Type
    uint16_t wpaVersion; //WPA
    uint8_t mCSS[4]; //Multicast Cipher Suite Select OUI mCSS[3] = type
    uint16_t uCSC; //unicast Cipher Suite Count
    uint8_t uCSS[4]; //unicast Cipher Suite Select OUI 4x가변길이 uCSS[3] = type
    uint16_t aSC; //AKM Suite Count
    uint8_t aSS[4]; //AKM Suite Selector 4x가변길이.. aSS[3] = type
};

struct OptionField
{
    uint8_t elementId; //Element_ID
    uint8_t length; //Length
    //Rsn rsn;
    //Vendor_specific vendor_specific;
    //Variable Length Optionflied 가변길이의 옵션필드
};

struct BeaconFrameBody
{
    uint64_t  timestamp;
    uint16_t  beaconInterval;
    uint16_t  capacityInformation;
};

struct AkmSuiteSelector//??
{
    //uint16_t aSC; //AKM Suite Count
    uint8_t aSS[4]; //AKM Suite Selector 4x가변길이.. aSS[3] = type
};

#pragma pack(pop)
void misconfigureAP (const uint8_t *);
int Cipher(uint8_t *);
int Auth(uint8_t *);

