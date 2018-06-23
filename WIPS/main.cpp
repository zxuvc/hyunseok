#include "aaa.h"

int Cipher(uint8_t cipher)
{
    switch (cipher)//Group Cipher Suite(broad,multicast) Type
                    {

                    case 0:
                        printf("Group Cipher Suite 사용\n");
                        cipher = 11; //Group Cipher Suite flsg:21
                        break;

                    case 1:
                        printf("WEP-40 사용\n");
                        cipher = 12; //WEP-40 flag:22
                        break;

                    case 2:
                        printf("TKIP 사용\n");
                        cipher = 13; //TKIP flag:23
                        break;

                    case 3:
                        printf("예약 사용\n");
                        cipher = 14; //예약 flag:24
                        break;

                    case 4:
                        printf("CCMP 사용\n");
                        cipher = 15; //CCMP flag:25
                        break;

                    case 5:
                        printf("WEP-104 사용\n");
                        cipher = 16; //WEP-104 flag:26
                        break;

                printf("Cipher fun:%d\n", cipher);
                    }
    return(cipher);
}

int Auth(uint8_t auth)
{
    switch (auth)
    {
    case 0:
        printf("예약 사용\n");
        auth = 17;
        break;

    case 1:
        printf("802.1X 인증\n");
        auth = 18;
        break;

    case 2:
        printf("PSK 인증\n");
        auth = 19;
        break;

    default:
        printf("...\n");
        break;
    }
    return(auth);

}


void misconfigureAP (const u_int8_t *data)
{
    struct RadiotapHeader *rH;
    struct RadiotapHeaderFlag *rF;
    struct ManagementFrame *mF;
    struct FrameCtrl *fC;
    //struct BeaconFrameBody *bF;
    struct OptionField *oF;
    struct Rsn *rsn;
    struct VendorSpecific *vS;
    struct SecurityMethod *sM;
    struct SecurityFlag *sF;
    struct AkmSuiteSelector *aS;

    rH = (struct RadiotapHeader *)data;
    rF = (struct RadiotapHeaderFlag *)data;
    mF = (struct ManagementFrame *)(data + rH->length);
    fC = (struct FrameCtrl *)(data + rH->length);
    //bF = (struct BeaconFrameBody *)data;
    oF = (struct OptionField *)(data + rH->length + sizeof(struct ManagementFrame) + sizeof(struct BeaconFrameBody));
    rsn = (struct Rsn *)data;
    vS = (struct VendorSpecific *)data;
    //sM = (struct SecurityMethod *)data;

    printf("--------------------------------\n");
    uint8_t apMac[6]; //BSS = AP MAC
    sM->wep = fC->protectedFrame;
    if(fC->protectedFrame == 1)
    {
    printf("WEP: %d*********************************************************************************",fC->protectedFrame);
    }
    int a, b, c, d;
    //printf("%d",sM->wep);
/*비콘 아닐때도 48, 221있는듯? 221은 확실히있음
그럼 비콘일때 ap mac 잡아버리면 ap mac 없는 패킷도 나옴 암호는 나오지만
그냥 비콘일때로 통일?*/
    apMac[0] = mF->addr3[0];
    apMac[1] = mF->addr3[1];
    apMac[2] = mF->addr3[2];
    apMac[3] = mF->addr3[3];
    apMac[4] = mF->addr3[4];
    apMac[5] = mF->addr3[5];
    printf("AP MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",apMac[0],apMac[1],apMac[2],apMac[3],apMac[4],apMac[5]);

            if(fC->subType == 8 && fC->type == 0)//BeaconFrame
            {
                apMac[0] = mF->addr3[0];
                apMac[1] = mF->addr3[1];
                apMac[2] = mF->addr3[2];
                apMac[3] = mF->addr3[3];
                apMac[4] = mF->addr3[4];
                apMac[5] = mF->addr3[5];

                printf("AP MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",apMac[0],apMac[1],apMac[2],apMac[3],apMac[4],apMac[5]);

                while((oF->elementId | oF->length )!= 0)//OptionFrame
                {
                    if(oF->elementId == 48 )//RSN ID:48
                    {
                        rsn = (Rsn *)(uint8_t*)oF;

                        sM->gCSS[0] = rsn->gCSS[0];//00-0f-ac
                        sM->gCSS[1] = rsn->gCSS[1];
                        sM->gCSS[2] = rsn->gCSS[2];
                        sM->gCSS[3] = rsn->gCSS[3];//Type
                        printf("Group OUI : %02x-%02x-%02x\n",sM->gCSS[0], sM->gCSS[1], sM->gCSS[2]);//Group OUI
                        printf("sM->gCSS[3]: %d\n",sM->gCSS[3]);
                        printf("sM->gCSS[3]: %d\n",rsn->gCSS[3]);
                        sM->pCSS[0] = rsn->pCSS[0];//00-0f-ac
                        sM->pCSS[1] = rsn->pCSS[1];
                        sM->pCSS[2] = rsn->pCSS[2];
                        sM->pCSS[3] = rsn->pCSS[3];//Type
                        printf("count:%d\n",rsn->pCSC);


                        if(rsn->pCSC != 0x01)
                        {
                            rsn = (Rsn *)(uint8_t*)oF+sizeof(rsn->pCSC)*4;
                            printf("count value: %d\n",sizeof(rsn->pCSC)*4);
                            printf("AKM: %d\n",rsn->aSS[2]);
                            printf("AKM: %d\n",rsn->aSS[3]);
                            //rsn = (Rsn *)((uint8_t*)rsn+10+(rsn->pCSC*4))+2+(rsn->aSC*4);
                            //printf("count: %x %x %x %x",aS->aSS[0],aS->aSS[1],aS->aSS[2],aS->aSS[3]);

                            //sizeof(rsn->pCSC * 4
                        }
                        printf("Pairwise OUI : %02x-%02x-%02x\n",sM->pCSS[0], sM->pCSS[1], sM->pCSS[2]);//Pairwise OUI
                        //printf("sM->pCSS[3]: %d\n",sM->pCSS[3]);
                        printf("sM->pCSS[3]: %d\n",sM->pCSS[3]);
                        printf("sM->pCSS[3]: %d\n",rsn->pCSS[3]);
                        sM->aSS[0] = rsn->aSS[0];//00-0f-ac
                        sM->aSS[1] = rsn->aSS[1];
                        sM->aSS[2] = rsn->aSS[2];
                        sM->aSS[3] = rsn->aSS[3];//Type
                        printf("sM->aSS[3]: %d\n",sM->aSS[3]);
                        printf("sM->aSS[3]: %d\n",rsn->aSS[3]);
                     }

                    else if(oF->elementId == 221)//Vendor specific ID:221
                    {
                        vS = (VendorSpecific *)(uint8_t*)oF;
                        printf("OUI : %02x-%02x-%02x\n",vS->oUI[0], vS->oUI[1], vS->oUI[2]);//OUI
                        printf("vST: %02x\n", vS->vST);

                        if(vS->oUI[0] == 0x00 && vS->oUI[1] == 0x50 && vS->oUI[2] == 0xf2)//OUI 00-50-f2
                        {
                            if(vS->vST == 0x01)//1: WPA Information Type-> WPA-1 & 2: WMM/WME -> CCMP 일때 2임...?
                            {
                            printf("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n");

                            sM->oUI[0] = vS->oUI[0];//00-50-f2
                            sM->oUI[1] = vS->oUI[1];
                            sM->oUI[2] = vS->oUI[2];
                            sM->mCSS[3] = vS->mCSS[3]; //Type =1 WPA Information
                            printf("sM->mCSS[3]: %d\n",sM->mCSS[3]);
                            printf("sM->mCSS[3]: %d\n",vS->mCSS[3]);
                            sM->uCSS[3] = vS->uCSS[3]; //type
                            printf("sM->uCSS[3]: %d\n",sM->uCSS[3]);
                            printf("sM->uCSS[3]: %d\n",vS->uCSS[3]);
                            //sM->vST = vS->vST;//type
                            sM->aKMS[3] = vS->aSS[3]; //type
                            printf("sM->aKMS[3]: %d\n",sM->aKMS[3]);
                            printf("sM->aKM6jS[3]: %d\n",vS->aSS[3]);

                            /*
                            printf("OUI : %02x-%02x-%02x\n",vS->oUI[0], vS->oUI[1], vS->oUI[2]);//OUI
                            printf("vST: %02x\n", vS->vST);
                            printf("wpaVersion: %04x\n", vS->wpaVersion);
                            printf("Group: %02x-%02x-%02x\nTYPE: %d\n", vS->mCSS[0], vS->mCSS[1], vS->mCSS[2], vS->mCSS[3]);//OUI
                            printf("Count: %04x%d\n", vS->uCSC);//OUI
                            printf("Pairwise: %02x-%02x-%02x\nTYPE: %d\n",vS->uCSS[0], vS->uCSS[1], vS->uCSS[2], vS->uCSS[3]); //4x가변길이..!! 아직 고정으로 사용
                            printf("Count: %04x%d\n", vS->aSC);//OUI
                            printf("AKM: %02x-%02x-%02x\nTYPE: %d\n",vS->aSS[0], vS->aSS[1], vS->aSS[2], vS->aSS[3]); //4x가변길이..!! 아직 고정으로 사용
                            */
                            }

                            if(vS->vST == 0x02)//1: WPA Information Type-> WPA-1 & 2: WMM/WME -> CCMP 일때 2임...?
                            {
                            printf("cccccccccccccccccccccccccccccccccc\n");

                            sM->oUI[0] = vS->oUI[0];//00-50-f2
                            sM->oUI[1] = vS->oUI[1];
                            sM->oUI[2] = vS->oUI[2];
                            }
                        }
                    }
                    oF = (OptionField *)((uint8_t*)oF+sizeof(OptionField)+oF->length);
                }
            }

            //*********************Flag set*******************
            if(sM->oUI[0] == 0x00 && sM->oUI[1] == 0x50 && sM->oUI[2] == 0xf2 &&
               sM->gCSS[0] == 0x00 && sM->gCSS[1] == 0x0f && sM->gCSS[2] == 0xac)//OUI 00-50-f2 && OUI 00-0f-ac -> WPA2
            {
                a = 20; //WPA-2 flsg:20
                sF->enc = a;
                printf("WPA-2: %d\n", sF->enc);
                //sF->enc = 20; //WPA-2 flsg:20
                printf("aaaaaaaaaaaaaaaaaaaaaaaaa\n");
                printf("Group Cipher Suite Selector: %d\n",sM->gCSS[3]);//Group Cipher Suite Selector(multicast) Type
                sF->groupCipher = Cipher(sM->gCSS[3]);
                printf("Flag: %d\n", sF->groupCipher);

                printf("Pairwise Cipher Suite Selector: %d\n",sM->pCSS[3]);//Pairwise Cipher Suite Selector(unicast) Type
                sF->pairwiseCipher = Cipher(sM->pCSS[3]);
                printf("Flag: %d\n", sF->pairwiseCipher);

                printf("AKM Suite Selector: %d\n",sM->aSS[3]);//Authentication and Key Management Type
                sF->auth = Auth(sM->aSS[3]);
                printf("Flag: %d\n", sF->auth);
            }

            else if(sM->oUI[0] == 0x00 && sM->oUI[1] == 0x50 && sM->oUI[2] == 0xf2)//OUI 00-50-f2 -> WPA-1
            {
               // printf("WPA-1\n");
                sF->enc = 10; //WPA-1 flsg:10
                printf("WPA-1: %d\n", sF->enc);

                printf("Group Cipher Suite Selector: %d\n",sM->mCSS[3]);//Group Cipher Suite Selector(multicast) Type
                sF->groupCipher = Cipher(sM->mCSS[3]);
                printf("Flag: %d\n", sF->groupCipher);

                printf("Pairwise Cipher Suite Selector: %d\n",sM->uCSS[3]);//Pairwise Cipher Suite Selector(unicast) Type
                sF->pairwiseCipher = Cipher(sM->uCSS[3]);
                printf("Flag: %d\n", sF->pairwiseCipher);

                printf("AKM Suite Selector: %d\n",sM->aKMS[3]);//Authentication and Key Management Type
                sF->auth = Auth(sM->aKMS[3]);
                printf("Flag: %d\n", sF->auth);
            }

            if(sM->wep == 1)//WEP
            {
                sF->enc = 1; //WEP flsg:1
                printf("WEP: %d\n", sF->enc);
            }

            if(sM->wep == 0 && rsn->elementId != 48 && vS->elementId != 221)//OPEN
            {
                sF->enc = 0; //OPEN flsg:0
                printf("OPEN: %d\n", sF->enc);
            }

            /*
            printf("\n");
            printf("WEP: %d\n",sM->wep);
            printf("Group Cipher Suite Selector OUI : %02x-%02x-%02x\nTYPE: %d\n", sM->gCSS[0], sM->gCSS[1], sM->gCSS[2], sM->gCSS[3]);//OUI
            printf("Pairwise Cipher Suite Selector OUI : %02x-%02x-%02x\nTYPE: %d\n",sM->pCSS[0], sM->pCSS[1], sM->pCSS[2], sM->pCSS[3]); //4x가변길이..!! 아직 고정으로 사용
            printf("AKM Suite Selector OUI : %02x-%02x-%02x\nTYPE: %d\n",sM->aSS[0], sM->aSS[1], sM->aSS[2], sM->aSS[3]); //4x가변길이..!! 아직 고정으로 사용
            printf("OUI : %02x-%02x-%02x\n",sM->oUI[0], sM->oUI[1], sM->oUI[2]);//OUI
            printf("Vendor Specific TYPE: %d\n",sM->vST);
            */
           printf("--------------------------------\n");

           //*********************Initialization*******************
           memset(rH,0,sizeof(struct RadiotapHeader));
           memset(rF,0,sizeof(struct RadiotapHeaderFlag));
           memset(mF,0,sizeof(struct ManagementFrame));
           memset(fC,0,sizeof(struct FrameCtrl));
           memset(oF,0,sizeof(struct OptionField));
           memset(rsn,0,sizeof(struct Rsn));
           memset(vS,0,sizeof(struct VendorSpecific));
           memset(sM,0,sizeof(struct SecurityMethod));
           memset(sF,0,sizeof(struct SecurityFlag));



           //printf("%d",sF->auth);
           /*sM->wep =0;
           sM->oUI[0] = 0;
           sM->oUI[1] = 0;
           sM->oUI[2] = 0;
           sM->gCSS[0] = 0;
           sM->gCSS[1] = 0;
           sM->gCSS[2] = 0;
           sM->gCSS[3] = 0; //type
           sM->pCSS[0] = 0;
           sM->pCSS[1] = 0;
           sM->pCSS[2] = 0;
           sM->pCSS[3] = 0; //type
           sM->aKMS[0] = 0;
           sM->aKMS[1] = 0;
           sM->aKMS[2] = 0;
           sM->aKMS[3] = 0;
           sM->aSS[0] = 0;
           sM->aSS[1] = 0;
           sM->aSS[2] = 0;
           sM->aSS[3] = 0;
           sF->enc =0;
           sF->groupCipher =0;
           sF->pairwiseCipher =0;
           sF->auth =0;*/
}




int main(int argc, char *argv[]){
    pcap_t *pcd;         /* Session handle */
    char *dev="wlan0";         /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];   /* Error string */

    int res=0;
    pcap_pkthdr *Header;

    const u_char *data;

//    dev = pcap_lookupdev(errbuf);

    /* Open the session in promiscuous mode */
    pcd = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
//    if (pcd == NULL)
//    {
//        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
//        return(2);
//    }

    while((res=pcap_next_ex(pcd,&Header,&data))>0)
   {
     // int len=Header->len;
      //int counter=0;

      misconfigureAP (data);
      /*while(len--)
      {
         if(counter++%16==0)printf("\n");
         printf("%02x ",*Data++);
      }*/
      printf("\n");

   }
pcap_close(pcd);
    return(0);
 }
