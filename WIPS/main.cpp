#include "aaa.h"


int Cipher(uint8_t cipher)
{
    switch (cipher)//Group Cipher Suite(broad,multicast) Type
                    {

                    case 0:
                        printf("Group Cipher Suite 사용\n");
                        cipher = GROUP_CIPHER_SUITE; //Group Cipher Suite flsg:21
                        break;

                    case 1:
                        printf("WEP-40 사용\n");
                        cipher = WEP40; //WEP-40 flag:12
                        break;

                    case 2:
                        printf("TKIP 사용\n");
                        cipher = TKIP; //TKIP flag:13
                        break;

                    case 3:
                        printf("예약 사용\n");
                        cipher = C_RESERVATON; //예약 flag:14
                        break;

                    case 4:
                        printf("CCMP 사용\n");
                        cipher = CCMP; //CCMP flag:15
                        break;

                    case 5:
                        printf("WEP-104 사용\n");
                        cipher = WEP104; //WEP-104 flag:16
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
        auth = A_RESERVATON;//flag:17
        break;

    case 1:
        printf("802.1X 인증\n");
        auth = A_8021X;//flag:18
        break;

    case 2:
        printf("PSK 인증\n");
        auth = PSK;//flag:19
        break;

    default:
        printf("...\n");
        break;
    }
    return(auth);

}


void misconfigureAP (const uint8_t *data)
{
    struct RadiotapHeader *rH;
    struct RadiotapHeaderFlag *rF;
    struct ManagementFrame *mF;
    struct FrameCtrl *fC;
    struct OptionField *oF;
    struct Rsn *rsn;
    struct VendorSpecific *vS;
    struct SecurityMethod *sM;
    struct SecurityFlag *sF;
    struct AkmSuiteSelector *aS;
    struct PairwiseCipherSuiteSelector *pS;


    rH = (struct RadiotapHeader *)data;
    rF = (struct RadiotapHeaderFlag *)data;
    mF = (struct ManagementFrame *)(data + rH->length);
    fC = (struct FrameCtrl *)(data + rH->length);
    oF = (struct OptionField *)(data + rH->length + sizeof(struct ManagementFrame) + sizeof(struct BeaconFrameBody));
    rsn = (struct Rsn *)data;
    vS = (struct VendorSpecific *)data;


    printf("--------------------------------\n");

    uint8_t apMac[6]; //BSS = AP MAC
    sM->wep = fC->protectedFrame;
    int16_t tpcss;

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


                while((oF->elementId | oF->length )!= 0)//OptionFrame
                {
                    if(oF->elementId == 48)//RSN ID:48
                    {
                        rsn = (Rsn *)(uint8_t*)oF;

                        sM->gCSS[0] = rsn->gCSS[0];//00-0f-ac
                        sM->gCSS[1] = rsn->gCSS[1];
                        sM->gCSS[2] = rsn->gCSS[2];
                        sM->gCSS[3] = rsn->gCSS[3];//Type


                        {


                            tpcss = rsn->pCSC; //이거지우면 안돌아감 왜??/

                            switch (rsn->pCSC)
                           {
                           case 1:
                               printf("PairwiseCipherSuiteSelector OUI : %02x-%02x-%02x\n", rsn->pCSS.pOUI[0], rsn->pCSS.pOUI[1], rsn->pCSS.pOUI[2]);//PairwiseCipherSuiteSelector OUI
                               printf("PairwiseCipherSuiteSelector TYPE : %02x\n", rsn->pCSS.pOUI[3]);//PairwiseCipherSuiteSelector OUISC);
                               sM->pCSS[3] = rsn->pCSS.pOUI[3];
                               printf("AKM OUI : %02x-%02x-%02x\n", rsn->aSS[0], rsn->aSS[1], rsn->aSS[2]);//AKM OUI ID=48 -> WPA-2
                               printf("AKM TYPE : %02x\n",rsn->aSS[3]);//AKM TYPE ID=48 -> WPA-2
                               sM->aSS[3] = rsn->aSS[3];
                               sM->aSC[0] = rsn->aSC[0];
                               sM->aSC[1] = rsn->aSC[1];
                               break;

                           case 2:
                               printf("PairwiseCipherSuiteSelector OUI : %02x-%02x-%02x\n", rsn->pCSS.pOUI[4], rsn->pCSS.pOUI[5], rsn->pCSS.pOUI[6]);//PairwiseCipherSuiteSelector OUI
                               printf("PairwiseCipherSuiteSelector TYPE : %02x\n", rsn->pCSS.pOUI[7]);//PairwiseCipherSuiteSelector OUISC);
                               sM->pCSS[3] = rsn->pCSS.pOUI[7];
                               printf("AKM OUI : %02x-%02x-%02x\n", rsn->aSS[4], rsn->aSS[5], rsn->aSS[6]);//AKM OUI ID=48 -> WPA-2
                               printf("AKM TYPE : %02x\n",rsn->aSS[7]);//AKM TYPE ID=48 -> WPA-2
                               sM->aSS[3] = rsn->aSS[7];
                               sM->aSC[0] = rsn->aSC[2];
                               sM->aSC[1] = rsn->aSC[3];
                               break;

                           case 3:
                               printf("PairwiseCipherSuiteSelector OUI : %02x-%02x-%02x\n", rsn->pCSS.pOUI[8], rsn->pCSS.pOUI[9], rsn->pCSS.pOUI[10]);//PairwiseCipherSuiteSelector OUI
                               printf("PairwiseCipherSuiteSelector TYPE : %02x\n", rsn->pCSS.pOUI[11]);//PairwiseCipherSuiteSelector OUISC);
                               sM->pCSS[3] = rsn->pCSS.pOUI[11];
                               printf("AKM OUI : %02x-%02x-%02x\n", rsn->aSS[8], rsn->aSS[9], rsn->aSS[10]);//AKM OUI ID=48 -> WPA-2
                               printf("AKM TYPE : %02x\n",rsn->aSS[11]);//AKM TYPE ID=48 -> WPA-2
                               sM->aSS[3] = rsn->aSS[7];
                               sM->aSC[0] = rsn->aSC[4];
                               sM->aSC[1] = rsn->aSC[5];
                               break;

                           case 4:
                               printf("PairwiseCipherSuiteSelector OUI : %02x-%02x-%02x\n", rsn->pCSS.pOUI[12], rsn->pCSS.pOUI[13], rsn->pCSS.pOUI[14]);//PairwiseCipherSuiteSelector OUI
                               printf("PairwiseCipherSuiteSelector TYPE : %02x\n", rsn->pCSS.pOUI[15]);//PairwiseCipherSuiteSelector OUISC);
                               sM->pCSS[3] = rsn->pCSS.pOUI[15];
                               printf("AKM OUI : %02x-%02x-%02x\n", rsn->aSS[12], rsn->aSS[13], rsn->aSS[14]);//AKM OUI ID=48 -> WPA-2
                               printf("AKM TYPE : %02x\n",rsn->aSS[15]);//AKM TYPE ID=48 -> WPA-2
                               sM->aSS[3] = rsn->aSS[15];
                               sM->aSC[0] = rsn->aSC[6];
                               sM->aSC[1] = rsn->aSC[7];
                               break;

                           default:
                               printf("???????????????????????????????????????????????????????????????????????/\n");
                               break;
                           }


                         if(sM->aSC[0] != 0x01)
                         {
                            switch (sM->aSC[0])
                          {
                           /*case 1:
                               printf("1111111111111111111111111111111111111111\n");
                               printf("AKM OUI : %02x-%02x-%02x\n", rsn->aSS[0], rsn->aSS[1], rsn->aSS[2]);//AKM OUI ID=48 -> WPA-2
                               printf("AKM TYPEdd : %02x\n",rsn->aSS[3]);//AKM TYPE ID=48 -> WPA-2
                             //  TYPE[2] = rsn->aSS[3];
                               break;*/

                          case 2:
                              printf("AKM OUI : %02x-%02x-%02x\n", rsn->aSS[4], rsn->aSS[5], rsn->aSS[6]);//AKM OUI ID=48 -> WPA-2
                              printf("AKM TYPE : %02x\n",rsn->aSS[7]);//AKM TYPE ID=48 -> WPA-2
                              sM->aSS[3] = rsn->aSS[7];
                              break;

                          case 3:
                              printf("AKM OUI : %02x-%02x-%02x\n", rsn->aSS[8], rsn->aSS[9], rsn->aSS[10]);//AKM OUI ID=48 -> WPA-2
                              printf("AKM TYPE : %02x\n",rsn->aSS[11]);//AKM TYPE ID=48 -> WPA-2
                              sM->aSS[3] = rsn->aSS[11];
                              break;

                          case 4:
                              printf("AKM OUI : %02x-%02x-%02x\n", rsn->aSS[12], rsn->aSS[13], rsn->aSS[14]);//AKM OUI ID=48 -> WPA-2
                              printf("AKM TYPE : %02x\n",rsn->aSS[15]);//AKM TYPE ID=48 -> WPA-2
                              sM->aSS[3] = rsn->aSS[15];
                              break;

                          default:
                              //printf("???????????????????????????????????????????????????????????????????????/\n");
                              break;
                          }
                         }
                        }

                        sM->aSS[0] = rsn->aSS[0];//00-0f-ac
                        sM->aSS[1] = rsn->aSS[1];
                        sM->aSS[2] = rsn->aSS[2];

                     }

                    else if(oF->elementId == 221)//Vendor specific ID:221
                    {
                        vS = (VendorSpecific *)(uint8_t*)oF;


                        if(vS->oUI[0] == 0x00 && vS->oUI[1] == 0x50 && vS->oUI[2] == 0xf2)//OUI 00-50-f2
                        {
                            if(vS->vST == 0x01)//1: WPA Information Type-> WPA-1 & 2: WMM/WME -> CCMP 일때 2임...?
                            {

                            sM->oUI[0] = vS->oUI[0];//00-50-f2
                            sM->oUI[1] = vS->oUI[1];
                            sM->oUI[2] = vS->oUI[2];
                            sM->mCSS[3] = vS->mCSS[3]; //Type =1 WPA Information

                            switch (vS->uCSC)
                            {
                            case 1:
                                printf("Unicast Cipher Suite OUI: %02x-%02x-%02x\n", vS->uCSS[0], vS->uCSS[1], vS->uCSS[2]);//Unicast Cipher Suite OUI ID:221
                                printf("Unicast Cipher Suite TYPE: %02x\n", vS->uCSS[3]);//Unicast Cipher Suite TYPE ID:221
                                sM->uCSS[3] = vS->uCSS[3];
                                printf("AKM OUI : %02x-%02x-%02x\n", vS->aSS[0], vS->aSS[1], vS->aSS[2]);//AKM OUI ID=221 -> WPA-1
                                printf("AKM TYPE : %02x\n",vS->aSS[3]);//AKM TYPE ID=221 -> WPA-1
                                sM->aKMS[3] = vS->aSS[3];
                                sM->aKMC[0] = vS->aSC[0];
                                sM->aKMC[1] = vS->aSC[1];
                                break;

                            case 2:
                                printf("Unicast Cipher Suite OUI: %02x-%02x-%02x\n", vS->uCSS[4], vS->uCSS[5], vS->uCSS[6]);//Unicast Cipher Suite OUI ID:221
                                printf("Unicast Cipher Suite TYPE: %02x\n", vS->uCSS[7]);//Unicast Cipher Suite TYPE ID:221
                                sM->uCSS[3] = vS->uCSS[7];
                                printf("AKM OUI : %02x-%02x-%02x\n", vS->aSS[4], vS->aSS[5], vS->aSS[6]);//AKM OUI ID=221 -> WPA-1
                                printf("AKM TYPE : %02x\n",vS->aSS[7]);//AKM TYPE ID=221 -> WPA-1
                                sM->aKMS[3] = vS->aSS[7];
                                sM->aKMC[0] = vS->aSC[2];
                                sM->aKMC[1] = vS->aSC[3];
                                break;

                            case 3:
                                printf("Unicast Cipher Suite OUI: %02x-%02x-%02x\n", vS->uCSS[8], vS->uCSS[9], vS->uCSS[10]);//Unicast Cipher Suite OUI ID:221
                                printf("Unicast Cipher Suite TYPE: %02x\n", vS->uCSS[11]);//Unicast Cipher Suite TYPE ID:221
                                sM->uCSS[3] = vS->uCSS[11];
                                printf("AKM OUI : %02x-%02x-%02x\n", vS->aSS[8], vS->aSS[9], vS->aSS[10]);//AKM OUI ID=221 -> WPA-1
                                printf("AKM TYPE : %02x\n",vS->aSS[11]);//AKM TYPE ID=221 -> WPA-1
                                sM->aKMS[3] = vS->aSS[11];
                                sM->aKMC[0] = vS->aSC[4];
                                sM->aKMC[1] = vS->aSC[5];
                                break;

                            case 4:
                                printf("Unicast Cipher Suite OUI: %02x-%02x-%02x\n", vS->uCSS[12], vS->uCSS[13], vS->uCSS[14]);//Unicast Cipher Suite OUI ID:221
                                printf("Unicast Cipher Suite TYPE: %02x\n", vS->uCSS[15]);//Unicast Cipher Suite TYPE ID:221
                                sM->uCSS[3] = vS->uCSS[15];
                                printf("AKM OUI : %02x-%02x-%02x\n", vS->aSS[12], vS->aSS[13], vS->aSS[14]);//AKM OUI ID=221 -> WPA-1
                                printf("AKM TYPE : %02x\n",vS->aSS[15]);//AKM TYPE ID=221 -> WPA-1
                                sM->aKMS[3] = vS->aSS[15];
                                sM->aKMC[0] = vS->aSC[6];
                                sM->aKMC[1] = vS->aSC[7];
                                break;

                            default:
                                printf("???????????????????????????????????????????????????????????????????????/\n");
                                break;
                            }


                            if(sM->aKMC[0] != 0x01)
                            {

                                switch (sM->aKMC[0])
                               {

                               /*case 1:
                                    printf("111111111111111111111111111111111111111\n");
                                    printf("AKM OUI : %02x-%02x-%02x\n", vS->aSS[0], vS->aSS[1], vS->aSS[2]);//AKM OUI ID=221 -> WPA-1
                                    printf("AKM TYPE : %02x\n",vS->aSS[3]);//AKM TYPE ID=221 -> WPA-1
                                  //  TYPE[5] = vS->aSS[3];
                                    break;*/

                               case 2:
                                   printf("AKM OUI : %02x-%02x-%02x\n", vS->aSS[4], vS->aSS[5], vS->aSS[6]);//AKM OUI ID=221 -> WPA-1
                                   printf("AKM TYPE : %02x\n",vS->aSS[7]);//AKM TYPE ID=221 -> WPA-1
                                   sM->aKMS[3] = vS->aSS[7];
                                   break;

                               case 3:
                                   printf("AKM OUI : %02x-%02x-%02x\n", vS->aSS[8], vS->aSS[9], vS->aSS[10]);//AKM OUI ID=221 -> WPA-1
                                   printf("AKM TYPE : %02x\n",vS->aSS[11]);//AKM TYPE ID=221 -> WPA-1
                                   sM->aKMS[3] = vS->aSS[11];
                                   break;

                               case 4:
                                   printf("AKM OUI : %02x-%02x-%02x\n", vS->aSS[12], vS->aSS[13], vS->aSS[14]);//AKM OUI ID=221 -> WPA-1
                                   printf("AKM TYPE : %02x\n",vS->aSS[15]);//AKM TYPE ID=221 -> WPA-1
                                   sM->aKMS[3] = vS->aSS[15];
                                   break;

                               default:
                                   printf("???????????????????????????????????????????????????????????????????????/\n");
                                   break;
                               }
                         }


                            }

                            if(vS->vST == 0x02)//1: WPA Information Type-> WPA-1 & 2: WMM/WME -> CCMP 일때 2임...?
                            {

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
                //a = 20; //WPA-2 flsg:20
                sF->enc = WPA2;
                printf("WPA-2: %d\n", sF->enc);
                //sF->enc = 20; //WPA-2 flsg:20
                //printf("aaaaaaaaaaaaaaaaaaaaaaaaa\n");
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
                sF->enc = WPA1; //WPA-1 flsg:10
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
                sF->enc = WEP; //WEP flsg:1
                printf("WEP flag: %d\n", sF->enc);
            }

            if(sM->wep == 0 && rsn->elementId != 48 && vS->elementId != 221)//OPEN
            {
                sF->enc = OPEN; //OPEN flsg:0
                printf("OPEN flag: %d\n", sF->enc);
            }

            //###################TYPE########################
            printf("##############################\n");
            //ID:48 WPA-2
            printf("GROUP:%d\n",sM->gCSS[3]);
            printf("PAIRWISE COUNT:%02x-%02x\n",sM->pCSC);
            printf("PAIRWISE:%d\n",sM->pCSS[3]);
            printf("ASS COUNT:%02x-%02x\n",sM->aSC[0],sM->aSC[1]);
            printf("ASS:%d\n",sM->aSS[3]);
            //ID:221 WPA-1
            printf("MULTI:%d\n",sM->mCSS[3]);
            printf("UNI COUNT:%02x-%02x\n",sM->uCSC);
            printf("UNI:%d\n",sM->uCSS[3]);
            printf("AKMS COUNT:%02x-%02x\n",sM->aKMC[0],sM->aKMC[1]);
            printf("AKMS:%d\n",sM->aKMS[3]);
            printf("##############################\n");

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
          // memset(koT,0,sizeof(struct KindOfType));
}




int main(int argc, char *argv[]){
    pcap_t *pcd;         /* Session handle */
    char *dev="wlan0";         /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];   /* Error string */

    int res=0;
    pcap_pkthdr *Header;

    const u_char *data;


    /* Open the session in promiscuous mode */
    pcd = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);


    while((res=pcap_next_ex(pcd,&Header,&data))>0)
   {

      misconfigureAP (data);

      printf("\n");

   }
pcap_close(pcd);
    return(0);
}
