#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <cstdint>
#include <iostream>
#include <map>
#include <unordered_map>
#include <fstream>
#include <memory>

#define APP_RTMP_PORT 1935
#define RTMP_AMF0_STRING_PLAY "play"
#define RTMP_AMF0_STRING_LIVE "live"
#define RTMP_AMF0_STRING_CONN "connect"
#define RTMP_AMF0_STRING_TCURL "tcUrl"


#define RTMP_M3U_FILE_PATH "/data/rtmp/live.m3u8"
#define RTMP_RECORD_PATH "/data/rtmp/rtmpdump/"

#pragma pack(1)



// IP header structure
struct ipheader {
 unsigned char      iph_ihl:4, iph_ver:4;
 unsigned char      iph_tos;
 unsigned short int iph_len;
 unsigned short int iph_ident;
 unsigned char      iph_flag:3, iph_offset:13;
 unsigned char      iph_ttl;
 unsigned char      iph_protocol;
 unsigned short int iph_chksum;
 struct in_addr     iph_sourceip;
 struct in_addr     iph_destip;
};


// TCP header structure
struct tcpheader {
    uint16_t source_port;       // 源端口号
    uint16_t dest_port;         // 目标端口号
    uint32_t sequence;          // 序列号
    uint32_t ack_sequence;      // 确认序列号
    uint16_t  data_offset;     // 数据偏移 和数据保留
    //uint8_t  flags;             // 标志位
    uint16_t window_size;       // 窗口大小
    uint16_t checksum;          // 校验和
    uint16_t urgent_pointer;    // 紧急指针
};


struct RTMPHeader {
    uint32_t keyword1;     // 2 bits + 6 bits stremaid + 3bytes timestamp
    uint32_t keyword2;     // body size + stream type
    uint32_t messageStreamId; // 4 bytes
};

enum RTMP_HEADER_TYPE_ID
{
    RTMP_HEADER_TYPE_AMF0 = 0x14
};

enum RTMP_AMF0_TYPE
{
    RTMP_AMF0_TYPE_NUMBER = 0x0,
    RTMP_AMF0_TYPE_BOOL   = 0x1,
    RTMP_AMF0_TYPE_STRING = 0x2,
    RTMP_AMF0_TYPE_OBJECT = 0x3,
    RTMP_AMF0_TYPE_NULL = 0x5
};


volatile int keepRunning = 1;

void intHandler(int dummy) {
    keepRunning = 0;
}


class appRTMPHandler
{
private:
    std::string tcUrl;
    std::string strToken;
    uint16_t payloadLen;
    bool isObtainAddr;

public:
    appRTMPHandler()
    {
        payloadLen = 0;
        isObtainAddr = false;
    }

    bool isStopDist()
    {
        return isObtainAddr;
    }

    std::string getLiveId()
    {
        std::string strLiveId;
        // strToken such as xxxx?token=xxxx&t=xxxx,so get live id from strToken,split ? and get the first part
        if(!strToken.empty())
        {
            size_t pos = strToken.find("?");
            if(pos != std::string::npos)
            {
                strLiveId = strToken.substr(0,pos);
            }
        }

        return strLiveId;
    }


    std::string formateM3U()
    {
        char m3uBuf[512] = {0};
        std::string strM3u;

        if(!getRtmpReplayUrl().empty())
        {
            snprintf(m3uBuf,512,"#EXTINF:0,1, Stream \n%s app=live tcUrl=%s conn= live=1",getRtmpReplayUrl().c_str(),getRtmpReplayUrl().c_str());
            strM3u = m3uBuf;
        }

        return strM3u;
    }

    std::string getRtmpReplayUrl()
    {
        std::string rtmpReplay;
        if(!tcUrl.empty() && !strToken.empty())
        {
            rtmpReplay = tcUrl + "/" + strToken;
        }

        return rtmpReplay;
    }

    void handle(const uint8_t *_tcpPayload,uint16_t _payloadLen)
    {
        payloadLen = _payloadLen;
        if (sizeof(struct RTMPHeader) > _payloadLen)
        {
            return;
        }

        struct RTMPHeader *rtmpHdr = (struct RTMPHeader *)_tcpPayload;
        uint16_t rtmpBodySize = (ntohl(rtmpHdr->keyword2) & 0xffffff00) >> 8;
        uint16_t rtmpTypeId = ntohl(rtmpHdr->keyword2) & 0x000000ff;

        if ((_payloadLen - sizeof(struct RTMPHeader)) < rtmpBodySize)
        {
            return;
        }

        if (rtmpTypeId != RTMP_HEADER_TYPE_AMF0)
        {
            return;
        }

        //std::cout << "=========rtmp body size: " << std::hex << rtmpTypeId << std::endl;

        const uint8_t *rtmpBody = _tcpPayload + sizeof(struct RTMPHeader);
        uint8_t amf0Type = *rtmpBody;
        uint16_t bodyOffset = 1;

        if(amf0Type == RTMP_AMF0_TYPE_STRING)
        {
            uint16_t strLen = ntohs(*(uint16_t *)(rtmpBody + bodyOffset));
            bodyOffset += 2;
            std::string strCmd = std::string((const char *)(rtmpBody + bodyOffset),(size_t)strLen);
            bodyOffset +=strLen;
        
            if(strCmd == RTMP_AMF0_STRING_CONN)
            {
                parseLiveAddr(rtmpBody,bodyOffset,rtmpBodySize);
            }

            if(strCmd == RTMP_AMF0_STRING_PLAY)
            {
                parseToken(rtmpBody,bodyOffset,rtmpBodySize);
            }

            if(!tcUrl.empty() && !strToken.empty())
            {
                isObtainAddr = true;
            }

        }
    }

    void parseRtmpObject(const uint8_t *_rtmpBody,uint16_t& rtmpOffset,uint16_t _bodySize)
    {
        while(rtmpOffset < _bodySize)
        {
            std::string strVal;
            uint16_t strLen = ntohs(*(uint16_t *)(_rtmpBody + rtmpOffset));
            //std::cout << "strLen:" << strLen << std::endl;
            rtmpOffset += 2;
            std::string strProperty = std::string((const char *)(_rtmpBody + rtmpOffset),strLen);
            rtmpOffset += strLen;

            //std::cout << "property name:" << strProperty << std::endl;

            uint8_t amf0Type = *(uint8_t *)(_rtmpBody + rtmpOffset);
            switch(amf0Type)
            {
                case RTMP_AMF0_TYPE_NUMBER:
                {   rtmpOffset +=1; // jump amf0Type
                    rtmpOffset += 8; // jump double type
                    break;
                }
                case RTMP_AMF0_TYPE_BOOL:
                {
                    rtmpOffset += 1;
                    rtmpOffset += 1; //offset bool value
                    break; 
                }
                case RTMP_AMF0_TYPE_STRING:
                {   
                    rtmpOffset += 1;
                    uint16_t strLen = ntohs(*(uint16_t *)(_rtmpBody + rtmpOffset));
                    rtmpOffset += 2;
                    strVal = std::string((const char *)(_rtmpBody + rtmpOffset),strLen);
                    rtmpOffset += strLen;
                    break;
                }
                case RTMP_AMF0_TYPE_NULL:
                {
                    rtmpOffset += 1;
                    break;
                }
                default:
                {
                    std::cout << "not support object amf0Type:" << std::hex <<  amf0Type << std::endl;
                    return;
                }
            }

            if(strProperty == RTMP_AMF0_STRING_TCURL)
            {
                tcUrl = strVal;
                break;
            }
        }
        
    }

    void parseLiveAddr(const uint8_t *_rtmpBody,uint16_t &rtmpOffset,uint16_t _bodySize)
    {
        while(rtmpOffset < _bodySize)
        {
            uint8_t amf0Type = *(uint8_t *)(_rtmpBody + rtmpOffset);
            switch(amf0Type)
            {
                case RTMP_AMF0_TYPE_NUMBER:
                {   rtmpOffset +=1; // jump amf0Type
                    rtmpOffset += 8; // jump double type
                    break;
                }
                case RTMP_AMF0_TYPE_OBJECT:
                {
                    rtmpOffset += 1;
                    parseRtmpObject(_rtmpBody,rtmpOffset,_bodySize);
                    return; 
                }
                case RTMP_AMF0_TYPE_NULL:
                {
                    rtmpOffset += 1;
                    break;
                }
                default:
                    std::cout << "not support amf0Type:" << amf0Type << std::endl;

            }
            if(!strToken.empty())
            {
                break;
            }
        }
    }

    void parseToken(const uint8_t *_rtmpBody,uint16_t &_offset,uint16_t _bodySize)
    {
        uint16_t rtmpOffset = _offset;
        while(rtmpOffset < _bodySize)
        {
            uint8_t amf0Type = *(uint8_t *)(_rtmpBody + rtmpOffset);
            switch(amf0Type)
            {
                case RTMP_AMF0_TYPE_NUMBER:
                {   rtmpOffset +=1; // jump amf0Type
                    rtmpOffset += 8; // jump double type
                    break;
                }
                case RTMP_AMF0_TYPE_STRING:
                {   rtmpOffset += 1;
                    uint16_t strLen = ntohs(*(uint16_t *)(_rtmpBody + rtmpOffset));
                    rtmpOffset += 2;
                    strToken = std::string((const char *)(_rtmpBody + rtmpOffset),strLen);
                    rtmpOffset += strLen;
                    break;
                }
                case RTMP_AMF0_TYPE_NULL:
                {
                    rtmpOffset += 1;
                    break;
                }
                default:
                    std::cout << "not support amf0Type:" << amf0Type << std::endl;

            }
            if(!strToken.empty())
            {
                //std::cout << "play token:" << strToken << std::endl;
                break;
            }
        }
    }
};


struct RtmpDistInfo
{
    std::shared_ptr<appRTMPHandler> rtmpHandler;
    uint16_t distPackets;
    int     startTime;

    RtmpDistInfo()
    {
        rtmpHandler = std::make_shared<appRTMPHandler>();
        distPackets = 1;

    }

    RtmpDistInfo(const RtmpDistInfo& _input)
    {
        rtmpHandler = _input.rtmpHandler;
        distPackets = _input.distPackets;

    }
    RtmpDistInfo& operator=(const RtmpDistInfo& _input)
    {

        rtmpHandler = _input.rtmpHandler;
        distPackets = _input.distPackets;
        return *this;
    }

    ~RtmpDistInfo()
    {
    }
    
};



class PacketDistCenter
{

private:
    std::unordered_map<uint16_t,std::shared_ptr<RtmpDistInfo> > distByPort;
    std::unordered_map<std::string,int32_t> ffmpegRecordList;

public:
    void distRecordToffmepg(std::string _rtmpRecordUrl,std::string _strLiveId)
    {
        int32_t recordTime = time(NULL);
        if(ffmpegRecordList.count(_strLiveId))
        {
            return;
        }
        else
        {
            ffmpegRecordList[_strLiveId] = recordTime;
        }

	std::string strRecordLog = RTMP_RECORD_PATH;
	strRecordLog += _strLiveId + ".txt";
        	

        std::string strCmd = "ffmpeg -y -i '" + _rtmpRecordUrl + "' -timeout 30000000 -vcodec copy -t 10000 -f mp4 ";
        strCmd += RTMP_RECORD_PATH;
        strCmd += _strLiveId + "_";
        strCmd += std::to_string(recordTime) + ".mp4 >";
	strCmd += strRecordLog +" 2>&1 &";

        std::cout << "ffmpeg cmd:" << strCmd << std::endl;

        system(strCmd.c_str());

        // remove recordtime from ffmpegRecordList that bigger than 10000
        std::unordered_map<std::string,int32_t>::iterator it = ffmpegRecordList.begin();
        while(it != ffmpegRecordList.end())
        {
            if(recordTime - it->second > 10000)
            {
                std::cout << "remove liveid:" << it->first << " recordtime:" << it->second << std::endl;
                ffmpegRecordList.erase(it++);
            }
            else
            {
                ++it;
            }
        }

    }


    void flushRecord()
    {
        // loop distByPort
        // if rtmpHandler isStopDist() and getRtmpReplayUrl() is not empty,then write starttime  to m3u file
        // clear distByPort that bigger than 30*60

        std::ofstream m3uFile(RTMP_M3U_FILE_PATH);
        std::unordered_map<uint16_t,std::shared_ptr<RtmpDistInfo> >::iterator it = distByPort.begin();
        while(it != distByPort.end())
        {
            if(it->second->rtmpHandler->isStopDist() && !it->second->rtmpHandler->getRtmpReplayUrl().empty())
            {
                //std::cout << "obtain tcurl:" << it->second->rtmpHandler->getRtmpReplayUrl() << std::endl;
                distRecordToffmepg(it->second->rtmpHandler->getRtmpReplayUrl(),it->second->rtmpHandler->getLiveId());

                if(m3uFile.good())
                {
                    m3uFile << "#EXTM3U x-tvg-url=https://iptv-org.github.io/epg/guides/ae-ar/osn.com.epg.xml" << std::endl;
                    m3uFile << it->second->rtmpHandler->formateM3U()<< std::endl;

                }
            }

            if(time(NULL) - it->second->startTime > 30*60)
            {
                distByPort.erase(it++);
            }
            else
            {
                ++it;
            }
        }

        m3uFile.close();

    }



    void process_packet(const u_char *packet) 
    {
        struct ipheader *iph = (struct ipheader *)(packet + 14);
        struct tcpheader *tcph = (struct tcpheader *)(packet + 14 + iph->iph_ihl*4);

        uint16_t ipTotalLen = ntohs(iph->iph_len);
        uint16_t tcpHdrLen = (ntohs(tcph->data_offset)&0xf000) >> 12;
        tcpHdrLen = tcpHdrLen * 4;

        uint16_t dstPort = ntohs(tcph->dest_port);
        uint16_t srcPort = ntohs(tcph->source_port);

        //uint16_t flagPort = dstPort > srcPort ? dstPort : srcPort;

        if(dstPort == APP_RTMP_PORT)
        {
            std::shared_ptr<RtmpDistInfo> rtmpHander;
            if(distByPort.count(srcPort))
            {
                rtmpHander = distByPort[srcPort];
                if(rtmpHander->rtmpHandler == nullptr || rtmpHander->distPackets > 128 || rtmpHander->rtmpHandler->isStopDist())
                {
                    return;
                }
                rtmpHander->distPackets++;
            }
            else
            {
                rtmpHander = std::make_shared<RtmpDistInfo>();
                rtmpHander->startTime = time(NULL);
                distByPort[srcPort] = rtmpHander;
            }

            const uint8_t *payload = packet + 14 + iph->iph_ihl*4 + tcpHdrLen;
            //std::cout << "ipid:" << std::hex << iph->iph_ident << std::endl;
            //printf("TCP Dest Port: %d\n", appPort);
            rtmpHander->rtmpHandler->handle(payload,ipTotalLen - tcpHdrLen - 20);

            flushRecord();

        }

    }
};

int main(int argc, char *argv[]) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char *packet;
    char *filename = NULL;
    char *interface = NULL;
    int c;

    PacketDistCenter pktDistCenter;

    signal(SIGINT, intHandler);
    
    std::cout << "sniff rtmp traffic......" << std::endl;

    while ((c = getopt (argc, argv, "i:r:")) != -1) {
        switch (c) {
            case 'i':
                interface = optarg;
                break;
            case 'r':
                filename = optarg;
                break;
            default:
                return 1;
        }
    }

    if (filename) {
        handle = pcap_open_offline(filename, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open pcap file: %s\n", errbuf);
            return(2);
        }
    } else if (interface) {
        handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
            return(2);
        }
    } else {
        fprintf(stderr, "Must specify either -i or -r option\n");
        return(2);
    }

    while (keepRunning && (packet = pcap_next(handle, &header))) {
        pktDistCenter.process_packet(packet);
    }

    pcap_close(handle);
    return(0);
}
