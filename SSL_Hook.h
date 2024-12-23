#pragma once

#include "src/version.h"

#include <TlHelp32.h>
#include <string>
#include <vector>
#include <winsock2.h>
#include <ctime>
#include <sstream>

using namespace std;

#if defined _M_X64
#define ADDRESS_VALUE uint64_t
#elif defined _M_IX86
#define ADDRESS_VALUE uint32_t
#endif

#undef UNICODE

// Defines

#define LINKTYPE_IPV4			228
#define PACKET_HEADER_SIZE		40
#define MAX_PACKET_SIZE			65535
#define MAX_TEMP_PATH 300

#define HTONS(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))
#define HTONL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
                  ((((unsigned long)(n) & 0xFF00)) << 8) | \
                  ((((unsigned long)(n) & 0xFF0000)) >> 8) | \
                  ((((unsigned long)(n) & 0xFF000000)) >> 24))

// Class to work with PCAP files

// Struct for sections

struct SECTION_INFO
{
	ADDRESS_VALUE dwStartAddress;
	DWORD dwSize;
};

// Struct for processes

struct PROCESS_TO_MONITOR
{
	DWORD Id = 0;
	string ProcessName;
};

// Struct for exports

struct EXPORT_ENTRY
{
	ADDRESS_VALUE dwAddress;
	ADDRESS_VALUE dwPointerOfAddress;
	string sName;
	USHORT uOrdinal;
};

// Struct for flags

struct FUNCTION_FLOW
{
	DWORD dwThreadId;
	BOOL  bFlag;
};

// Used to get IP/Port info

struct IPInfo
{
	uint32_t nSrcIP;
	uint32_t nDstIP;
	uint16_t nSrcPort;
	uint16_t nDstPort;
};

// Tracking seq and ack based in IPs/ports
struct PacketTracker
{
	uint32_t nSeq = 0;
	uint32_t nAck = 0;
	uint32_t nSrcIP = 0x10101010;
	uint32_t nDstIP = 0x20202020;
	uint16_t nSrcPort = 1337;
	uint16_t nDstPort = 80;
};
// Struct used internally

struct PCAPFile
{
	string sFilename;
	bool   bHeaderWritten = 0;
	vector<PacketTracker*> vPacketTrackers;
	CRITICAL_SECTION oCriticalSection;
};

// PCAP header: https://wiki.wireshark.org/Development/LibpcapFileFormat

typedef struct pcap_hdr_s
{
	uint32_t magic_number;   /* magic number */
	uint16_t version_major;  /* major version number */
	uint16_t version_minor;  /* minor version number */
	int32_t  thiszone;       /* GMT to local correction */
	uint32_t sigfigs;        /* accuracy of timestamps */
	uint32_t snaplen;        /* max length of captured packets, in octets */
	uint32_t network;        /* data link type */
} pcap_hdr_t;

// PCAP packet header: https://wiki.wireshark.org/Development/LibpcapFileFormat

typedef struct pcaprec_hdr_s
{
	uint32_t ts_sec;         /* timestamp seconds */
	uint32_t ts_usec;        /* timestamp microseconds */
	uint32_t incl_len;       /* number of octets of packet saved in file */
	uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

// Source https://stackoverflow.com/questions/16519846/parse-ip-and-tcp-header-especially-common-tcp-header-optionsof-packets-capture

typedef struct {
	uint8_t  ver_ihl;  // 4 bits version and 4 bits internet header length
	uint8_t  tos;
	uint16_t total_length;
	uint16_t id;
	uint16_t flags_fo; // 3 bits flags and 13 bits fragment-offset
	uint8_t  ttl;
	uint8_t  protocol;
	uint16_t checksum;
	uint32_t src_addr;
	uint32_t dst_addr;
} ip_header_t;

typedef struct {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq;
	uint32_t ack;
	uint16_t len_and_flags;
	uint16_t window_size;
	uint16_t checksum;
	uint16_t urgent_p;
} tcp_header_t;

static vector<PCAPFile*> s_vPCAPFiles;

// Structure used to return modified data

struct PLUGIN_DATA
{
	unsigned char* data;
	unsigned int   size;
};

class Plugin;

// Callback

typedef PLUGIN_DATA(*PluginCallback_Typedef)(unsigned char*, unsigned int, string);

// SSL_Read, SSL_Write

typedef int (*SSL_Write_Typedef)(void*, void*, int);
typedef int (*SSL_Read_Typedef)(void*, void*, int);


// Callbacks

int SSL_Write_Callback(void* ssl, void* buffer, int amount);
int SSL_Read_Callback(void* ssl, void* buffer, int amount);

//functions
void sync_write_log_sslhook(const char* format, ...);
BOOL Chrome_SSL_Hook();
SECTION_INFO Process_GetModuleSection(string p_sModule, string p_sSection);
ADDRESS_VALUE Process_SearchSignature(void* p_pvStartAddress, DWORD p_dwSize, void* p_pvBuffer, DWORD p_dwBufferSize);
vector<MODULEENTRY32> Process_GetProcessModules(DWORD p_dwID);
bool Utils_Is32BitProcess();
string Utils_ToLower(string p_sString);
BOOL FunctionFlow_CheckFlag();
void FunctionFlow_UnCheckFlag();
static void PluginSystem_ProcessAndSaveRead(string p_sFilename, unsigned char* p_pcData, unsigned int p_nSize, unsigned int p_nSocket = 0);
static void PluginSystem_ProcessAndSaveWrite(string p_sFilename, unsigned char* p_pcData, unsigned int p_nSize, unsigned int p_nSocket = 0);
PLUGIN_DATA PluginSystem_ProcessWriteData(unsigned char* p_pcData, unsigned int p_nSize);
static IPInfo Utils_GetIPInfo(unsigned int p_nSocket);
static void PCAP_WriteData(string p_sFilename, unsigned char* p_pcData, size_t p_nSize, bool p_bDataSent,
	uint32_t p_sSrcIP = 0x10101010, uint32_t p_sDstIP = 0x20202020, uint16_t p_nSrcPort = 1337, uint16_t p_nDstPort = 80);
PLUGIN_DATA PluginSystem_ProcessReadData(unsigned char* p_pcData, unsigned int p_nSize);
string Utils_GetFilename(string p_sFilename);