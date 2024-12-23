#include "SSL_Hook.h"

#undef UNICODE

// Global variables

static vector<FUNCTION_FLOW*> vFlags;
static CRITICAL_SECTION gCriticalSection;
static bool gInitialized = 0;


SSL_Write_Typedef SSL_Write_Original;
SSL_Read_Typedef SSL_Read_Original;

class Plugin
{
private:
	string m_sConfig;

public:
	Plugin();
	void SetConfig(string p_sConfig);

	// Called functions

	PLUGIN_DATA ProcessReadData(unsigned char* p_pcData, unsigned int p_nSize);
	PLUGIN_DATA ProcessWriteData(unsigned char* p_pcData, unsigned int p_nSize);

	// Read & Write callback

	PluginCallback_Typedef ReadCallback;
	PluginCallback_Typedef WriteCallback;
};
// All plugins
static vector<Plugin*> s_vPlugins;

Plugin::Plugin()
{
	ReadCallback = NULL;
	WriteCallback = NULL;
}

// Set config data

void Plugin::SetConfig(string p_sConfig)
{
	m_sConfig = p_sConfig;
}

// Called by PluginSystem to process read data

PLUGIN_DATA Plugin::ProcessReadData(unsigned char* p_pcData, unsigned int p_nSize)
{
	PLUGIN_DATA ret;

	ret.data = p_pcData;
	ret.size = p_nSize;

	if (this->ReadCallback != NULL) ret = this->ReadCallback(ret.data, ret.size, this->m_sConfig);

	return ret;
}

// Called by PluginSystem to process write data

PLUGIN_DATA Plugin::ProcessWriteData(unsigned char* p_pcData, unsigned int p_nSize)
{
	PLUGIN_DATA ret;

	ret.data = p_pcData;
	ret.size = p_nSize;

	if (this->WriteCallback != NULL) ret = this->WriteCallback(ret.data, ret.size, this->m_sConfig);

	return ret;
}


void sync_write_log_sslhook(const char* format, ...) {
	FILE* log_file = fopen("sync_log.txt", "a");  // Open in append mode
	if (log_file == NULL) {
		perror("Error opening log file");
		return;
	}

	// Handle variable arguments for formatted logging
	va_list args;
	va_start(args, format);
	vfprintf(log_file, format, args);
	va_end(args);

	// Add a newline to separate log entries
	fprintf(log_file, "\n");

	fclose(log_file);  // Close the file
}


string Utils_ToLower(string p_sString)
{
	string result = "";

	for (size_t i = 0; i < p_sString.length(); i++)
	{
		if (p_sString[i] >= 65 && p_sString[i] <= 90) result += (char)(p_sString[i] + 32);
		else result += p_sString[i];
	}

	return result;
}

bool Utils_Is32BitProcess()
{
	if (sizeof(void*) == 4) return true;
	else return false;
}

vector<MODULEENTRY32> Process_GetProcessModules(DWORD p_dwID)
{
	HANDLE hSnapshot;
	MODULEENTRY32 hModule;
	vector<MODULEENTRY32> vModules;

	// Process ID = 0 or -1 => current process

	if (p_dwID == 0 || p_dwID == -1) p_dwID = GetCurrentProcessId();

	/* Get processes snapshot */

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, p_dwID);

	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		sync_write_log_sslhook("[ERROR] Cannot get modules snapshot!");
		return vModules;
	}

	hModule.dwSize = sizeof(MODULEENTRY32);

	// Get first process

	if (!Module32First(hSnapshot, &hModule))
	{
		sync_write_log_sslhook("[ERROR] Cannot get first module!");
		return vModules;
	}

	vModules.push_back(hModule);

	// Get all processes

	while (Module32Next(hSnapshot, &hModule))
		vModules.push_back(hModule);

	return vModules;
}

ADDRESS_VALUE Process_SearchSignature(void* p_pvStartAddress, DWORD p_dwSize, void* p_pvBuffer, DWORD p_dwBufferSize)
{
	ADDRESS_VALUE dwMax = (ADDRESS_VALUE)p_pvStartAddress + p_dwSize;
	unsigned char c1 = 0, c2 = 0;
	bool bOk = false;

	for (DWORD i = 0; i < p_dwSize - p_dwBufferSize; i++)
	{
		bOk = false;

		for (DWORD j = 0; j < p_dwBufferSize; j++)
		{
			// c1 = from memory, c2 = from signature

			c1 = *(unsigned char*)((ADDRESS_VALUE)p_pvStartAddress + i + j);
			c2 = *(unsigned char*)((ADDRESS_VALUE)p_pvBuffer + j);

			// Check character

			if (c1 == c2 || c2 == '?')
			{
				bOk = true;
				continue;
			}
			else
			{
				bOk = false;
				break;
			}
		}

		// Check if we found the signature

		if (bOk) return (ADDRESS_VALUE)p_pvStartAddress + i;
	}

	sync_write_log_sslhook("[ERROR] SearchSignature did not find the signature!");

	return 0;
}

SECTION_INFO Process_GetModuleSection(string p_sModule, string p_sSection)
{
	SECTION_INFO oSectionData = { 0, 0 };
	bool bFound = 0;
	HMODULE hModule = 0;

	// Check if we want default module (filename.exe)

	if (!p_sModule.empty())
	{
		// Check if module is loaded

		p_sModule = Utils_ToLower(p_sModule);
		vector<MODULEENTRY32> vModules = Process_GetProcessModules(0);

		char narrowCharArray[256];		
		for (size_t i = 0; i < vModules.size(); i++)
		{
			wcstombs(narrowCharArray, vModules[i].szModule, sizeof(narrowCharArray));
			if (p_sModule.compare(Utils_ToLower(narrowCharArray)) == 0)
			{
				bFound = 1;

				hModule = GetModuleHandle(vModules[i].szModule);

				// If we can get module handle

				if (hModule == NULL)
				{
					sync_write_log_sslhook("[ERROR] Cannot find module handle: %s", p_sModule);
					return oSectionData;
				}
			}
		}
	}
	else
	{
		// Default file module 

		hModule = GetModuleHandle(0);

		// If we can get default module handle

		if (hModule == NULL)
		{
			sync_write_log_sslhook("[ERROR] Cannot find default module handle: %s", p_sModule);
			return oSectionData;
		}
	}

	// Parse module

	IMAGE_DOS_HEADER dos;
	IMAGE_NT_HEADERS ntHeaders;
	IMAGE_SECTION_HEADER* pSections = NULL;

	// Get DOS/PE header

	memcpy(&dos, (void*)hModule, sizeof(IMAGE_DOS_HEADER));
	memcpy(&ntHeaders, (void*)((ADDRESS_VALUE)hModule + dos.e_lfanew), sizeof(IMAGE_NT_HEADERS));

	// Get sections
	try {
		pSections = new IMAGE_SECTION_HEADER[ntHeaders.FileHeader.NumberOfSections];
	}
	catch (std::bad_alloc&)
	{
		sync_write_log_sslhook("[ERROR] Cannot allocate space for sections: %d", ntHeaders.FileHeader.NumberOfSections);
		return oSectionData;
	}

	// Copy

	memcpy(pSections, (void*)((ADDRESS_VALUE)hModule + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS)),
		(ntHeaders.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)));

	// Print

	for (size_t j = 0; j < ntHeaders.FileHeader.NumberOfSections; j++)
	{
		if (p_sSection.compare((char*)pSections[j].Name) == 0)
		{
			oSectionData.dwSize = pSections[j].SizeOfRawData;
			oSectionData.dwStartAddress = (ADDRESS_VALUE)hModule + pSections[j].VirtualAddress;
			delete pSections;
			return oSectionData;
		}
	}

	delete[] pSections;

	sync_write_log_sslhook("[ERROR] GetModuleSection did not find the section: %s", p_sSection);

	return oSectionData;
}

// SSL_Write callback 64 bits

int SSL_Write_Callback(void* fd, void* buffer, int amount)
{
	LONG res;

	// If allowed

	if (FunctionFlow_CheckFlag() == FALSE)
	{
		PluginSystem_ProcessAndSaveWrite("SSL_ReadWrite.pcap", (unsigned char*)buffer, amount);
	}

	// Call original function

	res = SSL_Write_Original(fd, buffer, amount);

	FunctionFlow_UnCheckFlag();

	return res;
}

// SSL_Read callback 64 bits

int SSL_Read_Callback(void* fd, void* buffer, int amount)
{
	BOOL bFlag = FunctionFlow_CheckFlag();
	int ret = SSL_Read_Original(fd, buffer, amount);

	// Do things

	if (bFlag == FALSE)
	{
		if (ret > 0) PluginSystem_ProcessAndSaveRead("SSL_ReadWrite.pcap", (unsigned char*)buffer, ret);
	}

	FunctionFlow_UnCheckFlag();

	return ret;
}

BOOL Chrome_SSL_Hook() {
	string p_sModule = "chrome.dll";
	SECTION_INFO rdata = { 0, 0 };
	SECTION_INFO text = { 0, 0 };

	// 64 bits signatures
	// 102.0.5005.115
	unsigned char Write_Signature64[] = {
	//	0x41, 0x56, 0x56, 0x57, 0x55, 0x53, 0x48, 0x83, 0xec, 0x40, 0x45, 0x89, 0xc6, 0x48, 0x89, 0xd7,
	//	0x48, 0x89, 0xcb, 0x48, 0x8b, 0x05, '?',  '?',  '?',  '?',  0x48, 0x31, 0xe0, 0x48, 0x89, 0x44 
		0x41, 0x54, 0x56, 0x57, 0x55, 0x53, 0x48, 0x83, 0xec, 0x50, 0x44, 0x89, 0xc3, 0x48, 0x89, 0xd7,
		0x48, 0x89, 0xce, 0x48, 0x8b, 0x05, '?',  '?',  '?',  '?',  0x48, 0x31, 0xe0, 0x48, 0x89, 0x44
	};

	unsigned char Read_Signature64[] = {
		0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x56, 0x57, 0x55,  0x53,  0x48,  0x81,  0xec, 0x98,
		'?', '?', '?', 0x0f , 0x29, 0xb4, 0x24, '?' };

	// 32 bits signatures
	// Chrome 64
	unsigned char Write_Signature32[] = {
		0x55, 0x89, 0xE5, 0x53, 0x57, 0x56, 0x83, 0xEC, 0x08, 0xA1, '?' , '?' , '?' , '?' , 0x8B, 0x7D,
		0x08, 0x31, 0xE8, 0x89, 0x45, 0xF0, 0x8B, 0x47, 0x18, 0xC7, 0x80, 0x98, 0x00, 0x00, 0x00, 0x01 };
	unsigned char Read_Signature32[] = {
		0x55, 0x89, 0xE5, 0x57, 0x56, 0x8B, 0x7D, 0x08, 0xFF, 0x75, 0x10, 0xFF, 0x75, 0x0C, 0x57, 0xE8,
		'?' , '?' , '?' , '?' , 0x83, 0xC4, 0x0C, 0x89, 0xC6, 0x85, 0xC0, 0x7E, 0x21, 0x8B, 0x47, 0x18 };

	// Get section

	text = Process_GetModuleSection(p_sModule, ".text");

	// Check if chrome

	if (text.dwSize == 0 || text.dwStartAddress == 0)
	{
		sync_write_log_sslhook("[ERROR] Cannot get Chrome text section!");
		return FALSE;
	}

	// We have the x86 versions

	if (Utils_Is32BitProcess())
	{
		// Search memory

		ADDRESS_VALUE pWrite32 = Process_SearchSignature((void*)text.dwStartAddress, text.dwSize, (void*)Write_Signature32, sizeof(Write_Signature32));
		ADDRESS_VALUE pRead32 = Process_SearchSignature((void*)text.dwStartAddress, text.dwSize, (void*)Read_Signature32, sizeof(Read_Signature32));

		if (pRead32 == 0 || pWrite32 == 0)
		{
			sync_write_log_sslhook("[ERROR] Cannot get Chrome SSL functions!");
			return FALSE;
		}

		// Add hooks

		SSL_Write_Original = (SSL_Write_Typedef)pWrite32;
		SSL_Read_Original = (SSL_Read_Typedef)pRead32;

		DetourAttach((void**)&SSL_Write_Original, (void*)SSL_Write_Callback);
		DetourAttach((void**)&SSL_Read_Original, (void*)SSL_Read_Callback);

		return TRUE;
	}
	else
	{
		// Search memory

		ADDRESS_VALUE pWrite64 = Process_SearchSignature((void*)text.dwStartAddress, text.dwSize, (void*)Write_Signature64, sizeof(Write_Signature64));
		/*ADDRESS_VALUE pRead64 = Process_SearchSignature((void*)text.dwStartAddress, text.dwSize, (void*)Read_Signature64, sizeof(Read_Signature64));

		if (pRead64 == 0)
		{
			sync_write_log_sslhook("[ERROR] Cannot get Chrome SSL read function!");
		}
		else*/ if (pWrite64 == 0)
		{
			sync_write_log_sslhook("[ERROR] Cannot get Chrome SSL write function!");
		}

		// Add hooks

		SSL_Write_Original = (SSL_Write_Typedef)pWrite64;
		//SSL_Read_Original = (SSL_Read_Typedef)pRead64;

		DetourAttach((void**)&SSL_Write_Original, (void*)SSL_Write_Callback);
		//DetourAttach((void**)&SSL_Read_Original, (void*)SSL_Read_Callback);

		return TRUE;
	}
	return TRUE;
}

BOOL FunctionFlow_CheckFlag()
{
	DWORD tid = GetCurrentThreadId();

	EnterCriticalSection(&gCriticalSection);

	// Search tid in vector

	for (unsigned i = 0; i < vFlags.size(); ++i)
	{
		if (vFlags[i]->dwThreadId == tid)
		{
			if (vFlags[i]->bFlag == TRUE)
			{
				// If flag is already set, return TRUE

				LeaveCriticalSection(&gCriticalSection);
				return TRUE;
			}
			else
			{
				// If flags is NOT set, we set it and return FALSE, do actions

				vFlags[i]->bFlag = TRUE;

				LeaveCriticalSection(&gCriticalSection);
				return FALSE;
			}
		}
	}

	// Create flag element

	FUNCTION_FLOW* oFlag = new FUNCTION_FLOW;
	oFlag->bFlag = TRUE;
	oFlag->dwThreadId = tid;

	// Add to vector

	vFlags.push_back(oFlag);

	LeaveCriticalSection(&gCriticalSection);

	// Do actions

	return FALSE;
}

void FunctionFlow_UnCheckFlag()
{
	DWORD tid = GetCurrentThreadId();

	EnterCriticalSection(&gCriticalSection);

	// Search tid in vector

	for (unsigned i = 0; i < vFlags.size(); ++i)
	{
		if (vFlags[i]->dwThreadId == tid)
		{
			// delete vFlags[i];
			// vFlags.erase(vFlags.begin() + i);

			vFlags[i]->bFlag = FALSE;
			break;
		}
	}

	LeaveCriticalSection(&gCriticalSection);
}

void PluginSystem_ProcessAndSaveWrite(string p_sFilename, unsigned char* p_pcData, unsigned int p_nSize, unsigned int p_nSocket)
{
	if (p_pcData == NULL || p_nSize == 0) return;

	PLUGIN_DATA ret = PluginSystem_ProcessWriteData(p_pcData, p_nSize);

	if (ret.size > 0)
	{
		if (p_nSocket)
		{
			IPInfo ip = Utils_GetIPInfo(p_nSocket);
			PCAP_WriteData(p_sFilename, ret.data, ret.size, true, ip.nSrcIP, ip.nDstIP, ip.nSrcPort, ip.nDstPort);
		}
		else 
			PCAP_WriteData(p_sFilename, ret.data, ret.size, true);
	}
	if (ret.data != p_pcData) delete[] ret.data;
}

PLUGIN_DATA PluginSystem_ProcessWriteData(unsigned char* p_pcData, unsigned int p_nSize)
{
	PLUGIN_DATA ret;
	unsigned char* p = NULL;

	ret.data = p_pcData;
	ret.size = p_nSize;

	if (p_pcData == NULL || p_nSize == 0) return ret;

	// Iterate through plugins

	for (size_t i = 0; i < s_vPlugins.size(); i++)
	{
		p = ret.data;
		ret = s_vPlugins[i]->ProcessWriteData(ret.data, ret.size);
		if (i != 0 && ret.data != p) delete[] p;
	}

	return ret;
}

IPInfo Utils_GetIPInfo(unsigned int p_nSocket)
{
	IPInfo data;
	sockaddr_in sock_client, sock_server;
	int len_client = sizeof(sock_client);
	int len_server = sizeof(sock_server);

	// Get socket data

	memset(&sock_client, 0, sizeof(sock_client));
	memset(&sock_server, 0, sizeof(sock_server));

	getsockname((SOCKET)p_nSocket, (struct sockaddr*)&sock_client, &len_client);
	getpeername((SOCKET)p_nSocket, (struct sockaddr*)&sock_server, &len_server);

	// Save data

	data.nSrcIP = (uint32_t)sock_client.sin_addr.S_un.S_addr;
	data.nDstIP = (uint32_t)sock_server.sin_addr.S_un.S_addr;
	data.nSrcPort = (uint16_t)ntohs(sock_client.sin_port);
	data.nDstPort = (uint16_t)ntohs(sock_server.sin_port);

	return data;
}

// Get the data path, create folder if it does not exists
string s_sDataPath = "TEMP";
string DynConfig_GetDataPath()
{
	char buffer[MAX_TEMP_PATH] = { 0 };
	string sPath = "";

	// If it is default configured to use TEMP

	if (s_sDataPath.compare("TEMP") == 0)
	{
		// Get Temp path

		if (GetTempPathA(MAX_TEMP_PATH, buffer) == 0)
		{
			sync_write_log_sslhook("[ERROR] Cannot get temporary path to save data!");
			return "";
		}

		sPath = buffer;
		sPath = sPath + "NetRipper";
	}
	else sPath = s_sDataPath;

	// Create DIRECTORY if does not exist

	if (CreateDirectoryA(sPath.c_str(), NULL) == 0)
	{
		if (GetLastError() != ERROR_ALREADY_EXISTS)
		{
			sync_write_log_sslhook("[ERROR] Cannot create NetRipper directory to save data!");
			return "";
		}
	}

	sPath = sPath + "\\";

	return sPath;
}
// Write data (append) to temporary file (/Temp)

void Utils_WriteToTempFile(string p_sFilename, const unsigned char* p_pcBuffer, size_t p_nLength)
{
	FILE* pFile = NULL;
	string sPath = "";
	size_t nWritten = 0;

	if (p_pcBuffer == NULL || p_nLength == 0)
	{
		sync_write_log_sslhook("WARNING: Cannot write NULL data");
		return;
	}

	sPath = DynConfig_GetDataPath();
	sPath = sPath + Utils_GetFilename(p_sFilename);

	// Open file

	pFile = fopen(sPath.c_str(), "ab");

	if (pFile == NULL)
	{
		string sDebug = "Cannot open data file: ";
		sDebug = sDebug + sPath;

		sync_write_log_sslhook(sDebug.c_str());
		return;
	}

	// Write data

	nWritten = fwrite(p_pcBuffer, sizeof(char), p_nLength, pFile);

	if (nWritten != p_nLength)
	{
		string sDebug = "Cannot write to data file: ";
		sDebug = sDebug + sPath;

		sync_write_log_sslhook(sDebug.c_str());
	}

	fclose(pFile);
}

// Write the PCAP file

void PCAP_WriteHeader(PCAPFile* p_pPCAP)
{
	pcap_hdr_s header;

	// Build struct

	header.magic_number = 0xA1B2C3D4;
	header.version_major = 2;
	header.version_minor = 4;
	header.thiszone = 0;
	header.sigfigs = 0;
	header.snaplen = MAX_PACKET_SIZE;
	header.network = LINKTYPE_IPV4;

	// Write the header

	p_pPCAP->bHeaderWritten = true;
	Utils_WriteToTempFile(p_pPCAP->sFilename, (unsigned char*)&header, sizeof(header));
}

// Create a PCAP struct
PCAPFile* CreatePCAP(string p_sFilepath, uint32_t p_sSrcIP, uint32_t p_sDstIP, uint16_t p_nSrcPort, uint16_t p_nDstPort)
{
	PCAPFile* pcap = new PCAPFile();
	pcap->sFilename = p_sFilepath;

	pcap->bHeaderWritten = false;
	InitializeCriticalSection(&pcap->oCriticalSection);

	srand((unsigned int)time(NULL));

	// Packet tracker

	PacketTracker* first = new PacketTracker();
	first->nAck = (uint32_t)rand();
	first->nSeq = (uint32_t)rand();

	first->nSrcIP = p_sSrcIP;
	first->nDstIP = p_sDstIP;
	first->nSrcPort = p_nSrcPort;
	first->nDstPort = p_nDstPort;

	pcap->vPacketTrackers.push_back(first);

	s_vPCAPFiles.push_back(pcap);

	return pcap;
}

// Find a PCAP struct by filepath or create it

PCAPFile* GetPCAP(string p_sFilename, bool p_bDataSent, uint32_t p_sSrcIP, uint32_t p_sDstIP, uint16_t p_nSrcPort, uint16_t p_nDstPort)
{
	for (size_t i = 0; i < s_vPCAPFiles.size(); i++)
	{
		if (p_sFilename.compare(s_vPCAPFiles[i]->sFilename) == 0)
		{
			// Create tracker if not there

			bool bFound = false;

			for (size_t p = 0; p < s_vPCAPFiles[i]->vPacketTrackers.size(); p++)
			{
				if ((s_vPCAPFiles[i]->vPacketTrackers[p]->nSrcIP == p_sSrcIP && s_vPCAPFiles[i]->vPacketTrackers[p]->nDstIP == p_sDstIP &&
					s_vPCAPFiles[i]->vPacketTrackers[p]->nSrcPort == p_nSrcPort && s_vPCAPFiles[i]->vPacketTrackers[p]->nDstPort == p_nDstPort) ||
					(s_vPCAPFiles[i]->vPacketTrackers[p]->nSrcIP == p_sDstIP && s_vPCAPFiles[i]->vPacketTrackers[p]->nDstIP == p_sSrcIP &&
						s_vPCAPFiles[i]->vPacketTrackers[p]->nSrcPort == p_nDstPort && s_vPCAPFiles[i]->vPacketTrackers[p]->nDstPort == p_nSrcPort))
					bFound = true;
			}

			if (!bFound)
			{
				PacketTracker* newtracker = new PacketTracker();
				newtracker->nAck = (uint32_t)rand();
				newtracker->nSeq = (uint32_t)rand();

				newtracker->nSrcIP = p_sSrcIP;
				newtracker->nDstIP = p_sDstIP;
				newtracker->nSrcPort = p_nSrcPort;
				newtracker->nDstPort = p_nDstPort;

				s_vPCAPFiles[i]->vPacketTrackers.push_back(newtracker);
			}

			return s_vPCAPFiles[i];
		}
	}

	// Or create it

	return CreatePCAP(p_sFilename, p_sSrcIP, p_sDstIP, p_nSrcPort, p_nDstPort);
}

// Return a packet tracker by IPs/ports

PacketTracker* GetPacketTracker(PCAPFile* p_pPCAP, bool p_bDataSent, uint32_t p_sSrcIP, uint32_t p_sDstIP, uint16_t p_nSrcPort, uint16_t p_nDstPort)
{
	for (size_t i = 0; i < p_pPCAP->vPacketTrackers.size(); i++)
	{
		if ((p_pPCAP->vPacketTrackers[i]->nSrcIP == p_sSrcIP && p_pPCAP->vPacketTrackers[i]->nDstIP == p_sDstIP &&
			p_pPCAP->vPacketTrackers[i]->nSrcPort == p_nSrcPort && p_pPCAP->vPacketTrackers[i]->nDstPort == p_nDstPort) ||
			(p_pPCAP->vPacketTrackers[i]->nSrcIP == p_sDstIP && p_pPCAP->vPacketTrackers[i]->nDstIP == p_sSrcIP &&
				p_pPCAP->vPacketTrackers[i]->nSrcPort == p_nDstPort && p_pPCAP->vPacketTrackers[i]->nDstPort == p_nSrcPort)
			) return p_pPCAP->vPacketTrackers[i];
	}

	sync_write_log_sslhook("ERROR: GetPacketTracker - PacketTracker not found!");
	return NULL;
}

// Create packet contents, including TCP/IP header (https://github.com/google/ssl_logger/blob/master/ssl_logger.py)

unsigned char* CreatePacket(PCAPFile* p_pPCAP, unsigned char* p_pcData, size_t p_nSize,
	bool p_bDataSent, uint32_t p_sSrcIP, uint32_t p_sDstIP, uint16_t p_nSrcPort, uint16_t p_nDstPort)
{
	ip_header_t  ipHeader;
	tcp_header_t tcpHeader;
	unsigned char* pData = NULL;
	uint32_t seq = 0, ack = 0;

	// Packet tracker

	PacketTracker def;
	PacketTracker* p = GetPacketTracker(p_pPCAP, p_bDataSent, p_sSrcIP, p_sDstIP, p_nSrcPort, p_nDstPort);
	if (p == NULL) p = &def;

	// Get SEQ and ACK

	if (p_bDataSent)
	{
		seq = p->nSeq;
		ack = p->nAck;
	}
	else
	{
		seq = p->nAck;
		ack = p->nSeq;
	}

	// Set up IP header

	ipHeader.ver_ihl = 0x45;
	ipHeader.tos = 0;
	ipHeader.total_length = HTONS((uint16_t)(p_nSize + PACKET_HEADER_SIZE));
	ipHeader.id = 0;
	ipHeader.flags_fo = HTONS(0x4000);
	ipHeader.ttl = 0xFF;
	ipHeader.protocol = 6;
	ipHeader.checksum = 0;

	// IP addresses and TCP ports

	if (!p_bDataSent)
	{
		ipHeader.src_addr = p_sDstIP;
		ipHeader.dst_addr = p_sSrcIP;
		tcpHeader.src_port = HTONS((uint16_t)p_nDstPort);
		tcpHeader.dst_port = HTONS((uint16_t)p_nSrcPort);
	}
	else
	{
		ipHeader.src_addr = p_sSrcIP;
		ipHeader.dst_addr = p_sDstIP;
		tcpHeader.src_port = HTONS((uint16_t)p_nSrcPort);
		tcpHeader.dst_port = HTONS((uint16_t)p_nDstPort);
	}

	// Set up TCP header

	tcpHeader.seq = HTONL(seq);
	tcpHeader.ack = HTONL(ack);

	if (p_bDataSent) tcpHeader.len_and_flags = HTONS(0x5018);
	else tcpHeader.len_and_flags = HTONS(0x5010);

	tcpHeader.window_size = 0xFFFF;
	tcpHeader.checksum = 0;
	tcpHeader.urgent_p = 0;

	// Update SEQ and ACK

	if (p_bDataSent) p->nSeq += (uint32_t)p_nSize;
	else p->nAck += (uint32_t)p_nSize;

	// Create packet

	pData = new unsigned char[sizeof(ipHeader) + sizeof(tcpHeader) + (uint16_t)p_nSize];
	memcpy(pData, (void*)&ipHeader, sizeof(ipHeader));
	memcpy(pData + sizeof(ipHeader), (void*)&tcpHeader, sizeof(tcpHeader));
	memcpy(pData + sizeof(ipHeader) + sizeof(tcpHeader), (void*)p_pcData, (uint16_t)p_nSize);

	return pData;
}

// Create packet header

pcaprec_hdr_s CreatePacketHeader(size_t nLength)
{
	pcaprec_hdr_s header;
	SYSTEMTIME t;
	GetSystemTime(&t);

	// Create header

	header.ts_sec = (uint32_t)time(NULL);
	header.ts_usec = (uint32_t)(t.wMilliseconds * 1000);
	header.incl_len = (uint32_t)(nLength + 40);
	header.orig_len = (uint32_t)(nLength + 40);

	return header;
}

// Write a packet's data

void PCAP_WritePacketData(PCAPFile* p_pPCAP, string p_sFilename, unsigned char* p_pcData, size_t p_nSize, bool p_bDataSent,
	uint32_t p_sSrcIP, uint32_t p_sDstIP, uint16_t p_nSrcPort, uint16_t p_nDstPort)
{
	// Packet header 

	pcaprec_hdr_s pheader = CreatePacketHeader(p_nSize);
	Utils_WriteToTempFile(p_sFilename, (unsigned char*)&pheader, sizeof(pheader));

	// Write packet data

	unsigned char* pData = CreatePacket(p_pPCAP, p_pcData, p_nSize, p_bDataSent, p_sSrcIP, p_sDstIP, p_nSrcPort, p_nDstPort);
	Utils_WriteToTempFile(p_sFilename, pData, sizeof(ip_header_t) + sizeof(tcp_header_t) + (uint16_t)p_nSize);
	delete[] pData;
}

void PCAP_WriteData(string p_sFilename, unsigned char* p_pcData, size_t p_nSize, bool p_bDataSent,
	uint32_t p_sSrcIP, uint32_t p_sDstIP, uint16_t p_nSrcPort, uint16_t p_nDstPort)
{
	PCAPFile* pcap = GetPCAP(p_sFilename, p_bDataSent, p_sSrcIP, p_sDstIP, p_nSrcPort, p_nDstPort);
	size_t size_counter = (size_t)(p_nSize / MAX_PACKET_SIZE);
	size_t size_rest = (size_t)(p_nSize % MAX_PACKET_SIZE);

	EnterCriticalSection(&pcap->oCriticalSection);

	// Write pcap header (if not written)

	if (pcap->bHeaderWritten == false) PCAP_WriteHeader(pcap);

	// Write by using maximum 65535 bytes in a packet

	for (size_t i = 0; i < size_counter; i++)
		PCAP_WritePacketData(pcap, p_sFilename, (unsigned char*)(p_pcData + i * MAX_PACKET_SIZE), MAX_PACKET_SIZE, p_bDataSent, p_sSrcIP, p_sDstIP, p_nSrcPort, p_nDstPort);

	if (size_rest) PCAP_WritePacketData(pcap, p_sFilename, (unsigned char*)(p_pcData + size_counter * MAX_PACKET_SIZE), size_rest, p_bDataSent, p_sSrcIP, p_sDstIP, p_nSrcPort, p_nDstPort);

	LeaveCriticalSection(&pcap->oCriticalSection);
}

// Will process read data and save it to a file

void PluginSystem_ProcessAndSaveRead(string p_sFilename, unsigned char* p_pcData, unsigned int p_nSize, unsigned int p_nSocket)
{
	if (p_pcData == NULL || p_nSize == 0) return;

	PLUGIN_DATA ret = PluginSystem_ProcessReadData(p_pcData, p_nSize);

	if (ret.size > 0)
	{
		if (p_nSocket)
		{
			IPInfo ip = Utils_GetIPInfo(p_nSocket);
			PCAP_WriteData(p_sFilename, ret.data, ret.size, false, ip.nSrcIP, ip.nDstIP, ip.nSrcPort, ip.nDstPort);
		}
		else PCAP_WriteData(p_sFilename, ret.data, ret.size, false);
	}
	if (ret.data != p_pcData) delete[] ret.data;
}

PLUGIN_DATA PluginSystem_ProcessReadData(unsigned char* p_pcData, unsigned int p_nSize)
{
	PLUGIN_DATA ret;
	unsigned char* p = NULL;

	ret.data = p_pcData;
	ret.size = p_nSize;

	if (p_pcData == NULL || p_nSize == 0) return ret;

	// Iterate through plugins

	for (size_t i = 0; i < s_vPlugins.size(); i++)
	{
		p = ret.data;
		ret = s_vPlugins[i]->ProcessReadData(ret.data, ret.size);
		if (i != 0 && ret.data != p) delete[] p;
	}

	return ret;
}

string Utils_IntToString(unsigned int p_nNumer)
{
	string sResult = "";
	ostringstream ss;

	ss << p_nNumer;
	sResult = ss.str();

	return sResult;
}
// Get filename: PID_processname_filename

string Utils_GetFilename(string p_sFilename)
{
	char pcBuffer[MAX_TEMP_PATH] = { 0 };
	string sResult = "";

	// Get module name

	sResult = Utils_IntToString(GetCurrentProcessId());
	sResult += "_";

	if (GetModuleFileNameA(NULL, pcBuffer, MAX_TEMP_PATH) == 0)
	{
		sync_write_log_sslhook("[ERROR] Cannot get current module name!");
		sResult += "NetRipper.txt";
	}
	else
	{
		// Get filename only

		string sFullPath = pcBuffer;

		size_t i = sFullPath.find_last_of('\\');
		if (i != string::npos)
			sFullPath = sFullPath.substr(i + 1);

		sResult += sFullPath;
	}

	// Add filename

	sResult += "_";
	sResult += p_sFilename;

	return sResult;
}