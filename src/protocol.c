#include "snt_protocol_func.h"
#include "snt_debug.h"
#include "snt_log.h"
#include <snt_compression.h>
#include <snt_encryption.h>
#include <snt_protocol.h>
#include <snt_utility.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <time.h>


const char* gs_symprotocol[] = {
		"Undefined",	/*0x0*/
		"Init",
		"ClientOption",
		"Certificate",
		"Secure",
		"Ready",
		"Start",
		"Error",
		"Benchmark",
		"Result",
		"DHReq",
		"DHInit",
		"DHExch",
		NULL
};

const char* gs_sym_cert[] = {
		"",
		"rsa",
		"ec",
		"x509",
		NULL
};

const char* gs_sym_duplex[] = {
		"",
		"simple",
		"half",
		"full",
		NULL
};

const char* gs_sym_transport[] = {
	"",
	"tcp",
	"udp",
	NULL
};

const char* gs_delta_sym[] = {
		"",
		"float",
		"int",
		"time",
		"hrestime",
		"double",
		NULL
};

const char* gs_error_sym[] = {
		"No error",
		"Invalid argument",
		"Signature failed",
		"Server error",
		"incompatible version",
		"SSL not supported",
		"Bad request",
		"Service unavailable",
		"Cipher not supported",
		"Benchmark mode not supported",
		"Diffie hellman not supported",
		NULL
};

void sntGetInterfaceAttr(SNTConnection* connection){

	struct ifreq ifr;				/*	*/
	struct ifconf ifcon;			/*	*/
	struct ifreq* ifcr;				/*	*/
	socklen_t aclen;				/*	*/

	char sockbuf[128];				/*	*/
	union{
		struct sockaddr_in addr4;	/*	*/
		struct sockaddr_in6 addr6;	/*	*/
	}addrU;
	struct sockaddr_in* sockaddr;	/*	*/
	struct sockaddr* addr;			/*	*/

	assert(connection->tcpsock > 0);

	/*	*/
	memset(&ifr, 0, sizeof(ifr));
	memset(&ifcon, 0, sizeof(ifcon));
	sockaddr = (struct sockaddr_in*)sockbuf;
	aclen = sizeof(sockbuf);

	/*	Get interface list associated with the socket.	*/
	if(ioctl(connection->tcpsock, SIOCGIFCONF, &ifcon) < 0){
		sntLogErrorPrintf("ioctl %s.\n", strerror(errno));
	}

	/*	*/
	if(ifcon.ifc_len > 0 && ifcon.ifc_ifcu.ifcu_req != NULL){

		ifcr = ifcon.ifc_ifcu.ifcu_req;
		ifr.ifr_ifru.ifru_ivalue = ifcr->ifr_ifru.ifru_ivalue;
		/*
		memcpy(&ifr.ifr_ifrn.ifrn_name[0],
				&ifcr->ifr_ifrn.ifrn_name[0], IFNAMSIZ);
		*/
		if(ioctl(connection->tcpsock, SIOCGIFMTU, &ifr) < 0){
			sntLogErrorPrintf("ioctl %s.\n", strerror(errno));
		}
		connection->mtu = ifr.ifr_ifru.ifru_mtu;
		printf("%d.+n", connection->mtu);
	}

	/*	TODO add support for IPV4 and IPV6.	*/

	/*	Get port used by socket on the host.	*/
	if(getsockname(connection->tcpsock, (struct sockaddr*)sockaddr, &aclen) != 0){
		sntLogErrorPrintf("getsockname failed, %s.\n", strerror(errno));
	}
	memcpy(connection->ip, inet_ntoa(sockaddr->sin_addr), strlen(inet_ntoa(sockaddr->sin_addr)) + 1);
	connection->port = ntohs(sockaddr->sin_port);

	/*	Get external port on the connected host.	*/
	if(getpeername(connection->tcpsock, (struct sockaddr *)sockaddr, &aclen) != 0){
		sntLogErrorPrintf("getpeername failed, %s.\n", strerror(errno));
	}
	memcpy(connection->extipv, inet_ntoa(sockaddr->sin_addr), strlen(inet_ntoa(sockaddr->sin_addr)) + 1);
	connection->externalport = ntohs(sockaddr->sin_port);

	/*	Set socket address size in bytes.	*/
	connection->sclen = aclen;

	/*	Socket address for UDP.	*/
	connection->extaddr = (struct sockaddr*)malloc(connection->sclen);
	connection->intaddr = (struct sockaddr*)malloc(connection->sclen);
	assert(connection->extaddr);
	assert(connection->intaddr);

	/*	zero out.	*/
	memset(connection->extaddr, 0, connection->sclen);
	memset(connection->intaddr, 0, connection->sclen);

	/*	Create socket address.	*/
	switch(connection->option->affamily){
	case AF_INET:

		bzero(&addrU.addr4, sizeof(addrU.addr4));
		addrU.addr4.sin_port = htons((uint16_t)connection->externalport);
		addrU.addr4.sin_family = (sa_family_t)connection->option->affamily;
		addrU.addr4.sin_addr.s_addr = inet_addr(connection->extipv);

		addr = (struct sockaddr*)&addrU.addr4;

		addrU.addr4.sin_port = htons((uint16_t)connection->externalport);
		memcpy(connection->extaddr, addr, connection->sclen);
		addrU.addr4.sin_port = htons((uint16_t)connection->port);
		memcpy(connection->intaddr, addr, connection->sclen);

		break;
	case AF_INET6:
		bzero(&addrU.addr6, sizeof(addrU.addr6));
		addrU.addr6.sin6_port = htons((uint16_t)connection->externalport);
		addrU.addr6.sin6_family = (sa_family_t)connection->option->affamily;
		//addr4.sin_addr.s_addr = inet_netof(connection->extipv);
		/*addr6.sin6_addr.__in6_u = IN6ADDR_ANY_INIT;*/
		connection->sclen = sizeof(addrU.addr6);
		addr = (struct sockaddr*)&addrU.addr6;

		addrU.addr6.sin6_port = htons((uint16_t)connection->externalport);
		memcpy(connection->extaddr, addr, connection->sclen);
		addrU.addr6.sin6_port = htons((uint16_t)connection->port);
		memcpy(connection->intaddr, addr, connection->sclen);

		break;
	default:
		break;
	}

	/*	Allocate transmission and receive buffer.	*/
	connection->tranbuf = malloc(1 << 16);
	assert(connection->tranbuf);
	connection->recvbuf = malloc(1 << 16);
	assert(connection->recvbuf);

	/*	Allocate payload.	*/
	connection->mtubuf = malloc(
	        connection->option->payload + sizeof(SNTPacketHeader)
	                + sizeof(SNTPresentationPacket));
	assert(connection->mtubuf);

}

SNTConnection* sntBindSocket(const char* ip, uint16_t port,
		const SNTConnectionOption* option) {

	SNTConnection* connection = NULL;	/*	*/
	socklen_t addrlen;					/*	*/
	struct sockaddr* addr;				/*	*/
	union{
		struct sockaddr_in addr4;		/*	*/
		struct sockaddr_in6 addr6;		/*	*/
	}addrU;
	int domain = option->affamily;

	/*	Create connection.	*/
	connection = sntPoolObtain(g_connectionpool);
	assert(connection);

	/*	Create socket.	*/
	sntConnectionCopyOption(connection, option);
	if(!sntInitSocket(connection, domain, connection->option->transport_mode  | SNT_TRANSPORT_TCP)){
		return 0;
	}

	/*	*/
	if(domain == AF_INET){
		bzero(&addrU.addr4, sizeof(addrU.addr4));
		addrU.addr4.sin_port = htons(port);
		addrU.addr4.sin_family = (sa_family_t)domain;
		if( inet_pton(domain, ip, &addrU.addr4.sin_addr) < 0){
			sntDisconnectSocket(connection);
			return NULL;
		}
		addrlen = sizeof(addrU.addr4);
		addr = (struct sockaddr*)&addrU.addr4;
	}
	else if(domain == AF_INET6){
		bzero(&addrU.addr6, sizeof(addrU.addr6));
		addrU.addr6.sin6_port = htons(port);
		addrU.addr6.sin6_family = (sa_family_t)domain;
		if( inet_pton(domain, ip, &addrU.addr6.sin6_addr) < 0){
			sntDisconnectSocket(connection);
			return NULL;
		}
		addrlen = sizeof(addrU.addr6);
		addr = (struct sockaddr*)&addrU.addr6;
	}else{
		sntLogErrorPrintf("Invalid address family.\n");
		sntDisconnectSocket(connection);
		return NULL;
	}

	/*	Bind process to socket.	*/
	if( bind(connection->tcpsock, (struct sockaddr *)addr, addrlen) < 0){
		sntLogErrorPrintf("Failed to bind TCP socket, %s.\n", strerror(errno));
		sntDisconnectSocket(connection);
		return NULL;
	}

	/*	Bind UDP socket to process. Optional.	*/
	if(connection->udpsock > 0){
		if( bind(connection->udpsock, (struct sockaddr *)addr, addrlen) < 0){
			sntLogErrorPrintf("Failed to bind UDP socket, %s.\n", strerror(errno));
			sntDisconnectSocket(connection);
			return NULL;
		}
	}

	/*	Listen.	*/
	if( listen(connection->tcpsock, option->listen) < 0){
		sntLogErrorPrintf("listen failed, %s.\n", strerror(errno));
		sntDisconnectSocket(connection);
		return NULL;
	}

	/*	Get attribute about connection interface.	*/
	sntGetInterfaceAttr(connection);

	/*	*/
	return connection;
}

SNTConnection* sntAcceptSocket(SNTConnection* bindcon){

	SNTConnection* connection = NULL;	/*	*/
	socklen_t aclen = 0;				/*	*/
	struct sockaddr tobuffer;			/*	*/
	SNTInitPackage init;				/*	*/
	struct timeval tv;					/*	*/

	/*	Allocate connection.	*/
	connection = (SNTConnection*)sntPoolObtain(g_connectionpool);
	if(connection == NULL){
		sntPoolResize(g_connectionpool, sntPoolNumNodes(g_connectionpool) * 2, sizeof(SNTConnection));
		connection = (SNTConnection*)sntPoolObtain(g_connectionpool);
	}
	sntConnectionCopyOption(connection, bindcon->option);

	/*	Accept incoming connection and get file descriptor.	*/
	connection->tcpsock = accept(bindcon->tcpsock, &tobuffer, &aclen);
	if( connection->tcpsock < 0 ){
		sntLogErrorPrintf("Failed to accept, %s.\n", strerror(errno));
		sntDisconnectSocket(connection);
		return NULL;
	}

	/*	Set timeout for client.	*/
	tv.tv_sec = 10;
	tv.tv_usec = 0;
	if(setsockopt(connection->tcpsock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0){
		sntLogErrorPrintf("setsockopt failed, %s.\n", strerror(errno));
		sntDisconnectSocket(connection);
		return NULL;
	}

	/*	Get attribute about connection interface.	*/
	sntGetInterfaceAttr(connection);

	/**/
	connection->udpsock = dup(bindcon->udpsock);
	/*	Set timeout for client.	*/
	if(setsockopt(connection->udpsock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0){
		sntLogErrorPrintf("setsockopt failed, %s.\n", strerror(errno));
		sntDisconnectSocket(connection);
		return NULL;
	}

	/*	Create init packet to send to client.	*/
	sntInitDefaultHeader(&init.header, SNT_PROTOCOL_STYPE_INIT, sizeof(init));
	init.ssl = connection->option->ssl;
	init.symchiper = connection->symchiper * ( connection->option->ssl ? 1 : 0 );
	init.mode = connection->option->bm_protocol_mode;
	init.compression = connection->option->compression;
	init.asymchiper = connection->option->asymmetric * ( connection->option->ssl ? 1 : 0 );
	init.inetbuffer = (unsigned int)connection->mtu;
	init.transmode = connection->option->transport_mode;
	init.extension = 0;
	init.deltaTypes = connection->option->deltatype;
	init.duplex = connection->option->duplex;
	if(sntWriteSocketPacket(connection, (SNTUniformPacket*)&init) <= 0){
		sntLogErrorPrintf("Failed to write to client, %s.\n", strerror(errno));
		sntDisconnectSocket(connection);
		return NULL;
	}

	return connection;
}

SNTConnection* sntConnectSocket(const char* host, uint16_t port,
		const SNTConnectionOption* option) {

	SNTConnection* connection = NULL;	/*	*/
	socklen_t addrlen;					/*	*/
	const struct sockaddr* addr;		/*	*/
	union{
		struct sockaddr_in addr4;		/*	*/
		struct sockaddr_in6 addr6;		/*	*/
	}addrU;
	struct hostent* hosten = NULL;		/*	*/
	int domain;
	struct timeval tv;					/*	*/

	/*	*/
	connection = sntPoolObtain(g_connectionpool);
	assert(connection);

	/*  */
	sntConnectionCopyOption(connection, option);
	domain = option->affamily;

	/*	Get IP from hostname.	*/
	hosten = gethostbyname(host);
	if(hosten == NULL){
		sntDebugPrintf("Couldn't find IP address for host %s.\n", host);
	}else{
		domain = hosten->h_addrtype;
	}

	/*	Create socket.	*/
	if(sntInitSocket(connection, domain, option->transport_mode | SNT_TRANSPORT_TCP) == 0){
		sntDisconnectSocket(connection);
		sntLogErrorPrintf("Failed to create socket, %s.\n", strerror(errno));
		return NULL;
	}

	/*	Assign address struct.	*/
	if(domain == AF_INET){
		bzero(&addrU.addr4, sizeof(addrU.addr4));
		addrU.addr4.sin_family = (sa_family_t)domain;
		addrU.addr4.sin_port = htons(port);
		if(hosten){
			memcpy(&addrU.addr4.sin_addr, *hosten->h_addr_list, hosten->h_length);
		}else{
			if( inet_pton(domain, host, &addrU.addr4.sin_addr) < 0){
				sntDisconnectSocket(connection);
				return NULL;
			}
		}
		addrlen = sizeof(addrU.addr4);
		addr = (const struct sockaddr*)&addrU.addr4;
	}
	else if(domain == AF_INET6){
		bzero(&addrU.addr6, sizeof(addrU.addr6));
		addrU.addr6.sin6_port = htons(port);
		addrU.addr6.sin6_family = (sa_family_t)domain;
		if( inet_pton(domain, host, &addrU.addr6.sin6_addr) < 0){
			sntDisconnectSocket(connection);
			return NULL;
		}
		addrlen = sizeof(addrU.addr6);
		addr = (const struct sockaddr*)&addrU.addr6;
	}else{
		sntLogErrorPrintf("Invalid address family.\n");
		sntDisconnectSocket(connection);
		return NULL;
	}

	/*	Establish connection.	*/
	sntVerbosePrintf("Connecting to %s:%d.\n", host, port);
	if( connect(connection->tcpsock, addr, addrlen) < 0){
		sntLogErrorPrintf("Failed to connect TCP, %s.\n", strerror(errno));
		sntDisconnectSocket(connection);
		return NULL;
	}

	/*	Get attribute about connection interface.	*/
	sntGetInterfaceAttr(connection);


	/*	Create UDP if UDP is used, optional.	*/
	if(connection->udpsock > 0){
		if( bind(connection->udpsock, connection->intaddr, addrlen) < 0){
			sntLogErrorPrintf("Failed to connect UDP, %s.\n", strerror(errno));
			sntDisconnectSocket(connection);
			return NULL;
		}

		/*	Set timeout for client.	*/
		tv.tv_sec = 10;
		tv.tv_usec = 0;
		if(setsockopt(connection->udpsock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0){
			sntLogErrorPrintf("setsockopt failed, %s.\n", strerror(errno));
			sntDisconnectSocket(connection);
			return NULL;
		}
	}
	return connection;
}

void sntDisconnectSocket(SNTConnection* connection){

	/*	Print disconnected.	*/
	sntVerbosePrintf("Disconnecting %s:%d from %s:%d.\n", connection->ip,
			connection->port, connection->extipv, connection->externalport);

	/*	Close socket connection.	*/
	if(connection->tcpsock > 0){
		close(connection->tcpsock);
	}
	if(connection->udpsock > 0){
		close(connection->udpsock);
	}

	/*	Release encryption. */
	sntASymFree(connection);
	sntSymFree(connection);

	/*	Release memories. */
	free(connection->option);
	free(connection->extaddr);
	free(connection->mtubuf);
	free(connection->recvbuf);
	free(connection->tranbuf);
	free(connection->session);

	/*	Clean up memory.	*/
	sntPoolReturn(g_connectionpool, connection);
}

void sntConnectionCopyOption(SNTConnection* connection, const SNTConnectionOption* option){
	if(!connection->option){
		connection->option = malloc(sizeof(SNTConnectionOption));
	}
	memcpy(connection->option, option, sizeof(SNTConnectionOption));
}


int sntInitSocket(SNTConnection* connection, int affamily,
		unsigned int protocol){

	assert(protocol > 0 && affamily > 0);

	/*	Create socket if not already created.	*/
	if( (protocol & SNT_TRANSPORT_TCP) && connection->tcpsock == 0){
		sntDebugPrintf("Create stream socket.\n");
		connection->tcpsock = socket(affamily, SOCK_STREAM, 0);
		if(connection->tcpsock < 0){
			sntLogErrorPrintf("Failed to create socket, %s.\n", strerror(errno));
			return 0;
		}
	}
	if( (protocol & SNT_TRANSPORT_UDP ) && connection->udpsock == 0){
		sntDebugPrintf("Create datagram socket.\n");
		connection->udpsock = socket(affamily, SOCK_DGRAM, IPPROTO_UDP);
		if(connection->udpsock < 0){
			sntLogErrorPrintf("Failed to create socket, %s.\n", strerror(errno));
			return 0;
		}
	}
	return 1;
}

int sntSetTransportProcotcol(SNTConnection* connection, unsigned int protocol){

	assert(protocol > 0 && connection->option->affamily > 0);

	/*	Create socket if not already created.	*/
	if( (protocol & SNT_TRANSPORT_TCP)){
		if(connection->tcpsock <= 0){
			connection->tcpsock = socket(connection->option->affamily, SOCK_STREAM, 0);
			if(connection->tcpsock < 0){
				sntLogErrorPrintf("Failed to create socket, %s.\n", strerror(errno));
				return 0;
			}
		}
	}else{
		/*		*/
	}
	if( protocol & SNT_TRANSPORT_UDP ){
		if(connection->udpsock <= 0){
			connection->udpsock = socket(connection->option->affamily, SOCK_DGRAM, 0);
			if(connection->udpsock < 0){
				sntLogErrorPrintf("Failed to create socket, %s.\n", strerror(errno));
				return 0;
			}
		}
	}else{
		/*		*/
	}

	/*	*/
	connection->option->transport_mode = protocol;

	return 1;
}

unsigned int sntCreateSendPacket(const SNTConnection* connection, void* buffer,
		unsigned int buflen, SNTPresentationUnion* __restrict__ pres) {

	unsigned int size;			/*	*/
	unsigned char buf[4096];	/*	*/
	unsigned char* sou;			/*	*/
	unsigned char* des;			/*	*/

	/*	Don't modify packet if no encryption or compression.	*/
	if ((!sntIsConnectionSecure(connection)
			&& !sntIsConnectionCompressed(connection))
			|| buflen == 0) {
		return buflen;
	}

	size = buflen;
	sou = buffer;
	des = buf;

	/*	*/
	if(connection->symchiper && connection->usecompression){
		size = sntSymEncrypt(connection, sou, des, size, pres->iv.iv, &pres->iv.iv[pres->iv.len]);
		pres->offset.noffset = (uint8_t)(size - buflen);
		sntSwapPointer((void**)&des, (void**)&sou);
		size = sntDeflate(connection->usecompression, (const char*)sou, (char*)des,
						sntSymTotalBlockSize(size, connection->blocksize));
		return size;
	}
	else{
		/*	Compress.	*/
		if(connection->usecompression){
			size = sntDeflate(connection->usecompression, (const char*)sou, (char*)des, size);
		}
		/*	Encryption.	*/
		if(connection->symchiper){
			size = sntSymEncrypt(connection, sou, des, size, pres->iv.iv, &pres->iv.iv[pres->iv.len]);
			pres->offset.noffset = size - buflen;
		}

		memcpy(buffer, des, size);
		return size;
	}
}

unsigned int sntCreateRecvPacket(const SNTConnection* connection, void* buffer,
		unsigned int buflen, SNTPresentationUnion* __restrict__ pres) {

	unsigned int size;			/*	*/
	unsigned char buf[4096];	/*	*/
	unsigned char* sou;			/*	*/
	unsigned char* des;			/*	*/

	/*	Check if needed to do anything. */
	if ((!sntIsConnectionSecure(connection)
			&& !sntIsConnectionCompressed(connection))
			|| buflen == 0) {
		return buflen;
	}

	/*	*/
	size = buflen;
	sou = buffer;
	des = buf;

	if(connection->symchiper && connection->usecompression){
		size = sntInflate(connection->usecompression, (const char*)sou, (char*)des, size);
		sntSwapPointer((void**)&sou, (void**)&des);
		size = sntSymDecrypt(connection, sou, des, size, pres->iv.iv, &pres->iv.iv[pres->iv.len]);
		size -= pres->offset.noffset;
		return size;
	}
	else{
		/*	Decrypt.	*/
		if(connection->symchiper){
			sntDebugPrintf("Receiving encrypted data, %d.\n", size);
			size = sntSymDecrypt(connection, sou, des, size, pres->iv.iv, &pres->iv.iv[pres->iv.len]);
			size -= pres->offset.noffset ;
		}
		/*	Decompress.	*/
		if(connection->usecompression){
			size = sntInflate(connection->usecompression, (const char*)sou, (char*)des, size);
			sntDebugPrintf("Receiving compressed data, %d:%d.\n", buflen, size);
		}

		memcpy(buffer, des, size);
		return size;
	}
}

int sntReadSocket(const SNTConnection* connection, void* buffer,
		unsigned int recvlen, int flag) {
	if(recvlen > 0){
		if(connection->flag & SNT_CONNECTION_TRANS){
			int len;
			switch(connection->option->transport_mode){
			case SNT_TRANSPORT_TCP:
				assert(connection->tcpsock > 0);
				return recv(connection->tcpsock, buffer, recvlen, flag);
			case SNT_TRANSPORT_UDP:
				assert(connection->udpsock > 0);
				len = connection->sclen;
				return recvfrom(connection->udpsock, buffer, recvlen, flag,
						connection->intaddr, &len);
			default:
				break;
			}
		}
		else{
			assert(connection->tcpsock > 0);
			return recv(connection->tcpsock, buffer, (size_t)recvlen, flag);
		}
	}
	return 0;
}

int sntWriteSocket(const SNTConnection* connection, const void* buffer,
		unsigned int senlen, int flag) {
	if(connection->flag & SNT_CONNECTION_TRANS){
		switch(connection->option->transport_mode){
		case SNT_TRANSPORT_TCP:
			assert(connection->tcpsock > 0);
			return send(connection->tcpsock, buffer, senlen, flag);
		case SNT_TRANSPORT_UDP:
			assert(connection->udpsock > 0);
			return sendto(connection->udpsock, buffer, senlen, flag,
					connection->extaddr, connection->sclen);
		default:
			break;
		}
	}
	else{
		assert(connection->tcpsock > 0);
		return send(connection->tcpsock, buffer, senlen, flag);
	}
	return 0;
}

int sntWriteSocketPacket(const SNTConnection* connection,
		const SNTUniformPacket* pack) {

	int translen = 0;
	SNTUniformPacket* tranpack;
	SNTPresentationUnion* pres;

	assert(pack);

	/*	Set flag of packet.	*/
	tranpack = (SNTUniformPacket*)connection->tranbuf;

	/*	Copy and set flag.	*/
	sntCopyHeader(&tranpack->header, &pack->header);
	tranpack->header.flag = (uint8_t)(
			(sntIsConnectionSecure(connection) ? SNT_PACKET_ENCRYPTION : 0)
			| (sntIsConnectionCompressed(connection) ? SNT_PACKET_COMPRESSION : 0)
			| (sntSymNeedIV(connection->symchiper) ? SNT_PACKET_IV_ENCRYPTION : 0)
			| (sntSymdNeedFB(connection->symchiper) ? SNT_PACKET_FB_ENCRYPTION : 0));

	/*	Update header if using encryption.	*/
	if(sntPacketHasEncrypted(tranpack->header)){
		tranpack->header.offset++;
		tranpack->header.len++;
	}

	/*	Update header if IV is used.	*/
	if(sntPacketHasIV(tranpack->header)){
		tranpack->header.offset += sntSymBlockSize(connection->symchiper) + 1;
		tranpack->header.len  += sntSymBlockSize(connection->symchiper) + 1;
		pres = (SNTPresentationUnion*)&tranpack->presentation;
		pres->iv.len = sntSymBlockSize(connection->symchiper);
	}

	/*	Check if feedback is used.	*/
	if(sntPacketHasFB(tranpack->header)){
		tranpack->header.offset += sizeof(SNTPresentationFeedbackPacket);
		tranpack->header.len += sizeof(SNTPresentationFeedbackPacket);
	}

	/*	Copy packet payload.	*/
	sntCopyPacketPayload((void*)&tranpack->totalbuf[sntProtocolHeaderSize(tranpack)],
			sntDatagramGetBlock(pack), sntProtocolHeaderDatagramSize(pack));

	/*	Construct the packet.	*/
	translen = sntCreateSendPacket(connection, sntDatagramGetBlock(tranpack),
			sntProtocolHeaderDatagramSize(&tranpack->header),
			(SNTPresentationUnion*)&tranpack->presentation);

	/*	Update header.	*/
	tranpack->header.len = translen + sntProtocolHeaderSize(&tranpack->header);

	sntDebugPrintf("Sending.\n");
	sntPrintPacketInfo(tranpack);
	translen = sntWriteSocket(connection, &tranpack->header,
			sntProtocolHeaderSize(&tranpack->header), MSG_MORE);
	return translen
			+ sntWriteSocket(connection, sntDatagramGetBlock(tranpack),
					sntProtocolHeaderDatagramSize(&tranpack->header), 0);
}

int sntReadSocketPacket(const SNTConnection* connection, SNTUniformPacket* pack) {

	int len;
	/*	Receive header.	*/
	sntDebugPrintf("Receiving.\n");
	len = sntPeekPacketHeader(connection, &pack->header);
	if(len <= 0){
		return 0;
	}
	len = sntProtocolHeaderSize(&pack->header);

	/*	Receiving body datagram.	*/
	if (sntReadSocket(connection, pack,
			sntProtocolPacketSize(&pack->header), 0)
			!= sntProtocolPacketSize(&pack->header)) {
		return 0;
	}

	/*	Copy to buffer.	*/
	len += sntCreateRecvPacket(connection, sntDatagramGetBlock(pack),
			sntProtocolHeaderDatagramSize(&pack->header),
			(SNTPresentationUnion*) &pack->presentation);

	/*	Update size.	*/
	pack->header.len = (uint16_t)len;

	/*	*/
	sntPrintPacketInfo(pack);
	return len;
}

int sntPeekPacketHeader(const SNTConnection* connection,
		SNTUniformPacket* header) {
	return sntReadSocket(connection, header, sizeof(SNTPacketHeader), MSG_PEEK);
}

void sntDropPacket(const SNTConnection* connection){
	char buf[1024];
	while(sntReadSocket(connection, buf, sizeof(buf), 0) == sizeof(buf));
}

void sntCopyHeader(SNTPacketHeader* dest, const SNTPacketHeader* source){
	memcpy(dest, source, sizeof(SNTPacketHeader));
}

void sntCopyPacket(SNTUniformPacket* dest, const SNTUniformPacket* source){
	memcpy(dest, source, source->header.len);
}

void sntInitDefaultHeader(SNTPacketHeader* header, unsigned int command,
		unsigned int len) {

	assert(header);

	header->version = SNT_VERSION;
	header->offset = sizeof(SNTPacketHeader);
	header->stype = (uint8_t)command;
	header->len = (uint16_t)len;
	header->flag = 0;
}
void sntInitHeader(SNTPacketHeader* header, unsigned int command,
		unsigned int buffer){
	sntInitDefaultHeader(header, command, buffer + sizeof(SNTPacketHeader));
}

unsigned int sntProtocolPacketSize(const SNTPacketHeader* header){
	return header->len;
}
unsigned int sntProtocolHeaderDatagramSize(const SNTPacketHeader* header){
	return (unsigned int)header->len - (unsigned int)header->offset;
}

unsigned int sntProtocolHeaderSize(const SNTPacketHeader* header){
	return header->offset;
}

void* sntDatagramGetBlock(SNTUniformPacket* packet){
	return &packet->totalbuf[packet->header.offset];
}
