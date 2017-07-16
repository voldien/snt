/**
	Simple network benchmark tool.
    Copyright (C) 2017  Valdemar Lindberg

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/
#ifndef _SNT_PROTOCOL_H_
#define _SNT_PROTOCOL_H_ 1
#include"snt_def.h"
#include"snt_hash.h"
#include"snt_compression.h"
#include"snt_encryption.h"
#include"snt_pool.h"
#include"snt.h"
#include"snt_benchmark.h"
#include"snt_utility.h"
#include"snt_delta.h"
#include<sys/socket.h>

/**
 *	Protocol sequence diagram.
 *
 *		Client          Server
 *		  | ->	connec -> |
 *		  |               |
 *		  | <-	init   <- |
 *		  |               |
 *		  | ->	cliopt -> |
 *		  |               |
 *		 [[ <-	certi  <- ]]
 *		 [[               ]]	Optional.
 *		 [[ ->	symm  ->  ]]
 *		  |               |
 *		  | <-	ready  <- |
 *		  |               |
 *		  | ->	start  -> |
 *		  |               |
 *		 [.               .]
 *		 [.   benchmark   .]	Execution based
 *		 [.               .]	on benchmark mode.
 *		  |      end      |
 *		  ^^^^^^^^^^^^^^^^^
 *
 *	The error code message command can be
 *	sent at any point of the sequence of
 *	the diagram.
 */

/**
 *	Constants.
 */
#define SNT_DEFAULT_PORT 54321					/*	Default port.	*/

/**
 *	SNT application protocol.
 */
#define SNT_PROTOCOL_STYPE_NONE			0x0		/*	No command.	*/
#define SNT_PROTOCOL_STYPE_INIT 		0x1		/*	Initialization packet sent by server.	*/
#define SNT_PROTOCOL_STYPE_CLIENTOPT	0x2		/*	Connection option selected by the client.	*/
#define SNT_PROTOCOL_STYPE_CERTIFICATE	0x3		/*	Asymmetric cipher certificate with public key.	*/
#define SNT_PROTOCOL_STYPE_SECURE 		0x4		/*	Packet for establishing a secure connection, sent by the client. Not mandatory.	*/
#define SNT_PROTOCOL_STYPE_READY 		0x5		/*	Packet when ready for testing, sent by the server.	*/
#define SNT_PROTOCOL_STYPE_STARTTEST	0x6		/*	Start testing. Sent to client by the server.*/
#define SNT_PROTOCOL_STYPE_ERROR		0x7		/*	Error packet. Informing about the error.	*/
#define SNT_PROTOCOL_STYPE_BENCHMARK	0x8		/*	Benchmark specific packet.	*/
#define SNT_PROTOCOL_STYPE_RESULT		0x9		/*	Result from server.	*/

/**
 *	protocol symbol table used
 *	for debugging incoming packets.
 */
extern const char* gs_symprotocol[];

/**
 *	Certificate types.
 */
#define SNT_CERTIFICATE_NONE	0x0		/*	No certificate.	*/
#define SNT_CERTIFICATE_RSA		0x1		/*	RSA key certificate.	*/
#define SNT_CERTIFICATE_EC		0x2		/*	Elliptic curve key certificate.	*/
#define SNT_CERTIFICATE_X509	0x4		/*	X509 certificate standard.	*/

/**
 *	Certificate type symbol.
 */
extern const char* gs_sym_cert[];

/**
 *	Duplex mode.
 */
#define SNT_DUPLEX_NONE		0x0		/*	.	*/
#define SNT_DUPLEX_SIMPLE	0x1		/*	Transmit from single point.	*/
#define SNT_DUPLEX_HALF		0x2		/*	Transmit from between point, one at a time.	*/
#define SNT_DUPLEX_FULL		0x4		/*	Transmit and receive between the point simultaneously.*/
#define SNT_DUPLEX_ALL						\
	(SNT_DUPLEX_SIMPLE | SNT_DUPLEX_HALF	\
	| SNT_DUPLEX_ALL)						\

/**
 *	Duplex symbol table
 */
extern const char* gs_sym_duplex[];

/**
 *	Transport layer.
 */
#define SNT_TRANSPORT_NONE	0x0			/*	None transport.	*/
#define SNT_TRANSPORT_TCP	0x1			/*	TCP - Transfer control protocol, Default.	*/
#define SNT_TRANSPORT_UDP	0x2			/*	UDP - User datagram protocol.	*/
#define SNT_TRANSPORT_ALL					\
	(SNT_TRANSPORT_TCP | SNT_TRANSPORT_UDP)	\

extern const char* gs_sym_transport[];

/**
 *	Delta type used for integrity
 *	benchmark mode.
 */
#define SNT_DELTA_TYPE_FLOAT			0x1		/*	Delta presented as incremented float.	*/
#define SNT_DELTA_TYPE_INT				0x2		/*	Delta presented as incremented whole number.	*/
#define SNT_DELTA_TYPE_TIMESTAMP		0x4		/*	Delta presented in time stamp.	*/
#define SNT_DELTA_TYPE_HIGHTIMESTAMP	0x8		/*	Delta presented in high resolution time stamp.	*/
#define SNT_DELTA_TYPE_DOUBLE			0x10	/*	Delta presented as incremented double.	*/
#define SNT_DELTA_TYPE_ALL										\
	(SNT_DELTA_TYPE_FLOAT | SNT_DELTA_TYPE_INT					\
	| SNT_DELTA_TYPE_TIMESTAMP | SNT_DELTA_TYPE_HIGHTIMESTAMP	\
	| SNT_DELTA_TYPE_DOUBLE)									\

/**
 *	Delta type symbols.
 */
extern const char* gs_delta_sym[];

/**
 *	Error codes.
 */
#define SNT_ERROR_NONE						0x0	/*	No error.	*/
#define SNT_ERROR_INVALID_ARGUMENT			0x1	/*	Invalid argument.	*/
#define SNT_ERROR_SIGNATURE_FAILED			0x2	/*	Signature failed.	*/
#define SNT_ERROR_SERVER					0x3	/*	Error on the server side.	*/
#define SNT_ERROR_INCOMPATIBLE_VERSION		0x4	/*	Version not compatible.	*/
#define SNT_ERROR_SSL_NOT_SUPPORTED			0x5	/*	Secure connection is not supported.	*/
#define SNT_ERROR_COMPRESSION_NOT_SUPPORTED	0x6	/*	Specified compression algorithm not supported.	*/
#define SNT_ERROR_BAD_REQUEST				0x7	/*	Invalid application protocol command.	*/
#define SNT_ERROR_SERVICE_UNAVAILABLE		0x8	/*	Server can't provide the service.	*/
#define SNT_ERROR_CIPHER_NOT_SUPPORTED		0x9	/*	Cipher not supported.	*/
#define SNT_ERROR_BENCHMARK_NOT_SUPPORTED	0x10/*	Benchmark not supported.	*/
/**
 *	Error code symbols.
 */
extern const char* gs_error_sym[];

/**
 *	Packet flag option.
 */
#define SNT_PACKET_NONE				0x0		/*	None.	*/
#define SNT_PACKET_ENCRYPTION		0x1		/*	Packet contains encryption.	*/
#define SNT_PACKET_COMPRESSION		0x2		/*	Packet contains compression.	*/
#define SNT_PACKET_IV_ENCRYPTION	0x4		/*	Packet contains initilize vector.	*/

#define sntPacketHasEncrypted(head) (head.flag & SNT_PACKET_ENCRYPTION)
#define sntPacketHasIV(head)		(head.flag & SNT_PACKET_IV_ENCRYPTION)
#define snTPacketHasCompress(head)	(head.flag & SNT_PACKET_COMPRESSION)

/**
 *	SNT protocol header. This header will be attached
 *	to all packet with a intention of informing something.
 *	Everything except the benchmark uses the packet header.
 */
typedef struct snt_packet_header_t{
	uint16_t version;	/*	version of the protocol.	*/
	uint8_t stype;		/*	packet type.	*/
	uint8_t offset;		/*	offset from application protocol header to the payload.	*/
	uint16_t len;		/*	size of the total packet.	*/
	uint8_t flag;		/*	flag of packet type.	*/
} __attribute__ ((__packed__)) SNTPacketHeader;

/**
 *	Used for encryption. Contains negative offset
 *	of the packet size. This is used in order get the
 *	original size since all encryption is block cipher.
 *	This means the size is always a multiple of blocksize.
 *	This will remove the padding added in order perform the encryption.
 */
typedef struct snt_presentation_package_t{
	uint8_t noffset;			/*	Negative offset.	*/
} __attribute__ ((__packed__)) SNTPresentationPacket;

/**
 *	Presentation initialization vector. Used for cryptographic
 *	that uses initial vector.
 */
typedef struct snt_presentation_iv_package_t{
	uint8_t len;	/*	size of IV in bytes.	*/
	uint8_t iv[0];	/*	IV pointer only.	*/
} __attribute__ ((__packed__)) SNTPresentationIVPacket;

/**
 *
 */
typedef struct snt_presentation_union_t{
	SNTPresentationPacket offset;
	SNTPresentationIVPacket iv;
} __attribute__ ((__packed__)) SNTPresentationUnion;

/**
 *	Packet used by the server that will be
 *	the first packet a client receives.
 *
 *	Information about what the server supports and
 *	capability in order for the client.
 */
typedef struct snt_init_package_t{
	SNTPacketHeader header;		/*	Protocol header.	*/
	uint32_t ssl;				/*	Using secure connection.	*/
	uint32_t asymchiper;		/*	What asymmetric cipher is supported.	*/
	uint32_t symchiper;			/*	What asymmetric cipher is supported.	*/
	uint32_t compression;		/*	What compression is supported.	*/
	uint32_t mode;				/*	protocol mode supported.	*/
	uint32_t inetbuffer;		/*	buffer of payload in bytes.*/
	uint32_t transmode;			/*	Default transport mode.	*/
	uint32_t extension;			/*	Not supported.	*/
	uint32_t deltaTypes;		/*	Delta type supported.	*/
	uint32_t duplex;			/*	Duplex mode supported.	*/
}__attribute__ ((__packed__)) SNTInitPackage;

/**
 *	Client decided options.
 *	Send to server by the client.
 */
typedef struct snt_client_option_packet_t{
	SNTPacketHeader header;			/*	Protocol header.	*/
	uint32_t ssl;					/*	If to use a secure connection. */
	uint32_t symchiper;				/*	Symmetric cipher use.	*/
	uint32_t compression;			/*	Compression use.	*/
	uint32_t benchmode;				/*	bench mode.	*/
	uint32_t transprotocol;			/*	Transport protocol.	*/
	uint32_t deltaTypes;			/*	Delta type.	*/
	SNTDelta incdelta;				/*	Incremental delta.	*/
	uint32_t duplex;				/*	Duplex of the communication.	*/
	uint64_t invfrequency;			/*	Inverse frequency. Aka sleep between each transmission.	*/
	uint16_t payload;				/*	Payload.	*/
	uint32_t extension;				/*	Not supported.	*/
	uint64_t duration;				/*	Duration of the benchmark in nano seconds.	*/
}__attribute__ ((__packed__))SNTClientOption;

/**
 *	Packet containing certificate.
 */
typedef struct snt_certifcate_packet_t{
	SNTPacketHeader header;		/*	Protocol header.	*/
	uint8_t certype;			/*	Type of certificate.	*/
	uint32_t hashtype;			/*	Hash type.	*/
	int32_t localhashedsize;	/*	Size of */
	int32_t encryedhashsize;	/*	Size of */
	uint8_t offset;				/*	Offset of the certificate data in the packet diagram.	*/
	uint32_t asymchiper;		/*	Asymmetric cipher.	*/
	int32_t certlen;			/*	Certificate length in bytes.	*/
	uint8_t cert[1024];			/*	Certificate data.	*/
	uint8_t hash[256];			/*	Hash buffer.	*/
}__attribute__ ((__packed__))SNTCertificate;

/**
 *	Packet sent by the client to the server
 *	of what symmetric key should used between the
 *	connection.
 */
typedef struct snt_secure_establishment_packet_t{
	SNTPacketHeader header;			/*	Protocol header.	*/
	uint32_t symchiper;				/*	What symmetric cipher to use.	*/
	uint32_t keybitlen;				/*	Size of symmetric key in bits.	*/
	int32_t encrykeyblock;			/*	Size in bytes of encrypted data block.	*/
	uint8_t key[512];				/*	Encrypted symmetric Key.	*/
}__attribute__ ((__packed__))SNTSecureEstablismentPacket;

/**
 *	Packet sent from server to
 *	client when server has created benchmark
 *	thread and and is ready to start the benchmark.
 */
typedef struct snt_ready_packet_t{
	SNTPacketHeader header;			/*	Protocol header.	*/
}__attribute__ ((__packed__))SNTReadyPacket;

/**
 *	Packet sent from server to
 *	client when server has created benchmark
 *	thread and and is ready to start the benchmark.
 */
typedef struct snt_start_packet_t{
	SNTPacketHeader header;			/*	Protocol header.	*/
}__attribute__ ((__packed__))SNTstartPacket;

/**
 *	Error message packet.
 */
typedef struct snt_error_packet_t{
	SNTPacketHeader header;			/*	Protocol header.	*/
	int32_t errorcode;				/*	Error code.	*/
	uint32_t meslen;				/*	Length of message.	*/
	int8_t message[512];			/*	Message.	*/
}__attribute__ ((__packed__))SNTErrorPacket;

/**
 *	Result packet from the end of a
 *	benchmark.
 */
typedef struct snt_result_packet_t{
	SNTPacketHeader header;			/*	Protocol header.	*/
	uint32_t type;					/*	Type of result.	*/
	uint64_t npackets;				/*	Number of packets.	*/
	uint64_t nbytes;				/*	Number of bytes.	*/
	uint64_t elapse;				/*	Elapse time.	*/
	uint64_t timeres;				/*	Time resolution.	*/

}__attribute__ ((__packed__))SNTResultPacket;

/**
 *	Uniform buffer packet data type.
 *	Never use sizeof of this data type.
 *	It's only intended to simply the programming.
 *
 *	It can be used with a buffer that exceeds the size
 *	of sizeof(totalbuf).
 */
typedef union snt_unionform_packet_t{
	union{
		uint8_t totalbuf[1500];								/*	Total buffer.	*/
		struct{
			SNTPacketHeader header;							/*	*/
			uint8_t buf[1500 - sizeof(SNTPacketHeader)];	/*	*/
		};
		struct{
			SNTPacketHeader enc_header;						/*	*/
			SNTPresentationPacket presentation;				/*	*/
			/*	*/
			uint8_t enc_buf[1500 - (sizeof(SNTPacketHeader) + sizeof(SNTPresentationPacket))];
		};
	};
}__attribute__ ((__packed__))SNTUniformPacket;

/**
 *	Connection container object.
 */
typedef struct snt_connection_t{
	int tcpsock;					/*	socket file descriptor, TCP.	*/
	int udpsock;					/*	socket file descriptor, UDP.	*/
	struct sockaddr* intaddr;		/*	Internal socket address. aka* source address.	*/
	struct sockaddr* extaddr;		/*	External socket address. aka* destination address.	*/
	socklen_t sclen;				/*	Socket address length in bytes.	*/
	int externalport;				/*	External port. aka* destination port.	*/
	int port;						/*	Source port.	*/
	char ip[16];					/*	Source IP address.	*/
	char extipv[16];				/*	External/Destination IP address.	*/
	unsigned int flag;				/*	connection flag.	*/
	unsigned int asynumbits;		/*	Asymmetric cipher bit size.	*/
	unsigned int inverfreq;			/*	Inverse frequency.	*/
	unsigned int payload;			/*	packet payload in bytes.*/
	int mtu;						/*	Max transfer unite.	*/
	char* mtubuf;					/*	MTU buffer.	*/
	char* tranbuf;					/*	Transmit buffer.	*/
	char* recvbuf;					/*	Receive buffer.	*/
	union{
		void* asymkey;				/*	Asymmetric.	*/
		void* RSAkey;				/*	RSA.	*/
		void* ECkey;				/*	Elliptic curves.	*/
	};
	unsigned int symchiper;			/*	Symmetric cipher used for the connection.	*/
	unsigned int blocksize;			/*	Block size in bytes for the symmetric cipher. */
	unsigned int asymchiper;		/*	Asymmetric cipher used for the connection.	*/
	unsigned int usecompression;	/*	Compression used for the connection.	*/
	union{
		void* symmetrickey;			/*	Symmetric key.	*/
		void* aes;					/*	AES. ( Advanced encryption standard.)	*/
		void* blowfish;				/*	BlowFish.	*/
		void* des3;					/*	DES3.	*/
	};
	union{
		void* desymmetrickey;		/*	Desymmetric.	*/
		void* deaes;				/*	*/
		void* deblowfish;			/*	*/
		void* dedes3;				/*	desDES3.	*/
	};
	SNTConnectionOption* option;	/*	*/
}SNTConnection;

/**
 *	Connection flag.	TODO Add some kind of encpsulation.
 */
#define SNT_CONNECTION_TRANS	0x1	/*	Transport mode enabled.	*/
#define SNT_CONNECTION_BENCH	0x2	/*	Benchmark mode.	*/

/**
 *	Check connection flag status.
 */
#define sntIsTransportEnable(con) (con->flag & SNT_CONNECTION_TRANS)
#define sntIsBenchEnable(con) (con->flag & SNT_CONNECTION_BENCH)


#define sntIsConnectionSecure(con) (con->symchiper != 0)
#define sntIsConnectionCompressed(con) (con->usecompression != 0)

/**
 *	Get attribute about the current socket
 *	connection. This has to invoked before using
 *	connection.
 */
extern void sntGetInterfaceAttr(SNTConnection* connection);

/**
 *	Bind server to socket.
 *
 *	TODO add listen IP address.
 *
 *	@Return None null pointer if successful.
 */
extern SNTConnection* sntBindSocket(uint16_t port, const SNTConnectionOption* option);

/**
 *	Accept connections from clients.
 *
 *	@Return None null pointer if successful.
 */
extern SNTConnection* sntAcceptSocket(SNTConnection* bindconnection);

/**
 *	Connect to server.
 *
 *	@Return None null pointer if successful.
 */
extern SNTConnection* sntConnectSocket(const char* __restrict__ host,
		uint16_t port, const SNTConnectionOption* __restrict__ option);

/**
 *	Disconnect and release all resource associated.
 */
extern void sntDisconnectSocket(SNTConnection* connection);

/**
 *	Copy connection option.
 */
extern void sntConnectionCopyOption(SNTConnection* __restrict__ connection,
		const SNTConnectionOption* __restrict__ option);

/**
 *
 */
extern int sntInitSocket(SNTConnection* connection, int affamily,
		unsigned int protocol);

/**
 *	Set transport protocol. Used during the initialization part.
 */
extern int sntSetTransportProcotcol(SNTConnection* connection,
		unsigned int protocol);

/**
 *	Each packet sent will consist of a header
 *	and body. The header will never be compressed
 *	nor encrypted. However this might change in future version.
 *
 *	The presentation layer is an extension of the header.
 *	It will only added when using secure connection.
 *	The header uses the flag member for informing the receiver
 *	it contains a presentation layer.
 *
 *		|---------------|]
 *		|     header    |]	Application protocol header.
 *		|  OSI Layer 7  |]	Describe incoming packets.
 *		|---------------|
 *		| presentation  |]	Only used when using symmetric
 *		|  OSI Layer 6  |]	cryptographic.
 *		|---------------|
 *		|---------------|]	Application protocol data
 *		|   payload.    |]	chunk.
 *		|  OSI Layer 4  |]
 *		|^^^^^^^^^^^^^^^|
 *
 *	The max size of the packet depends if the transport
 *	layer uses TCP or UDP.
 *
 */

/**
 *	Create packet ready to be sent.
 *
 *	@#eturn number of bytes of the packet body.
 */
extern unsigned int sntCreateSendPacket(const SNTConnection* __restrict__ connection,
		void* __restrict__ buffer, unsigned int buflen, uint8_t* __restrict__ noffset);
/**
 *	Create packet ready to be received.
 *
 *	@Return number of bytes of the packet body.
 */
extern unsigned int sntCreateRecvPacket(const SNTConnection* __restrict__ connection,
		void* __restrict__ buffer, unsigned int buflen, uint8_t noffset);

/**
 *	Read data from socket.
 *
 *	@Return number of bytes read.
 */
extern int sntReadSocket(const SNTConnection* __restrict__ connection,
		void* __restrict__ buffer, unsigned int buflen, int flag);

/**
 *	Write data to socket.
 *
 *	@Return number of bytes written.
 */
extern int sntWriteSocket(const SNTConnection* __restrict__ connection,
		const void* __restrict__ buffer, unsigned int buflen, int flag);

/**
 *	Send packet.
 *
 *	Will make a copy of the packet to transmit buffer in
 *	the connection pointer. This will be used in order not
 *	alter the inputed packet. This is because the packet will
 *	altered if compression or encryption is used.
 *
 *	@Return number of bytes sent.
 */
extern int sntWriteSocketPacket(const SNTConnection* __restrict__ connection,
			const SNTUniformPacket* __restrict__ pack);
/*extern int sntWriteSocketPacketFast(const SNTConnection* __restrict__ connection,
			const SNTUniformPacket* __restrict__ pack);*/

/**
 *	Receiving packet.
 *
 *	@Return number of bytes received.
 */
extern int sntReadSocketPacket(const SNTConnection* __restrict__ connection,
		SNTUniformPacket* __restrict__ pack);
/*extern int sntReadSocketPacketFast(const SNTConnection* __restrict__ connection,
		SNTUniformPacket* __restrict__ pack);*/

/**
 *	Recv application protocol header.
 *
 *	@Return none zero if sucesfully fetch. zero otherwise.
 */
extern int sntRecvPacketHeader(
		const SNTConnection* __restrict__ connection,
		SNTUniformPacket* __restrict__ header);

/**
 *	Drop incoming packet.
 */
extern void sntDropPacket(const SNTConnection* connection);

/**
 *	Copy application protocol header. This includes layer
 *	5 to 7 in the OSI model.
 */
extern void sntCopyHeader(SNTPacketHeader* dest, const SNTPacketHeader* __restrict__ source);

/**
 *	Copy packet payload.
 */
#define sntCopyPacketPayload(a,b,c) memcpy(a, b, c)

/**
 *	Copy whole packet based on the values in the application
 *	protocl header.
 */
extern void sntCopyPacket(SNTUniformPacket* __restrict__ dest,
		const SNTUniformPacket* __restrict__ source);

/**
 *	Initialize default header values.
 *
 *	\command Application protocol command.
 *
 *	\len Total size of the packet. Includes packet header
 *	and the size the data block.
 *
 */
extern void sntInitDefaultHeader(SNTPacketHeader* header, unsigned int command,
		unsigned int len);

/**
 *	Initialize protocol header.
 *
 *	\command Application protocol command.
 *
 *	\buffer size of the payload in bytes.
 */
extern void sntInitHeader(SNTPacketHeader* header, unsigned int command,
		unsigned int buffer);
extern void sntSetDatagramSize(SNTPacketHeader* header, unsigned int buffer);

/**
 *	@Return Total size of packet in bytes.
 */
extern unsigned int sntProtocolPacketSize(const SNTPacketHeader* header);

/**
 *	Get the size of data inside the packet. This excluses the size
 *	of the packet header and presentation header if exists.
 *	This is done by computing packet.length - packet.offset.
 *
 *	@Return number of bytes in the data block.
 */
extern unsigned int sntProtocolHeaderDatagramSize(const SNTPacketHeader* header);

/**
 *	Get size of application protocol layer in bytes. This is done by
 *	reading the offset. Since the offset repesentate the offset to the datablock.
 */
extern unsigned int sntProtocolHeaderSize(const SNTPacketHeader* header);

/**
 *	Get pointer of datagram block pointer based on the header
 *	values.
 */
extern void* sntDatagramGetBlock(SNTUniformPacket* packet);

#endif
