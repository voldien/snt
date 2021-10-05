#ifndef _SNT_PROTOCOL_H_
#define _SNT_PROTOCOL_H_ 1
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus /*	C++ Environment	*/
extern "C" {
#endif

/**
 *	SNT protocol header. This header will be attached
 *	to all packet with a intention of informing something.
 *	Everything except the benchmark uses the packet header.
 */
typedef struct snt_packet_header_t {
	uint16_t version; /*	version of the protocol.	*/
	uint8_t stype;	  /*	packet type.	*/
	uint8_t offset;	  /*	offset from application protocol header to the payload.	*/
	uint16_t len;	  /*	size of the total packet.	*/
	uint8_t flag;	  /*	flag of packet type.	*/
} __attribute__((__packed__)) SNTPacketHeader;

/**
 *	Used for encryption. Contains negative offset
 *	of the packet size. This is used in order get the
 *	original size since all encryption is block cipher.
 *	This means the size is always a multiple of blocksize.
 *	This will remove the padding added in order perform the encryption.
 */
typedef struct snt_presentation_package_t {
	uint8_t noffset; /*	Negative offset.	*/
} __attribute__((__packed__)) SNTPresentationPacket;

/**
 *	Presentation initialization vector. Used for cryptographic
 *	that uses initial vector.
 */
typedef struct snt_presentation_iv_package_t {
	uint8_t len;   /*	size of IV in bytes.	*/
	uint8_t iv[0]; /*	IV pointer only.	*/
} __attribute__((__packed__)) SNTPresentationIVPacket;

/**
 *	Presentation feedback.
 */
typedef struct snt_presentation_feedback_package_t {
	int32_t num; /*	*/
} __attribute__((__packed__)) SNTPresentationFeedbackPacket;

/**
 *	Presentation layer union. The presentation layer will always
 *	be presented in this order.
 */
typedef struct snt_presentation_union_t {
	SNTPresentationPacket offset;	  /*	Negative Offset.	*/
	SNTPresentationIVPacket iv;		  /*	Initialize vector.	*/
	SNTPresentationFeedbackPacket fb; /*	feedback number.	*/
} __attribute__((__packed__)) SNTPresentationUnion;

// /**
//  *	Create packet ready to be sent.
//  *
//  *	@Return number of bytes of the packet body.
//  */
// extern unsigned int sntCreateSendPacket(const SNTConnection *__restrict__ connection, void *__restrict__ buffer,
// 										unsigned int buflen, SNTPresentationUnion *__restrict__ pres);
// /**
//  *	Create packet ready to be received.
//  *
//  *	@Return number of bytes of the packet body.
//  */
// extern unsigned int sntCreateRecvPacket(const SNTConnection *__restrict__ connection, void *__restrict__ buffer,
// 										unsigned int buflen, SNTPresentationUnion *__restrict__ pres);

// /**
//  *	Read data from socket.
//  *
//  *	@Return number of bytes read.
//  */
// extern int sntReadSocket(const SNTConnection *__restrict__ connection, void *__restrict__ buffer, unsigned int buflen,
// 						 int flag);

// /**
//  *	Write data to socket.
//  *
//  *	@Return number of bytes written.
//  */
// extern int sntWriteSocket(const SNTConnection *__restrict__ connection, const void *__restrict__ buffer,
// 						  unsigned int buflen, int flag);

// /**
//  *	Send packet.
//  *
//  *	Will make a copy of the packet to transmit buffer in
//  *	the connection pointer. This will be used in order not
//  *	alter the inputed packet. This is because the packet will
//  *	altered if compression or encryption is used.
//  *
//  *	@Return number of bytes sent.
//  */
// extern int sntWriteSocketPacket(const SNTConnection *__restrict__ connection,
// 								const SNTUniformPacket *__restrict__ pack);

// /**
//  *	Receiving packet.
//  *
//  *	@Return number of bytes received.
//  */
// extern int sntReadSocketPacket(const SNTConnection *__restrict__ connection, SNTUniformPacket *__restrict__ pack);

// /**
//  *	Peek application protocol header.
//  *
//  *	@Return none zero if successfully fetch. zero otherwise.
//  */
// extern int sntPeekPacketHeader(const SNTConnection *__restrict__ connection, SNTUniformPacket *__restrict__ header);

// /**
//  *	Drop incoming packet.
//  */
// extern void sntDropPacket(const SNTConnection *connection);

// /**
//  *	Copy application protocol header. This includes layer
//  *	5 to 7 in the OSI model.
//  */
// extern void sntCopyHeader(SNTPacketHeader *__restrict__ dest, const SNTPacketHeader *__restrict__ source);

// /**
//  *	Copy packet payload.
//  */
// #define sntCopyPacketPayload(a, b, c) memcpy((a), (b), (c))

// /**
//  *	Copy the whole packet based on the values
//  *	in the application protocol header.
//  */
// extern void sntCopyPacket(SNTUniformPacket *__restrict__ dest, const SNTUniformPacket *__restrict__ source);

// /**
//  *	Initialize default header values.
//  *
//  *	\command Application protocol command.
//  *
//  *	\len Total size of the packet. Includes packet header
//  *	and the size the data block.
//  *
//  */
// extern void sntInitDefaultHeader(SNTPacketHeader *header, unsigned int command, unsigned int len);

// /**
//  *	Initialize protocol header.
//  *
//  *	\command Application protocol command.
//  *
//  *	\buffer size of the payload in bytes.
//  */
// extern void sntInitHeader(SNTPacketHeader *header, unsigned int command, unsigned int buffer);
// extern void sntSetDatagramSize(SNTPacketHeader *header, unsigned int buffer);

// /**
//  *
//  */
// extern unsigned int sntProtocolPacketCommand(const SNTPacketHeader *header);

// /**
//  *	@Return Total size of packet in bytes.
//  */
// extern unsigned int sntProtocolPacketSize(const SNTPacketHeader *header);

// /**
//  *	Get the size of data inside the packet. This excluses the size
//  *	of the packet header and presentation header if exists.
//  *	This is done by computing packet.length - packet.offset.
//  *
//  *	@Return number of bytes in the data block.
//  */
// extern unsigned int sntProtocolHeaderDatagramSize(const SNTPacketHeader *header);

// /**
//  *	Get size of application protocol layer in bytes. This is done by
//  *	reading the offset. Since the offset repesentate the offset to the datablock.
//  *
//  *	@Return number of bytes.
//  */
// extern unsigned int sntProtocolHeaderSize(const SNTPacketHeader *header);

// /**
//  *	Get pointer of datagram block pointer based on the header
//  *	values.
//  *
//  *	@Return address pointer to begining.
//  */
// extern void *sntDatagramGetBlock(const SNTUniformPacket *packet);

#ifdef __cplusplus /*	C++ Environment	*/
}
#endif

#endif
