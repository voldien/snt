#include"snt_debug.h"

void sntPrintPacketInfo(const SNTUniformPacket* packet){

	/*	*/
	if(g_verbosity < SNT_LOG_DEBUG)
		return;

	fprintf(stdout, "--- header ---\n"
					"version : %u.%u.\n"
					"stype : %u : %s.\n"
					"offset : %u.\n"
					"len : %u.\n"
					"flag : %u.\n"
					"--------------\n",
					SNT_GET_MAJ_VERSION(packet->header.version),
					SNT_GET_MIN_VERSION(packet->header.version),
					packet->header.stype, gs_symprotocol[packet->header.stype],
					packet->header.offset,
					sntDatagramSize(&packet->header),
					packet->header.flag);

	/*	*/
	if(packet->header.flag & SNT_PACKET_ENCRYPTION){
		fprintf(stdout, "--- presentation layer ---\n"
						"noffset : %u.\n"
						"--------------\n",
						packet->totalbuf[sizeof(SNTPacketHeader)]);
	}

	const SNTInitPackage* init = (SNTInitPackage*)packet;
	const SNTClientOption* cli = (SNTClientOption*)packet;
	const SNTCertificate* cer = (SNTCertificate*)packet;
	const SNTSecureEstablismentPacket* sec = (SNTSecureEstablismentPacket*)packet;

	/*	*/
	switch(packet->header.stype){
	case SNT_PROTOCOL_STYPE_INIT:
		fprintf(stdout,
				"ssl : %u.\n"
				"asymchiper : %u : .\n"
				"symchiper : %u : .\n"
				"compression : %u  : .\n"
				"mode : %u  : .\n"
				"inetbuffer : %u.\n"
				"transmode : %u.\n"
				"extension : %u.\n"
				"deltaTypes : %u : .\n",
				init->ssl,
				init->asymchiper,
				init->symchiper,
				init->compression,
				init->mode,
				init->inetbuffer,
				init->transmode,
				init->extension,
				init->deltaTypes);
		break;
	case SNT_PROTOCOL_STYPE_CLIENTOPT:
		fprintf(stdout,
				"ssl : %u.\n"
				"symchiper : %u.\n"
				"compression : %u.\n"
				"benchmode : %u.\n"
				"transprotocol : %u.\n"
				"deltaTypes : %u.\n"
				"incdelta : %lu.\n"
				"duplex : %u.\n"
				"frequency : %lu.\n"
				"playload : %hu.\n"
				"extension : %u.\n",
				cli->ssl,
				cli->symchiper,
				cli->compression,
				cli->benchmode,
				cli->transprotocol,
				cli->deltaTypes,
				cli->incdelta.i,
				cli->duplex,
				cli->invfrequency,
				cli->playload,
				cli->extension);
		break;
	case SNT_PROTOCOL_STYPE_CERTIFICATE:
		fprintf(stdout,
				"type : %u\n"
				"hashtype : %u\n"
				"localhashe : %u\n"
				"encryhashe : %u\n"
				"offset : %u\n"
				"asymchiper : %u\n"
				"certlen : %u\n",
				cer->certype,
				cer->hashtype,
				cer->localhashedsize,
				cer->encryedhashsize,
				cer->offset,
				cer->asymchiper,
				cer->certlen);
		break;
	case SNT_PROTOCOL_STYPE_SECURE:
		fprintf(stdout,
				"symchiper : %u\n"
				"keylen : %u\n"
				"encrypsize : %u\n",
				sec->symchiper,
				sec->keybitlen,
				sec->encrykeyblock);
		break;
	case SNT_PROTOCOL_STYPE_READY:
	case SNT_PROTOCOL_STYPE_STARTTEST:
	case SNT_PROTOCOL_STYPE_ERROR:
	case SNT_PROTOCOL_STYPE_BENCHMARK:
	default:
		break;
	}

	fprintf(stdout, ".\n");
}

/*extern void sntPrintConnection(const SNTConnection* connection);	*/
