#include"snt_debug.h"

void sntPrintPacketInfo(const SNTUniformPacket* packet){

	union{
		const SNTUniformPacket* uni;
		const SNTInitPackage* init;
		const SNTClientOption* cli;
		const SNTCertificate* cer;
		const SNTSecureEstablismentPacket* sec;
		const SNTResultPacket* res;
		const SNTErrorPacket* error;
	}pack;

	/*	Check the verbosity.	*/
	if(g_verbosity < SNT_LOG_DEBUG)
		return;

	/*	*/
	pack.uni = packet;

	/*	Application protocol header.	*/
	fprintf(stdout, "--- header ---\n"
					"version : %u.%u.\n"
					"stype   : %u : %s.\n"
					"offset  : %u.\n"
					"len     : %u.\n"
					"flag    : %u.\n"
					"--------------\n",
					SNT_GET_MAJ_VERSION(packet->header.version),
					SNT_GET_MIN_VERSION(packet->header.version),
					packet->header.stype, packet->header.stype <= sntSymbolArraySize((const void**)gs_symprotocol) ?
							gs_symprotocol[packet->header.stype] : "",
					packet->header.offset,
					sntProtocolPacketSize(&packet->header),
					packet->header.flag);

	/*	Presentation layer if present.	*/
	if(packet->header.flag & SNT_PACKET_ENCRYPTION){
		SNTPresentationUnion* press = (SNTPresentationUnion*)&packet->presentation;
		fprintf(stdout, "--- presentation layer ---\n"
						"noffset : %u.\n",
						press->offset.noffset);
		/*	Print Initialization vector.	*/
		if(packet->header.flag & SNT_PACKET_IV_ENCRYPTION){
			uint32_t iv[16];
			uint32_t i;
			memcpy(iv, press->iv.iv, 16);
			fprintf(stdout, "len : %u.\n"
							"IV  : ",
							press->iv.len);
			for(i = 0; i < press->iv.len / 4; i++){
				fprintf(stdout, "%x",iv[i]);
			}
			fprintf(stdout, ".\n");
		}

		fprintf(stdout, "--------------\n");
	}



	/*	*/
	switch(packet->header.stype){
	case SNT_PROTOCOL_STYPE_INIT:
		fprintf(stdout,
				"ssl         : %u.\n"
				"asymchiper  : %u.\n"
				"symchiper   : %u.\n"
				"compression : %u.\n"
				"mode        : %u.\n"
				"inetbuffer  : %u.\n"
				"transmode   : %u.\n"
				"extension   : %u.\n"
				"deltaTypes  : %u.\n",
				pack.init->ssl,
				pack.init->asymchiper,
				pack.init->symchiper,
				pack.init->compression,
				pack.init->mode,
				pack.init->inetbuffer,
				pack.init->transmode,
				pack.init->extension,
				pack.init->deltaTypes);
		break;
	case SNT_PROTOCOL_STYPE_CLIENTOPT:
		fprintf(stdout,
				"ssl            : %u.\n"
				"symchiper      : %u.\n"
				"compression    : %u.\n"
				"benchmode      : %u.\n"
				"transprotocol  : %u.\n"
				"deltaTypes     : %u.\n"
				"incdelta       : %lu.\n"
				"duplex         : %u.\n"
				"frequency      : %lu.\n"
				"playload       : %hu.\n"
				"extension      : %u.\n"
				"duration       : %lu.\n",
				pack.cli->ssl,
				pack.cli->symchiper,
				pack.cli->compression,
				pack.cli->benchmode,
				pack.cli->transprotocol,
				pack.cli->deltaTypes,
				pack.cli->incdelta.i,
				pack.cli->duplex,
				pack.cli->invfrequency,
				pack.cli->payload,
				pack.cli->extension,
				pack.cli->duration);
		break;
	case SNT_PROTOCOL_STYPE_CERTIFICATE:
		fprintf(stdout,
				"type       : %u\n"
				"hashtype   : %u\n"
				"localhashe : %u\n"
				"encryhashe : %u\n"
				"offset     : %u\n"
				"asymchiper : %u\n"
				"certlen    : %u\n",
				pack.cer->certype,
				pack.cer->hashtype,
				pack.cer->localhashedsize,
				pack.cer->encryedhashsize,
				pack.cer->offset,
				pack.cer->asymchiper,
				pack.cer->certlen);
		break;
	case SNT_PROTOCOL_STYPE_SECURE:
		fprintf(stdout,
				"symchiper  : %u\n"
				"keylen     : %u\n"
				"encrypsize : %u\n",
				pack.sec->symchiper,
				pack.sec->keybitlen,
				pack.sec->encrykeyblock);
		break;
	case SNT_PROTOCOL_STYPE_RESULT:
		fprintf(stdout,
				"type       : %u\n"
				"npackets   : %lu\n"
				"nbytes     : %lu\n"
				"elapse     : %lu\n"
				"timeres    : %lu\n",
				pack.res->type,
				pack.res->npackets,
				pack.res->nbytes,
				pack.res->elapse,
				pack.res->timeres);
		break;
	case SNT_PROTOCOL_STYPE_ERROR:
		fprintf(stdout,
				"errorcode  : %d\n"
				"meslen     : %u\n",
				pack.error->errorcode,
				pack.error->meslen);
		break;
	case SNT_PROTOCOL_STYPE_READY:
	case SNT_PROTOCOL_STYPE_STARTTEST:
	case SNT_PROTOCOL_STYPE_BENCHMARK:
		/*	NO additional attributes.	*/
	default:
		break;
	}

	fprintf(stdout, ".\n");
}

