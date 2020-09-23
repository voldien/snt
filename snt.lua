
-- Scirpt for enable support for wireshark sniffing decoding.
-- Copyright (C) 2017  Valdemar Lindberg
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <http://www.gnu.org/licenses/>.

-- Debug print.
dprint = function(...)
	info(table.concat({"Lua: ", ...}," "))
end

-- Default settings of the dissector.
local default_settings =
{
	enabled      = true,          -- whether this dissector is enabled or not
	port         = 54321,         -- default TCP port number for FPM
	subdissect   = true,          -- whether to call sub-dissector or not
	subdiss_type = wtap.NETLINK,  -- the encap we get the subdissector for
}

-- Create snt protocol.
local snt = Proto("snt", "simple-network-tool-protocol")
dprint("Registered snt protocol.")

--
-- snt header fields.
local snt_hdr_fields = 
{
	-- Protocol header.
	version = ProtoField.uint16("snt.version", "Version", base.DEC),
	stype = ProtoField.uint8("snt.stype", "Stype", base.DEC),
	offset = ProtoField.uint8("snt.offset", "Offset", base.DEC),
	len = ProtoField.uint16("snt.len", "Length", base.DEC),
	flag = ProtoField.uint8("snt.flag", "PacketFlag", base.DEC),

	-- Presentation layer for resolving encryption padding issue and other.
	presentation = ProtoField.uint8("snt.presentation.noffet", "Negative offset", base.DEC),
	presentationiv = ProtoField.bytes("snt.presentation.IV", "Initilization Vector"),
	presentationfb = ProtoField.uint32("snt.presentation.fb", "Feedback", base.DEC),
	
	-- Initialization packet.
	secure = ProtoField.uint32("snt.init.ssl", "Secure", base.DEC),
	asymchiper = ProtoField.uint32("snt.init.asymchiper", "Asymchiper", base.DEC),
	symchiper = ProtoField.uint32("snt.init.symchiper", "Symchiper", base.DEC),
	compression = ProtoField.uint32("snt.init.compression", "Compression", base.DEC),
	mode = ProtoField.uint32("snt.init.mode", "Mode", base.DEC),
	inetbuf = ProtoField.uint32("snt.init.inetbuffer", "Inet-Buffer", base.DEC),
	transmode = ProtoField.uint32("snt.init.transmode", "Transport-Mode", base.DEC),
	extension = ProtoField.uint32("snt.init.extension", "Extension", base.DEC),
	deltatype = ProtoField.uint32("snt.init.deltaTypes", "Delta-Type", base.DEC),
	
	-- Client option.
	cliopt_ssl = ProtoField.uint32("snt.cli.ssl", "Secure", base.DEC),
	cliopt_symchiper = ProtoField.uint32("snt.cli.symchiper", "Symmetric-Cipher", base.DEC),
	cliopt_compression = ProtoField.uint32("snt.cli.compression", "Compression", base.DEC),
	cliopt_benchmode = ProtoField.uint32("snt.cli.benchmarkmode", "Benchmark-Mode", base.DEC),
	cliopt_transprotocol = ProtoField.uint32("snt.cli.transport", "Transport-Protocol", base.DEC),
	cliopt_deltaTypes = ProtoField.uint32("snt.cli.deltatype", "delta-Type", base.DEC),
	cliopt_incdelta = ProtoField.uint32("snt.init.incdelta", "Increment-Delta", base.DEC),
	cliopt_duplex = ProtoField.uint32("snt.cli.duplex", "Duplex", base.DEC),
	cliopt_invfrequency = ProtoField.uint32("snt.cli.invfrequency", "Inverse-Frequency", base.DEC),
	cliopt_playload = ProtoField.uint32("snt.cli.payload", "Payload", base.DEC),
	cliopt_extension = ProtoField.uint32("snt.cli.extension", "Extension", base.DEC),
	cliopt_duration = ProtoField.uint32("snt.cli.duration", "Duration", base.DEC),
	
	-- certificate.
	cert_certype = ProtoField.uint8("snt.certificate.certtype", "Certificate Type", base.DEC),
	cert_hashtype = ProtoField.uint32("snt.certificate.hashtype", "Hash Type", base.DEC),
	cert_localhashedsize = ProtoField.uint32("snt.certificate.encrypt", "encrypted data block", base.DEC),
	cert_encryedhashsize = ProtoField.uint32("snt.certificate.symmetric", "symmetric", base.DEC),
	cert_offset = ProtoField.uint32("snt.certificate.keybitlen", "Offset", base.DEC),
	cert_asymchiper = ProtoField.uint32("snt.certificate.encrypt", "Asymmetric Type", base.DEC),
	cert_certlen = ProtoField.uint32("snt.certificate.certlen", "Certificate Length", base.DEC),
	
	-- Symmetric key exchange.
	sec_symchiper = ProtoField.uint32("snt.secure.symmetric", "Symmetric-Cipher", base.DEC),
	sec_keybitlen = ProtoField.uint32("snt.secure.keybitlen", "Key-Bit-Length", base.DEC),
	sec_encrykeyblock = ProtoField.uint32("snt.secure.encrypt", "Encrypted-Data-Block-Size", base.DEC),
	
	-- Error
	err_code = ProtoField.int32("snt.error.code", "Error Code", base.DEC),
	err_length = ProtoField.uint32("snt.error.length", "Error Message Length", base.DEC),
	err_msg = ProtoField.bytes("snt.error.msg", "Error Message"),
	
	-- Result
	res_type = ProtoField.uint32("snt.result.type", "Result Type", base.DEC),
	res_npackets = ProtoField.uint64("snt.result.npackets", "Number of Packets", base.DEC),
	res_nbytes = ProtoField.uint64("snt.result.nbytes", "Number of Bytes", base.DEC),
	res_elapse = ProtoField.uint64("snt.result.elapse", "Elapse Time", base.DEC),
	res_timeres = ProtoField.uint64("snt.result.timeres", "Time Resolution", base.DEC),

	-- Diffie hellman  
	-- Diffie hellman request don't need 
	
	-- Diffie hellman init
	hs_init_numbit = ProtoField.uint32("snt.dh.numbits", "Number of bits for Diffie hellman.", base.DEC),
	hs_init_plen = ProtoField.uint32("snt.dh.plen", "P size in bytes.", base.DEC),
	hs_init_glen = ProtoField.uint32("snt.dh.glen", "G size in bytes.", base.DEC),
	hs_init_offset = ProtoField.uint32("snt.dh.offset", "Offset in bytes.", base.DEC),
	
	-- Diffie hellman exchange.
	hs_exch_qlen = ProtoField.uint32("snt.dh.qlen", "Q size in bytes.", base.DEC),
	hs_exch_offset = ProtoField.uint32("snt.dh.offset", "Offset in bytes.", base.DEC),
	hs_exch_sym = ProtoField.uint32("snt.dh.sym", "Symmetric cipher to create from Diffie hellman.", base.DEC),
	
}

-- Register protocol
snt.fields = snt_hdr_fields

-- SNT application protocol header size in bytes.
local SNT_MSG_HDR_LEN = 7
-- SNT application protocol max command number.
local SNT_MAX_STYPE = 12

-- SNT header flag constants.
local SNT_MSG_FLAG_ENCR = 0x1	-- Packet contains encrypted data.
local SNT_MSG_FLAG_COMP = 0x2	-- Packet contains compressede data.
local SNT_MSG_FLAG_IV	= 0x4   -- Packet contains initilization vector data.
local SNT_MSG_FLAG_FB	= 0x8   -- Packet contains encryption feedback data.

-- Protocol command name.
local stype_hdr_symbol=
{
	[0] = "Undefined",
	[1] = "Init",
	[2] = "ClientOption",
	[3] = "Certificate",
	[4] = "Secure",
	[5] = "Ready",
	[6] = "Start",
	[7] = "Error",
	[8] = "Benchmark",
	[9] = "Result",
	[10] = "DHReq",
	[11] = "DHInit",
	[12] = "DHExch"
}

-- TODO fix.
local stype_col_info=
{
	[0] = "Undefined",
	[1] = "Init",
	[2] = "ClientOption",
	[3] = "Certificate",
	[4] = "Secure packet.",
	[5] = "Ready",
	[6] = "Start",
	[7] = "Error",
	[8] = "Benchmark",
	[9] = "Result",
	[10] = "DHReq",
	[11] = "DHInit",
	[12] = "DHExch"
}


----------------------------------------
-- main root dissector function.
-- 
-- @param buf
-- 
-- @param pkt
-- 
-- @param root
-- 
-- @return number of bytes dissected.
-- 
function snt.dissector(buf, pkt, root)

	-- Do nothing if dissector is disabled.
	if not default_settings.enabled then
	return 0 -- TODO check default return value actually is.
	end

	-- Initial.
	local pktlen = buf:len()
	local bytes_consumed = 0

	-- Dissect protocol header of the packet.
	local head = buf(0, SNT_MSG_HDR_LEN)
	local result, tree = dissectSNTHeader(head, pkt, root, bytes_consumed)
	bytes_consumed = sntProtocolHeaderSize(head)

	-- Check if to continue the dissection.
	if not default_settings.subdissect then
	return pktlen
	end

	-- Check if presentation layer is pressented.
	if bytes_consumed > SNT_MSG_HDR_LEN and sntProtocolIsEncrypted(head) then
	local preselay = buf(SNT_MSG_HDR_LEN, bytes_consumed - SNT_MSG_HDR_LEN)
	local subtree = tree:add(preselay, "Presentation layer: " )
	sntDissectPresentationLayer(preselay,
									pkt, subtree, sntProtocolHeaderFlag(head))
	end
	
	-- Check if packet is compressed.
	if sntProtocolIsCompressed(head) then
	local subtree = tree:add(buf:range(bytes_consumed), "Compressed:" )
	end
	
	-- Check if command extract is in range, main dissector of the
	-- the protocol.
	if result <= SNT_MAX_STYPE and result > 0 then
	
	-- Create subtree for packet command type.
	local subtree = tree:add(buf:range(bytes_consumed), "Message type: " .. stype_hdr_symbol[result])
	
	-- Set default coloums information.
	pkt.cols.info:set(stype_col_info[result])
	
	-- Display information only if compression or encryption not used.
	if not sntProtocolIsCompressed(head) and not
		sntProtocolIsEncrypted(head) then
		local consumed = disectcommand[result](buf, pkt, subtree, bytes_consumed)
	else
		dprint("Packet's content not decodable.")
	end
	else
	-- Display invalid or unknown packet.
	dprint("Invalid stype command.")
	pkt.cols.info:set("Unknown packet.")
	end

	-- Return length of the packet in bytes.
	return bytes_consumed
end

----------------------------------------
-- Dissect SNT protocol header.
-- @return stype command.
-- 
function dissectSNTHeader(tvbuf, pktinfo, root, offset)

	local length_val, length_tvbr = tvbuf:len() - offset

	if length_val <= 0 then
		return length_val
	end

	-- Set packet information.
	pktinfo.cols.protocol:set("snt")
	pktinfo.cols.info:set("snt protocol.")

	-- We start by adding our protocol to the dissection display tree.
	local tree = root:add(snt, tvbuf:range(offset, length_val))

	-- Dissect the version field.
	local version_val  = tvbuf:range(offset, 2):le_uint()
	tree:add(snt_hdr_fields.version, tvbuf(offset, 2), version_val, sntProtocolGetVersionStr(tvbuf(offset,2)))
	
	-- Dissect the stype field
	local stype_tvbr = tvbuf:range(offset + 2, 1)
	local stype_val  = stype_tvbr:le_uint()
	
	-- Dissect the field
	tree:add(snt_hdr_fields.stype, tvbuf(offset + 2, 1):le_uint(), stype_val, stype_hdr_symbol[stype_val] )

	-- Dissect the header offset field.
	tree:add(snt_hdr_fields.offset, tvbuf(offset + 3, 1))
	
	-- Dissect the total length of incoming packet field.
	tree:add_le(snt_hdr_fields.len, tvbuf(offset + 4, 2))
	
	-- Dissect the flag field
	tree:add(snt_hdr_fields.flag, sntProtocolHeaderFlag(tvbuf))
	
	--
	-- Return stype of the packet datagram.
	return stype_val, tree
end

----------------------------------------
-- Get protocol header size in bytes.
-- @return size in bytes.
function sntProtocolHeaderSize(tvbuf)
	return bit.band( tvbuf(3, 1):le_uint(), 0xffff)
end

----------------------------------------
-- Get protocol header flag.
-- @return flag.
function sntProtocolHeaderFlag(tvbuf)
	return tvbuf(6, 1):le_uint()
end

----------------------------------------
-- Check if packet contains encrypted data.
-- @return true if packet is encrypted.
function sntProtocolIsEncrypted(tvbuf)
	return bit.band(sntProtocolHeaderFlag(tvbuf), SNT_MSG_FLAG_ENCR) == SNT_MSG_FLAG_ENCR
end

----------------------------------------
-- Check if packet is compressed.
-- @return true if packet is compressed.
function sntProtocolIsCompressed(tvbuf)
	return bit.band(sntProtocolHeaderFlag(tvbuf), SNT_MSG_FLAG_COMP) == SNT_MSG_FLAG_COMP
end

----------------------------------------
-- Check if IV data contains in packet.
-- @return true if flag in packet is set.
function sntProtocolUseIV(tvbuf)
	return bit.band(sntProtocolHeaderFlag(tvbuf), SNT_MSG_FLAG_IV) == SNT_MSG_FLAG_IV 
end

----------------------------------------
-- Check if feedback data contains in packet.
-- @return true if flag in packet is set.
function sntProtocolUseFB(tvbuf)
	return bit.band(sntProtocolHeaderFlag(tvbuf), SNT_MSG_FLAG_FB) == SNT_MSG_FLAG_FB
end

----------------------------------------
-- Get version in string format.
-- @return version in string format.
function sntProtocolGetVersionStr(tvbuf)

	local version_val  = tvbuf:le_uint()
	version_val = bit.band(version_val, 0xffff)
	
	local major = bit.band( bit.rshift(bit.band(version_val, bit.bnot(0x3FF)), 10), 0xffff)
	local minor = bit.band( bit.band(version_val, 0x3FF), 0xffff)
	
	return tostring(major) .. "." .. tostring(minor)  
end


------------------------------------------------------------
-- Subdissector part for SNT command.
------------------------------------------------------------

------------------------------------------------------------
-- Dissect the presentation layer, containing cryptographic
-- information for decryping the packet payload.
-- @return Presentation layer size in bytes.
function sntDissectPresentationLayer(tvbuf, pktinfo, tree, flag)

	-- 
	local offset = 0
	local len = tvbuf:len()
	
	-- Display negative offset.
	tree:add(snt_hdr_fields.presentation, tvbuf(offset, 1), tvbuf(offset, 1):le_uint())
	offset = 1

	-- Check if packet contains IV data.
	if bit.band(flag, SNT_MSG_FLAG_IV) and offset < len then
	-- Extract length of IV.
	local ivsize = tvbuf(offset, 1):le_uint()
	offset = offset + 1
	
	-- Add IV as a string.
	tree:add(snt_hdr_fields.presentationiv, tvbuf(offset, ivsize), tostring(tvbuf(offset, ivsize)))
	offset = offset + ivsize
	
	-- Check if feedback contains in the packet.
	if bit.band(flag, SNT_MSG_FLAG_FB) and offset < len then
		tree:add(snt_hdr_fields.presentationfb, tvbuf(offset, 4), tvbuf(offset, 4):le_uint())
		offset = offset + 4
	end
	end
	
	return offset
	
end

------------------------------------------------------------
-- Initialization packet dissector function.
-- @return
function sntDissectInitPacket(tvbuf, pktinfo, tree, offset)
	
	--
	tree:add(snt_hdr_fields.secure, tvbuf(offset + 0, 4), tvbuf(offset + 0, 4):le_uint())
	tree:add(snt_hdr_fields.asymchiper, tvbuf(offset + 4, 4), tvbuf(offset + 4, 4):le_uint())
	tree:add(snt_hdr_fields.symchiper, tvbuf(offset + 8, 4), tvbuf(offset + 8, 4):le_uint())
	tree:add(snt_hdr_fields.compression, tvbuf(offset + 12, 4), tvbuf(offset + 12, 4):le_uint())
	tree:add(snt_hdr_fields.mode, tvbuf(offset + 16, 4), tvbuf(offset + 16, 4):le_uint())

	--
	tree:add(snt_hdr_fields.inetbuf, tvbuf(offset + 20, 4), tvbuf(offset + 20, 4):le_uint())
	tree:add(snt_hdr_fields.transmode, tvbuf(offset + 24, 4), tvbuf(offset + 24, 4):le_uint())
	tree:add(snt_hdr_fields.extension, tvbuf(offset + 28, 4), tvbuf(offset + 28, 4):le_uint())
	tree:add(snt_hdr_fields.deltatype, tvbuf(offset + 32, 4), tvbuf(offset + 32, 4):le_uint())
	 
	--
	pktinfo.cols.info = "Initilization packet."
	
	--
	return 0
end

--------------------------------------------------------------------------------
-- Client-Option packet dissector function.
-- @return
function sntDissectClientPacket(tvbuf, pktinfo, tree, offset)

	--
	tree:add(snt_hdr_fields.cliopt_ssl, tvbuf(offset + 0, 4), tvbuf(offset + 0, 4):le_uint())
	tree:add(snt_hdr_fields.cliopt_symchiper, tvbuf(offset + 4, 4), tvbuf(offset + 4, 4):le_uint())
	tree:add(snt_hdr_fields.cliopt_compression, tvbuf(offset + 8, 4), tvbuf(offset + 8, 4):le_uint())
	tree:add(snt_hdr_fields.cliopt_benchmode, tvbuf(offset + 12, 4), tvbuf(offset + 12, 4):le_uint())
	tree:add(snt_hdr_fields.cliopt_transprotocol, tvbuf(offset + 16, 4), tvbuf(offset + 16, 4):le_uint())

	--  
	tree:add(snt_hdr_fields.cliopt_deltaTypes, tvbuf(offset + 20, 4), tvbuf(offset + 20, 4):le_uint())
	tree:add(snt_hdr_fields.cliopt_incdelta, tvbuf(offset + 24, 4), tvbuf(offset + 24, 4):le_uint())
	tree:add(snt_hdr_fields.cliopt_duplex, tvbuf(offset + 28, 4), tvbuf(offset + 28, 4):le_uint())
	tree:add(snt_hdr_fields.cliopt_invfrequency, tvbuf(offset + 32, 4), tvbuf(offset + 32, 4):le_uint())
	tree:add(snt_hdr_fields.cliopt_playload, tvbuf(offset + 36, 4), tvbuf(offset + 36, 4):le_uint())
	tree:add(snt_hdr_fields.cliopt_extension, tvbuf(offset + 40, 4), tvbuf(offset + 40, 4):le_uint())  
	tree:add(snt_hdr_fields.cliopt_duration, tvbuf(offset + 44, 4), tvbuf(offset + 44, 4):le_uint())

	--
	pktinfo.cols.info = "Client options packet."
	
	return 48;
end

--------------------------------------------------------------
-- Certificate packet dissector function.
-- @return
function sntDissectCertPacket(tvbuf, pktinfo, tree, offset)
	
	-- Print certificate type in the packet.
	tree:add(snt_hdr_fields.cert_certype, tvbuf(offset + 0, 1), tvbuf(offset + 0, 1):le_uint())
	
	-- Print hash type used for computing the hash contained in the encrypted hash block.
	tree:add(snt_hdr_fields.cert_hashtype, tvbuf(offset + 1, 4), tvbuf(offset + 1, 4):le_uint())
	
	-- Print hash block size without encryption.
	tree:add(snt_hdr_fields.cert_localhashedsize, tvbuf(offset + 5, 4), tvbuf(offset + 5, 4):le_uint())
	
	-- Print hash block size with encryption.
	tree:add(snt_hdr_fields.cert_encryedhashsize, tvbuf(offset + 9, 4), tvbuf(offset + 9, 4):le_uint())
	
	--  Print offset to certificate buffer.
	tree:add(snt_hdr_fields.cert_offset, tvbuf(offset + 10, 1), tvbuf(offset + 10, 1):le_uint())

	--
	pktinfo.cols.info = "Certificate packet."
	
	--
	return 0
end

--------------------------------------------------------------------------------
-- Secure symmetric key exchange dissector function.
-- @return
function sntDissectSecPacket(tvbuf, pktinfo, tree, offset)

	-- Print symmetric cipher.
	tree:add(snt_hdr_fields.sec_symchiper, tvbuf(offset + 0, 4), tvbuf(offset + 0, 4):le_uint())
	
	-- Print symmetric cipher size in bits.
	tree:add(snt_hdr_fields.sec_keybitlen, tvbuf(offset + 4, 4), tvbuf(offset + 4, 4):le_uint())
	
	-- Print encrypted symmetric key in bytes.
	tree:add(snt_hdr_fields.sec_encrykeyblock, tvbuf(offset + 8, 4), tvbuf(offset + 8, 4):le_int())  

	--
	pktinfo.cols.info = "Secure packet."
	
	--
	return 0
end

--------------------------------------------------------------------------------
--
-- @return
function sntDissectReadyPacket(tvbuf, pktinfo, tree, offset)

	pktinfo.cols.info = "Ready packet."
	
	--
	return 0
end

--------------------------------------------------------------------------------
--
-- @return
function sntDissectStartPacket(tvbuf, pktinfo, tree, offset)

	pktinfo.cols.info = "Start packet."
	
	--
	return 0
end

--------------------------------------------------------------------------------
-- 
-- @return
function sntDissectErrorPacket(tvbuf, pktinfo, tree, offset)
	
	-- Print error code.
	tree:add(snt_hdr_fields.err_code, tvbuf(offset + 0, 4), tvbuf(offset + 0, 4):le_uint())

	-- Print error message length in character.
	local msglen = tvbuf(offset + 4, 4):le_uint()
	tree:add(snt_hdr_fields.err_length, tvbuf(offset + 4, 4), msglen)
	
	-- Check if message exists.
	if msglen > 0 then
	msg = tvbuf(offset + 8, msglen)
	tree:add(snt_hdr_fields.err_msg, msg, tostring(msg))
	end
	
	-- 
	pktinfo.cols.info = "Error packet."
	
	--
	return 8 + tvbuf(offset + 4, 4):le_uint()
end

--------------------------------------------------------------------------------
--
-- @return
function sntDissectBenchmarkPacket(tvbuf, pktinfo, tree, offset)

	--
	pktinfo.cols.info = "Benchmark packet."

	--  
	return 0
end

--------------------------------------------------------------------------------
--
-- @return
function sntDissectResultPacket(tvbuf, pktinfo, tree, offset)

	--
	tree:add(snt_hdr_fields.res_type, tvbuf(offset + 0, 4), tvbuf(offset + 0, 4):le_uint())
	
	--
	tree:add(snt_hdr_fields.res_npackets, tvbuf(offset + 4, 8), tvbuf(offset + 4, 8):le_uint64())
	
	--
	tree:add(snt_hdr_fields.res_nbytes, tvbuf(offset + 12, 8), tvbuf(offset + 12, 8):le_uint64())
	
	--
	tree:add(snt_hdr_fields.res_elapse, tvbuf(offset + 20, 8), tvbuf(offset + 20, 8):le_uint64())
	
	--
	tree:add(snt_hdr_fields.res_timeres, tvbuf(offset + 28, 8), tvbuf(offset + 28, 8):le_uint64())

	pktinfo.cols.info = "Result packet."
	
	return 0
end

--------------------------------------------------------------------------------
-- Dissector dummy function.
-- @return 
function sntDissectDHReq(tvbuf, pktinfo, tree, offset)

	pktinfo.cols.info = "Diffie hellman request."
	return 0
end

--------------------------------------------------------------------------------
-- Dissect Diffie hellman initialization packet.
-- @return
function sntDissectDHInit(tvbuf, pktinfo, tree, offset)

	--
	tree:add(snt_hdr_fields.hs_init_numbit, tvbuf(offset + 0, 4), tvbuf(offset + 0, 4):le_uint())
	
	--
	tree:add(snt_hdr_fields.hs_init_plen, tvbuf(offset + 4, 4), tvbuf(offset + 4, 4):le_uint())

	--  
	tree:add(snt_hdr_fields.hs_init_glen, tvbuf(offset + 8, 4), tvbuf(offset + 8, 4):le_uint())
	
	--
	tree:add(snt_hdr_fields.hs_init_offset, tvbuf(offset + 12, 1), tvbuf(offset + 12, 1):le_uint())
	
	return 0
end

--------------------------------------------------------------------------------
-- Dissect Diffie hellman exchange packet.
-- @return
function sntDissectDHExch(tvbuf, pktinfo, tree, offset)

	--
	tree:add(snt_hdr_fields.hs_exch_qlen, tvbuf(offset + 0, 4), tvbuf(offset + 0, 4):le_uint())
	
	--
	tree:add(snt_hdr_fields.hs_exch_offset, tvbuf(offset + 4, 4), tvbuf(offset + 4, 4):le_uint())

	--  
	tree:add(snt_hdr_fields.hs_exch_sym, tvbuf(offset + 8, 4), tvbuf(offset + 8, 4):le_uint())
	
	return 0
end


-- Dissector protocol command function map.
disectcommand = {
	[1] = sntDissectInitPacket,
	[2] = sntDissectClientPacket,
	[3] = sntDissectCertPacket,
	[4] = sntDissectSecPacket,
	[5] = sntDissectReadyPacket,
	[6] = sntDissectStartPacket,
	[7] = sntDissectErrorPacket,
	[8] = sntDissectBenchmarkPacket,
	[9] = sntDissectResultPacket,
	[10] = sntDissectDHReq,
	[11] = sntDissectDHInit,
	[12] = sntDissectDHExch,
}

-----------------------------------------------
-- Enable dissector function.
-- 
local function enableDissector()

	--
	local udp_encap_table = DissectorTable.get("udp.port")
	local tcp_encap_table = DissectorTable.get("tcp.port")
	
	-- Add dissection for UDP and TCP transport protocol.
	udp_encap_table:add(54321, snt)
	tcp_encap_table:add(54321, snt)

	--
	--
	wtap_encap_table = DissectorTable.get("wtap_encap")
	wtap_encap_table:add(wtap.USER15, snt)
	wtap_encap_table:add(wtap.USER12, snt)
end

------------------------------------------------
-- Disable dissector function.
--
function disableDissector()

	-- get dissector 
	local udp_encap_table = DissectorTable.get("udp.port")
	local tcp_encap_table = DissectorTable.get("tcp.port")

	-- Remove SNT dissector from UDP table.
	if udp_encap_table:get_dissector(54321) then
	udp_encap_table:remove(54321, udp_encap_table:get_dissector(54321))
	 end
	 
	-- Remove SNT dissector from TCP table.
	if tcp_encap_table:get_dissector(54321) then
	tcp_encap_table:remove(54321, tcp_encap_table:get_dissector(54321))
	 end
	 
end

-- call it now, because we're enabled by default
enableDissector()


--------------------------------------------------------------------------------
-- preferences handling stuff
--------------------------------------------------------------------------------

----------------------------------------
--
snt.prefs.enabled = Pref.bool("Dissector enabled", default_settings.enabled,
					"Whether the SNT dissector is enabled or not")

----------------------------------------
--
snt.prefs.subdissect  = Pref.bool("Enable sub-dissectors", default_settings.subdissect,
										"Whether the SNT packet's content" ..
										" should be dissected or not")

----------------------------------------
-- Preference callback changed function.
-- This function will be invoked when 
-- preference settings is changed.
function snt.prefs_changed()
	
	-- Get set option values.
	default_settings.subdissect  = snt.prefs.subdissect
	default_settings.debug_level = snt.prefs.debug_level  
	
	-- Determine if to enable or disable dissector.
	if default_settings.enabled ~= snt.prefs.enabled then
	default_settings.enabled = snt.prefs.enabled
	if default_settings.enabled then
		enableDissector()
	else
		disableDissector()
	end
	--
	reload()
	end
	
end
		
--                                  
dprint("snt Prefs registered")
