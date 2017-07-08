
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

--
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
  -- protocol header.
  version = ProtoField.uint16("snt.version", "Version", base.DEC),
  stype = ProtoField.uint8("snt.stype", "Stype", base.DEC),
  offset = ProtoField.uint8("snt.offset", "Offset", base.DEC),
  len = ProtoField.uint16("snt.len", "Length", base.DEC),
  flag = ProtoField.uint8("snt.flag", "PacketFlag", base.DEC),

  -- Presentation layer for resolving encryption padding issue.
  presentation = ProtoField.uint8("snt.presentation.noffet", "Negative offset", base.DEC),
  
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
  
  -- Result
  res_type = ProtoField.uint32("snt.result.type", "Result Type", base.DEC),
  res_npackets = ProtoField.uint64("snt.result.npackets", "Number of Packets", base.DEC),
  res_nbytes = ProtoField.uint64("snt.result.nbytes", "Number of Bytes", base.DEC),
  res_elapse = ProtoField.uint64("snt.result.elapse", "Elapse Time", base.DEC),
  res_timeres = ProtoField.uint64("snt.result.timeres", "Time Resolution", base.DEC)
  
}

-- Register protocol
snt.fields = snt_hdr_fields

-- SNT application protocol header size in bytes.
--
local SNT_MSG_HDR_LEN = 7
local SNT_MAX_STYPE = 9

-- SNT header flag constants.
local SNT_MSG_FLAG_ENCR = 0x1
local SNT_MSG_FLAG_COMP = 0x2

--
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
}


----------------------------------------
-- main root dissector function.
-- 
-- @Return number of bytes.
-- 
function snt.dissector(buf, pkt, root)


  -- Do nothing if dissector is disabled.
  if not default_settings.enabled then
    return 0 -- TODO check default return value actually is.
  end

  -- Initial.
	local pktlen = buf:len()
	local bytes_consumed = 0

  -- dissect protocol header of the packet.
	local result = dissectSNT(buf(0, SNT_MSG_HDR_LEN), pkt, root, bytes_consumed)
	bytes_consumed = sntProtocolHeaderSize(buf(0, SNT_MSG_HDR_LEN))

  --
  if not default_settings.subdissect then
    return pktlen
  end

  -- Check if presentation layer is pressented.
  if bytes_consumed > SNT_MSG_HDR_LEN and sntProtocolIsEncrypted(buf(0, SNT_MSG_HDR_LEN)) then
    local subtree = root:add(buf:range(bytes_consumed), "Presentation layer: " )
    sntDissectPresentationLayer(buf, pkt, subtree, bytes_consumed)
  end
  
  -- Check if packet is compressed.
  if sntProtocolIsCompressed(buf(0, SNT_MSG_HDR_LEN)) then
    local subtree = root:add(buf:range(bytes_consumed), "Compressed:" )    
  end
  
  -- Check if command extract is in range.
	if result <= SNT_MAX_STYPE then
  
    -- Create subtree for packet command type.
    local subtree = root:add(buf:range(bytes_consumed), "Message type: " .. stype_hdr_symbol[result])
    
    -- 
    pkt.cols.info:set(stype_col_info[result])
    
    -- Display information only if compression or encryption not used.
    if not sntProtocolIsCompressed(buf(0, SNT_MSG_HDR_LEN)) and not
      sntProtocolIsEncrypted(buf(0, SNT_MSG_HDR_LEN)) then
      local consumed = disectcommand[result](buf, pkt, subtree, bytes_consumed)
    else
      dprint("Packet content not decodable.")
    end
  else
    --
    dprint("Invalid stype command.")
  end

  -- return length of packet.
  return bytes_consumed
end

----------------------------------------
-- Dissect SNT protocol header.
-- @Return stype command.
-- 
function dissectSNT(tvbuf, pktinfo, root, offset)

	local length_val, length_tvbr = tvbuf:len() - offset

	if length_val <= 0 then
		return length_val
	end

  --
	pktinfo.cols.protocol:set("snt")
	pktinfo.cols.info:set("snt protocol.")

	-- We start by adding our protocol to the dissection display tree.
	local tree = root:add(snt, tvbuf:range(offset, length_val))

	-- dissect the version field.
	local version_val  = tvbuf:range(offset, 2):le_uint()
	tree:add(snt_hdr_fields.version, tvbuf(offset, 2), version_val, sntProtocolGetVersionStr(tvbuf(offset,2)))
	
	-- dissect the __ field
	local stype_tvbr = tvbuf:range(offset + 2, 1)
	local stype_val  = stype_tvbr:le_uint()
	
  -- dissect the __ field
	tree:add(snt_hdr_fields.stype, tvbuf(offset + 2, 1):le_uint(), stype_val, stype_hdr_symbol[stype_val] )

  -- dissect the header offset field.
  tree:add(snt_hdr_fields.offset, tvbuf(offset + 3, 1))
  
  -- dissect the total length of incoming packet field.
  tree:add_le(snt_hdr_fields.len, tvbuf(offset + 4, 2))
  
  -- dissect the __ field
  tree:add(snt_hdr_fields.flag, tvbuf(offset + 6, 1))
  
	--
	--
	return stype_val
end

----------------------------------------
-- Get pr
-- @Return
function sntProtocolHeaderSize(tvbuf)
  return bit.band( tvbuf(3, 1):le_uint(), 0xffff)
end

----------------------------------------
-- Check if packet contains encrypted data.
-- @Return  true if packet is encrypted.
function sntProtocolIsEncrypted(tvbuf)
  return bit.band(tvbuf(6, 1):le_uint(), SNT_MSG_FLAG_ENCR) == SNT_MSG_FLAG_ENCR
end

----------------------------------------
-- Check if packet is compressed.
-- @Return true if packet is compressed.
function sntProtocolIsCompressed(tvbuf)
  return bit.band(tvbuf(6, 1):le_uint(), SNT_MSG_FLAG_COMP) == SNT_MSG_FLAG_COMP
end

----------------------------------------
-- Get version in string format.
-- @Return version in string format.
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
--
function sntDissectPresentationLayer(tvbuf, pktinfo, tree, offset)
  tree:add(snt_hdr_fields.presentation, tvbuf(offset, 1), tvbuf(offset, 1):le_uint())
end

------------------------------------------------------------
-- Initialization packet dissector function.
-- @Return
--
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
--
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

--------------------------------------------------------------------------------
-- Certificate packet dissector function.
--
function sntDissectCertPacket(tvbuf, pktinfo, tree, offset)
  
  --
  tree:add(snt_hdr_fields.cert_certype, tvbuf(offset + 0, 1), tvbuf(offset + 0, 1):le_uint())
  tree:add(snt_hdr_fields.cert_hashtype, tvbuf(offset + 1, 4), tvbuf(offset + 1, 4):le_uint())
  
  --
  tree:add(snt_hdr_fields.cert_localhashedsize, tvbuf(offset + 5, 4), tvbuf(offset + 5, 4):le_uint())
  tree:add(snt_hdr_fields.cert_encryedhashsize, tvbuf(offset + 9, 4), tvbuf(offset + 9, 4):le_uint())
  tree:add(snt_hdr_fields.cert_offset, tvbuf(offset + 10, 1), tvbuf(offset + 10, 1):le_uint())

  --
  pktinfo.cols.info = "Certificate packet."
end

--------------------------------------------------------------------------------
-- Secure symmetric key exchange dissector function.
--
function sntDissectSecPacket(tvbuf, pktinfo, tree, offset)

  --
  tree:add(snt_hdr_fields.sec_symchiper, tvbuf(offset + 0, 4), tvbuf(offset + 0, 4):le_uint())
  tree:add(snt_hdr_fields.sec_keybitlen, tvbuf(offset + 4, 4), tvbuf(offset + 4, 4):le_uint())
  tree:add(snt_hdr_fields.sec_encrykeyblock, tvbuf(offset + 8, 4), tvbuf(offset + 8, 4):le_int())  

  --
  pktinfo.cols.info = "Secure packet."
  
  --
  return 0
end

--------------------------------------------------------------------------------
--
--
function sntDissectReadyPacket(tvbuf, pktinfo, tree, offset)

  pktinfo.cols.info = "Ready packet."
  
  --
  return 0
end

--------------------------------------------------------------------------------
--
--
function sntDissectStartPacket(tvbuf, pktinfo, tree, offset)

  pktinfo.cols.info = "Start packet."
  
  --
  return 0
end

--------------------------------------------------------------------------------
-- 
--
function sntDissectErrorPacket(tvbuf, pktinfo, tree, offset)
  
  --
  tree:add(snt_hdr_fields.err_code, tvbuf(offset + 0, 4), tvbuf(offset + 0, 4):le_uint())

  --
  tree:add(snt_hdr_fields.err_length, tvbuf(offset + 4, 4), tvbuf(offset + 4, 4):le_uint())
  
  -- 
  pktinfo.cols.info = "Error packet."
  
  --
  return 8 + tvbuf(offset + 4, 4):le_uint()
end

--------------------------------------------------------------------------------
--
--
function sntDissectBenchmarkPacket(tvbuf, pktinfo, tree, offset)

  --
  pktinfo.cols.info = "Benchmark packet."

  --  
  return 0
end

--------------------------------------------------------------------------------
--
-- @Return
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

-- 
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
}

-----------------------------------------------
-- Enable dissector function.
-- 
local function enableDissector()

  --
	local udp_encap_table = DissectorTable.get("udp.port")
	local tcp_encap_table = DissectorTable.get("tcp.port")
	
	--
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

  --
  local udp_encap_table = DissectorTable.get("udp.port")
  local tcp_encap_table = DissectorTable.get("tcp.port")

  --    
  if udp_encap_table:get_dissector(54321) then
    udp_encap_table:remove(54321, udp_encap_table:get_dissector(54321))
   end
   
  --
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
