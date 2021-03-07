
-- This date is used as the version information for all policies, which is fine (and better imo)
_policyInformation.NAP.version = "2021-03-02-001"

securityLevel = _policyInformation.NAP.securityLevel

-- set no-rules-active to be the same as balanced-ips for NAP configs
if _policyInformation.NAP.id == "no-rules-active-NAP" then
   securityLevel = 20
end


-- all policies
include('baseconfig.lua')
detection.global_default_rule_state = false
ssl.trust_servers = true
port_scan = nil
stream_ip.policy = 'windows'
stream_tcp.policy = 'windows'

cip.embedded_cip_path = '0x2 0x36'


-- just connectivity
if securityLevel == 10 then

   http_inspect.unzip = false
   http_inspect.utf8 = false

end


-- connectivity and balanced (and no-rules-active)
if securityLevel <= 20 then

   http_inspect.request_depth = 300
   http_inspect.response_depth = 500

-- This causes http/2 (and anything else non-HTTP/1.x on port 80) to be missed
--   -- for these policies, we force port 80 to be http_inspect, always, for perf reasons
--   table.insert( binder, 1,
--      { when = { proto = 'tcp', ports = '80', role = 'server'}, use = { type = 'http_inspect'}} )

end


-- security and max-detect
if securityLevel >= 30 then

   stream_tcp.small_segments =
   {
       count = 3,
       maximum_size = 150,
   }

   -- this is temporary for accounting for a bug in enable_signature
   file_id.enable_signature = true
 
   http_inspect.decompress_swf = true
   http_inspect.decompress_pdf = true
   http_inspect.decompress_zip = true
   http_inspect.percent_u = true
   http_inspect.normalize_javascript = true

   imap.b64_decode_depth = -1
   imap.bitenc_decode_depth = -1
   imap.qp_decode_depth = -1
   imap.uu_decode_depth = -1
   imap.decompress_pdf = true
   imap.decompress_swf = true
   imap.decompress_zip = true
   
   pop.b64_decode_depth = -1
   pop.bitenc_decode_depth = -1
   pop.qp_decode_depth = -1
   pop.uu_decode_depth = -1
   pop.decompress_pdf = true
   pop.decompress_swf = true
   pop.decompress_zip = true
   
   smtp.b64_decode_depth = -1
   smtp.bitenc_decode_depth = -1
   smtp.qp_decode_depth = -1
   smtp.uu_decode_depth = -1
   smtp.decompress_pdf = true
   smtp.decompress_swf = true
   smtp.decompress_zip = true
   
   telnet.check_encrypted = true
   telnet.normalize = true

   ftp_server.check_encrypted = true

end


-- just max-detect
if securityLevel == 40 then

   -- ssl.trust_servers is false by default, but above we set it to true for all policies
   ssl.trust_servers = false
   search_engine.queue_limit = 0;
   -- detect_raw_tcp makes snort 3 process raw packets like snort 2 does, which can allow
   -- poorly written rules to alert, but then you lose perf and FP resistance of Snort 3 buffers
   -- search_engine.detect_raw_tcp = true

if MISSING_SCRIPT_DETECTION == nil then
   http_inspect.script_detection = true
end

end

