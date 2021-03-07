
include('snort_defaults.lua')
include('file_magic.lua')

env = getfenv()

detection = { }
search_engine = { }
normalizer = { }

stream = { }
stream_ip = { }
stream_icmp = { }
stream_tcp = { }
stream_udp = { }
stream_user = { }
stream_file = { }

appid = { }

arp_spoof = { }
back_orifice = { }

dns = { }

http_inspect = { }
if MISSING_HTTP2 == nil then
   http2_inspect = { }
end

imap = { }
pop = { }

rpc_decode = { }
ssh = { }
ssl = { }

telnet = { }

dce_smb = { }
dce_tcp = { }
dce_udp = { }
dce_http_proxy = { }
dce_http_server = { }

-- Industrial Control Systems (ICS) protocols
sip = { }
dnp3 = { }
modbus = { }
s7commplus = { }
cip = { }

if MISSING_IEC104 == nil then
   iec104 = { }
end

-- see snort_defaults.lua for default_*
gtp_inspect = default_gtp

port_scan = default_med_port_scan

smtp = default_smtp

ftp_server = default_ftp_server
ftp_client = { }
ftp_data = { }

-- see file_magic.lua for file id rules
file_id = { file_rules = file_magic }

---------------------------------------------------------------------------
-- 4. configure performance
---------------------------------------------------------------------------

-- use latency to monitor / enforce packet and rule thresholds
--latency = { }

-- use these to capture perf data for analysis and tuning
--profiler = { }
perf_monitor = { }


---------------------------------------------------------------------------
-- 3. configure bindings
---------------------------------------------------------------------------

wizard = default_wizard
binder = default_binder

-- Remove binder entries for which there is no module configured
for i, v in pairs (binder) do
    if v.when ~= nil and v.use ~= nil then
       if env[v.use.type] == nil then
          -- Not printing status to not confuse people when it's an unsupported feature
          -- that is being removed from the binder.
          --print( v.use.type .. " module is not configured, removing binder entry")
          table.remove(binder, i)
       end
    end
end


---------------------------------------------------------------------------
-- 5. configure detection
---------------------------------------------------------------------------
-- this is also in load_ips.lua, where it belongs.  Remove this at some point.
references = default_references
classifications = default_classifications

