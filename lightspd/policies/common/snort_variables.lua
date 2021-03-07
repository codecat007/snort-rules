
---------------------------------------------------------------------------
-- Set paths, ports, and nets:
--
-- variables with 'PATH' in the name are vars
-- variables with 'PORT' in the name are portvars
-- variables with 'NET' in the name are ipvars
-- variables with 'SERVER' in the name are ipvars
---------------------------------------------------------------------------

---------------------------------------------------------------------------
-- default networks
---------------------------------------------------------------------------

-- By default, rules will work in, out, and laterally
HOME_NET = 'any'
EXTERNAL_NET = 'any'

-- List of DNS servers on your network 
DNS_SERVERS = HOME_NET

-- List of ftp servers on your network
FTP_SERVERS = HOME_NET

-- List of web servers on your network
HTTP_SERVERS = HOME_NET

-- List of sip servers on your network
SIP_SERVERS = HOME_NET

-- List of SMTP servers on your network
SMTP_SERVERS = HOME_NET

-- List of sql servers on your network 
SQL_SERVERS = HOME_NET

-- List of ssh servers on your network
SSH_SERVERS = HOME_NET

-- List of telnet servers on your network
TELNET_SERVERS = HOME_NET

-- other variables, these should not be modified

---------------------------------------------------------------------------
-- default ports - used in Talos rules
---------------------------------------------------------------------------

-- List of ports you run ftp servers on
FTP_PORTS = ' 21 2100 3535'

-- List of ports you run web servers on
HTTP_PORTS =
[[
    80 81 311 383 591 593 901 1220 1414 1741 1830 2301 2381 2809 3037 3128
    3702 4343 4848 5250 6988 7000 7001 7070 7144 7145 7510 7777 7779 8000 8008
    8014 8028 8080 8085 8088 8090 8118 8123 8180 8181 8243 8280 8300 8800
    8888 8899 9000 9060 9080 9090 9091 9443 9999 10443 11371 34443 34444 41080
    50002 55555 
]]

-- List of ports you run mail servers on
MAIL_PORTS = ' 110 143'

-- List of ports you might see oracle attacks on
ORACLE_PORTS = ' 1024:'

-- List of ports you run SIP servers on
SIP_PORTS = ' 5060 5061 5600'

-- List of ports you want to look for SSH connections on
SSH_PORTS = ' 22'

-- List of ports for file inspection
FILE_DATA_PORTS = HTTP_PORTS .. MAIL_PORTS


if MISSING_IPS_VARIABLES == nil or MISSING_IPS_VARIABLES_SUBTABLES == nil then

   if ips == nil then
      ips = { }
   end

   if ips.variables == nil then
      ips.variables = { }
   end
end

if MISSING_IPS_VARIABLES_SUBTABLES == nil then
   
   if ips.variables.nets == nil then
      ips.variables.nets = { }
   end
   
   if ips.variables.ports == nil then
      ips.variables.ports = { }
   end
   
   if ips.variables.paths == nil then
      ips.variables.paths = { }
   end
end


if MISSING_IPS_VARIABLES == nil or MISSING_IPS_VARIABLES_SUBTABLES == nil then

   env = getfenv()

   for j,k in pairs(env)
   do
      if( string.match(j, "_PORTS") or string.match(j, "_NET") or
          string.match(j, "_PATH") or string.match(j, "_SERVERS"))
      then
   
         --print(k .. " = " .. j)
   
         -- first version is just putting all snort variables in ips.variables
         -- Note I'm breaking convention here a little regarding missing features
         -- because I don't want to have to carry MISSING_IPS_VARIABLES forward
         -- in perpetuity.  
         -- This essentially means !MISSING_IPS_VARIABLES && MISSING_IPS_VARIABLES_SUBTABLES
         if MISSING_IPS_VARIABLES_SUBTABLES ~= nil then
            ips.variables[j] = k
         end
   
         -- new version is copying variables into subtables under ips.variables
         if MISSING_IPS_VARIABLES_SUBTABLES == nil then
            if(string.match(j, "_PORTS")) then

               ips.variables.ports[j] = k

            elseif(string.match(j, "_NET") or string.match(j, "_SERVERS")) then

               ips.variables.nets[j] = k

            elseif(string.match(j, "_PATH")) then

               ips.variables.paths[j] = k

            end
         end
   
         -- remove it from the global table
         env[j] = nil
   
      end
   end
end

