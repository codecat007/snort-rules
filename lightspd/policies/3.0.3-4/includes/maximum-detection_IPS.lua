
rulestatesFileName = "rulestates-max-detect-ips.states"
include('ruleDirs.lua')

if _policyInformation == nil then
   _policyInformation = { }
end

_policyInformation.IPS =
{
   id = "max-detect-ips-IPS",
   version = "2020-10-20-001",
   name = "Maximum Detection",
   description = "This policy places all emphasis on security.  Network connectivity and throughput is not guaranteed and false positives are likely.  This policy should only be used for high security areas and security monitors must be prepared to investigate alerts to determine their validity.",
   snort2equivalent = "experimental-1",
   securityLevel = 40,
   displayOrder = 10,
   isSnort2LegacyPolicy = true
}

include("missing_features.lua")
include('../../common/load_ips.lua')

