
rulestatesFileName = "rulestates-balanced-ips.states"
include('ruleDirs.lua')

if _policyInformation == nil then
   _policyInformation = { }
end

_policyInformation.IPS =
{
   id = "balanced-ips-IPS",
   version = "2020-10-20-001",
   name = "Balanced Security and Connectivity",
   description = "This policy attempts to strike the delicate balance between network connectivity and throughput and the needs of security.  While not as strict as Security Over Connectivity, this policy attempts to keep users secure while being less obtrusive about normal traffic.",
   snort2equivalent = "balanced-security-and-connectivity",
   securityLevel = 20,
   displayOrder = 30,
   isSnort2LegacyPolicy = true
}

include("missing_features.lua")
include('../../common/load_ips.lua')

