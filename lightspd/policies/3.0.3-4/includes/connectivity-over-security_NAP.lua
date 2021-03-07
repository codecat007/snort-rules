
if _policyInformation == nil then
   _policyInformation = { }
end

_policyInformation.NAP =
{
   id = "connectivity-ips-NAP",
   version = "2020-08-11-001",
   name = "Connectivity Over Security",
   description = "This policy places an emphasis on network connectivity and throughput, at the possible expense of security.  Traffic is inspected less deeply, and less rules are evaluated.",
   snort2equivalent = "connectivity-over-security",
   securityLevel = 10,
   displayOrder = 40,
   isSnort2LegacyPolicy = true
}

include("missing_features.lua")
include("../../common/policy_logic.lua")

