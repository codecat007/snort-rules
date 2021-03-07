---------------------------------------------------------------------------
-- balanced connectivity and security policy
---------------------------------------------------------------------------

_policyInformation =
{
   id = "balanced-ips",
   version = "2020-07-29-001",
   name = "Balanced Security and Connectivity",
   description = "This policy attempts to strike the delicate balance between network connectivity and throughput and the needs of security.  While not as strict as Security Over Connectivity, this policy attempts to keep users secure while being less obtrusive about normal traffic.",
   snort2equivalent = "balanced-security-and-connectivity",
   securityLevel = 20,
   displayOrder = 30,
   isSnort2LegacyPolicy = true
}

NAP = "includes/balanced-security-and-connectivity_NAP.lua"
include(NAP)

IPS = "includes/balanced-security-and-connectivity_IPS.lua"
include(IPS)
