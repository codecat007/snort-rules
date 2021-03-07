---------------------------------------------------------------------------
-- connectivity over security policy
---------------------------------------------------------------------------

_policyInformation =
{
   id = "connectivity-ips",
   version = "2020-07-29-001",
   name = "Connectivity Over Security",
   description = "This policy places an emphasis on network connectivity and throughput, at the possible expense of security.  Traffic is inspected less deeply, and less rules are evaluated.",
   snort2equivalent = "connectivity-over-security",
   securityLevel = 10,
   displayOrder = 40,
   isSnort2LegacyPolicy = true
}

NAP = "includes/connectivity-over-security_NAP.lua"
include(NAP)

IPS = "includes/connectivity-over-security_IPS.lua"
include(IPS)
