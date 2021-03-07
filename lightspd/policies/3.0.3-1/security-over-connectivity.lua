---------------------------------------------------------------------------
-- security over connectivity policy
---------------------------------------------------------------------------

_policyInformation =
{
   id = "security-ips",
   version = "2020-07-29-001",
   name = "Security Over Connectivity",
   description = "This policy places an emphasis on security, at the possible expense of network connectivity and throughput.  Traffic is inspected more deeply, more rules are evaluated, and both false positives and increased latency are expected but within reason.",
   snort2equivalent = "security-over-connectivity",
   securityLevel = 30,
   displayOrder = 20,
   isSnort2LegacyPolicy = true
}

NAP = "includes/security-over-connectivity_NAP.lua"
include(NAP)

IPS = "includes/security-over-connectivity_IPS.lua"
include(IPS)
