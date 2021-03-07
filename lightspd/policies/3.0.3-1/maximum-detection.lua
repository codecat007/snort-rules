---------------------------------------------------------------------------
-- maximum detection policy
---------------------------------------------------------------------------

_policyInformation =
{
   id = "max-detect-ips",
   version = "2020-07-29-001",
   name = "Maximum Detection",
   description = "This policy places all emphasis on security.  Network connectivity and throughput is not guaranteed and false positives are likely.  This policy should only be used for high security areas and security monitors must be prepared to investigate alerts to determine their validity.",
   snort2equivalent = "experimental-1",
   securityLevel = 40,
   displayOrder = 10,
   isSnort2LegacyPolicy = true
}

NAP = "includes/maximum-detection_NAP.lua"
include(NAP)

IPS = "includes/maximum-detection_IPS.lua"
include(IPS)
