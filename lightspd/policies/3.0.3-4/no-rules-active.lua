---------------------------------------------------------------------------
-- no rules active policy
---------------------------------------------------------------------------

_policyInformation =
{
   id = "no-rules-active",
   version = "2020-07-29-001",
   name = "No Rules Active",
   description = "This policy is a basic policy that configures typical preprocessor settings but does not have any rules or built-in alerts enabled.",
   snort2equivalent = "no-rules-active",
   securityLevel = 1, -- later, we're going to give this same NAP config as balanced-ips
   displayOrder = 50,
   isSnort2LegacyPolicy = true
}

NAP = "includes/no-rules-active_NAP.lua"
include(NAP)

IPS = "includes/no-rules-active_IPS.lua"
include(IPS)
