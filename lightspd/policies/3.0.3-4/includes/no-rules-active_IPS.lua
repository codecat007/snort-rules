
rulestatesFileName = "rulestates-no-rules-active.states"
include('ruleDirs.lua')

if _policyInformation == nil then
   _policyInformation = { }
end

_policyInformation.IPS =
{
   id = "no-rules-active-IPS",
   version = "2020-10-20-001",
   name = "No Rules Active",
   description = "This policy is a basic policy that configures typical preprocessor settings but does not have any rules or built-in alerts enabled.",
   snort2equivalent = "no-rules-active",
   securityLevel = 1, -- later, we're going to give this same NAP config as balanced-ips
   displayOrder = 50,
   isSnort2LegacyPolicy = true
}

include("missing_features.lua")
include('../../common/load_ips.lua')

