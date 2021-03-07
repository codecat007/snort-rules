--
-- Loads components of the ips table to create the IPS policy
-- 
-- Provide rulestatesFileName, which is the name used for the rule states, and
-- ruleDirs, which is an array of strings of paths to where to find rules (all types)
--
-- ruleDirs is always required.  rulestatesFileName is only required if loading rule states
--
-- If you don't want to load the rule states, or don't want to load the rule files,
-- set DO_NOT_LOAD_RULE_STATES or DO_NOT_LOAD_RULES to any value prior to inclusion
--

include('snort_variables.lua')
include('snort_defaults.lua')
include('file_magic.lua')

-- So file_type rules work
if file_id == nil then
   file_id = { }
end

if file_id.file_rules == nil then
   file_id.file_rules = file_magic
end

-- so rules load
if references == nil then
   references = default_references
end

-- so rule load
if classifications == nil then
   classifications = default_classifications
end

if ruleDirs == nil then
   print("load_ips: ruleDirs == nil")
   os.exit(-1)
end

if ips == nil then
   ips = { }
end

if DO_NOT_LOAD_RULE_STATES == nil then

   if rulestatesFileName == nil then
      print("load_ips: rulestatesFileName == nil")
      os.exit(-1)
   end

   if ips.states == nil then
      ips.states = ""
   end
end

if DO_NOT_LOAD_RULES == nil then

   if ips.rules == nil then
      ips.rules = ""
   end
end

for i,v in ipairs(ruleDirs) do

   if DO_NOT_LOAD_RULE_STATES == nil then
      ips.states = ips.states .. "include " .. v .. "/" .. rulestatesFileName .. "\n"
   end

   if DO_NOT_LOAD_RULES == nil then
      if string.find(v, "builtins") then
         ips.rules = ips.rules .. "include " .. v .. "/builtins.rules\n"
      else
         ips.rules = ips.rules .. "include " .. v .. "/includes.rules\n"
      end
   end
end

