#!/bin/bash

if [ $# -ne 7 ]
then
   echo 
   echo "$0 <SNORTINSTALLDIR> <DAQDIR> <SNORTPOLICYVER> <SNORTMODULESVER> <ARCHITECTURE> <POLICY> <PCAPDIR>"
   echo "Ex: $0 /usr/local/bin/snort/snort3/install /usr/local/lib/daq 3.0.0-268 3.0.0-270 arch-x64 security-over-connectivity /tmp/pcaps"
   echo
   echo "SNORTINSTALLDIR is the --prefix parameter of configure_cmake.sh when you built snort3"
   echo "DAQDIR is where the DAQ plugins are installed.  This is needed for things like daq pcap reading"
   echo

   echo "Valid snort policy versions are:"
   find policies/ -maxdepth 1 -type d | sed 's/policies\///' | grep -v common | sort -r
#   egrep "^\s+\"[0-9.-]*\": {" manifest.json | sed 's/"//' | sed 's/".*//' | sed 's/^\s*/\t/g'
#   echo
   echo -n "Valid snort modules versions are:"
   find modules/ -maxdepth 1 -type d | sed 's/modules\///' | grep -v stubs
   echo
   echo "Valid architectures are:"
   for X in `ls modules/$(ls modules | grep -v stubs) | sort -u`; do echo -e "\t$X"; done
   echo
   echo "Valid policies are (usually):"
   echo "	connectivity-over-security"
   echo "	balanced-security-and-connectivity"
   echo "	security-over-connectivity"
   echo "	maximum-detection"
   echo "	no-rules-active"
   echo 
   echo "Also, this script is intended only for testing, as by default it reads pcaps and alerts to terminal"
   echo
   exit
fi;



#location of snort3 install dir
#location of daq plugins

#ls policies
#-> select version
#ls policies/${version}.lua
#-> select policy

#ls modules | grep -v stubs
#-> select version
#ls modules/${version}
#-> select architecture



SNORTINSTALLDIR=$1
DAQDIR=$2
SNORTPOLICYVER=$3
SNORTMODULESVER=$4
ARCH=$5
POLICY=$6
PCAPDIR=$7

${SNORTINSTALLDIR}/bin/snort -c policies/${SNORTPOLICYVER}/${POLICY}.lua --daq-dir $DAQDIR --plugin-path modules/${SNORTMODULESVER}/${ARCH}/ --daq dump --daq-var load-mode=read-file --pcap-dir $PCAPDIR -A cmg












exit



SNORTINSTALLDIR=$1
SNORTVER=$2
ARCH=$3
POLICY=$4
PCAPDIR=$5

# LUA_PATH is needed to be in the environment for snort3 to run.  Make sure $install is set to your environment.
# $install is the target directory of the --prefix parameter to configure_cmake.sh when you built snort3.
export install=$SNORTINSTALLDIR
export snort=$install/bin/snort
export include=$install/include/snort
export LUA_PATH=$include/lua/\?.lua\;\;

# SNORT_LUA_PATH is also needed in the environment for snort3 to run; we're synthesizing it for simplicity
MYDIR=`pwd`
export SNORT_LUA_PATH="${MYDIR}/policies/$SNORTVER/"
echo "SNORT_LUA_PATH = $SNORT_LUA_PATH"

# $ grep "\"3.0.0-255\":" --after-context=2 snort3/lightSPD/lightspd/manifest.json | grep modules | sed 's/^.*: "//' | sed 's/".*//'
# modules/3.0.0.0/
# $ grep "\"3.0.0-255\":" --after-context=2 snort3/lightSPD/lightspd/manifest.json | grep policies | sed 's/^.*: "//' | sed 's/".*//'
# policies/3.0.0-255/

# Let's parse the manifest file!
modules=`grep "\"$SNORTVER\":" --after-context=2 manifest.json | grep modules | sed 's/^.*: "//' | sed 's/".*//'`
policies=`grep "\"$SNORTVER\":" --after-context=2 manifest.json | grep policies | sed 's/^.*: "//' | sed 's/".*//'`

#$snort -c policies/$SNORTVER/$POLICY.lua --plugin-path modules/$SNORTVER/$ARCH/ --daq dump --daq-var load-mode=read-file --pcap-dir $PCAPDIR -A cmg
$snort -c ${policies}/${POLICY}.lua --plugin-path ${modules}/${ARCH}/ --daq dump --daq-var load-mode=read-file --pcap-dir $PCAPDIR -A cmg

