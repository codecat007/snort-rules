#!/usr/bin/env bash

if [[ $# != 1 ]]; then
    echo "Usage: $0 <category>"
    exit
fi

category=$1

SOs=$(sed -n 's/^const BaseApi.*\(pso_[0-9]*\).*/\1/p' ${category}_*.cc)

# header
cat <<'EOF'
#include "main/snort_types.h"
#include "framework/base_api.h"

using namespace snort;

EOF

# externs
for so in $SOs; do
    echo "extern BaseApi* $so;"
done

# snort_plugins
cat <<'EOF'

SO_PUBLIC const BaseApi* snort_plugins[] =
{
EOF

for so in $SOs; do
    echo "    $so,"
done

cat <<'EOF'
    nullptr
};
EOF
