#!/bin/bash

_toggle=$1
_iters=$2

if [ -z "$3" ]; then
    _devs=($(/usr/local/dos-mitigation/common/bin/list_exp_devs))
else
    _devs=($3)
fi

my_ip=$(echo "$(ip addr show eth1 | grep "inet\b" | awk '{print $2}' | cut -d/ -f1)")

file="/usr/local/dos-mitigation/common/thresholds.txt"

k_value=$_iters

while IFS=',' read -r ipaddr threshold_k
do
        if [[ $ipaddr == $my_ip ]]; then
                k_value=$threshold_k
        fi
done <$file


for _dev in "${_devs[@]}"; do
  /usr/local/dos-mitigation/common/ebpf/bin/tc_clear $_dev
  if [[ $_toggle -eq 1 ]]; then
    # theta = 2^32 * ((k-1) / k)
    pow_threshold=$(echo "(($k_value - 1) / $k_value) * 4294967296.0" | bc -l)
    # strip decimals
    pow_threshold=${pow_threshold%.*}
    clang -O2 -target bpf -D POW_THRESHOLD=$pow_threshold -c /usr/local/dos-mitigation/common/ebpf/syn_pow.c -o syn_pow\
      -I /usr/include/bpf\
      -I /usr/include/iproute2\
      -I /usr/include/x86_64-linux-gnu\
      -Wno-int-to-void-pointer-cast

    /usr/local/dos-mitigation/common/ebpf/bin/tc_load_egress syn_pow $interface
  fi
done