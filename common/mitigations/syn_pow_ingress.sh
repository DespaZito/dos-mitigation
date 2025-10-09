#!/bin/bash

_toggle=$1
_default_k=$2

if [ -z "$3" ]; then
    _devs=($(/usr/local/dos-mitigation/common/bin/list_exp_devs))
else
    _devs=($3)
fi


for _dev in "${_devs[@]}"; do
  /usr/local/dos-mitigation/common/ebpf/bin/tc_clear $_dev # clear mac address
  if [[ $_toggle -eq 1 ]]; then

  # | Ip address | threshold_k |
# | 10.0.0.1   | 16          |

# | MAC address | threshold_k |
# | doijfoijof  | 16          |


    # get IP address of current mac address = client
    # Retrieve K for that ip address from table
    # Calculate threshold with K for this client

    # theta = 2^32 * ((k-1) / k)
    default_pow_threshold=$(echo "(($_default_k - 1) / $_default_k) * 4294967296.0" | bc -l)
    # strip decimals
    default_pow_threshold=${default_pow_threshold%.*}
    clang -O2 -target bpf -D DEFAULT_POW_THRESHOLD=$default_pow_threshold -c /usr/local/dos-mitigation/common/ebpf/syn_pow.c -o syn_pow\
      -I /usr/include/bpf\
      -I /usr/include/iproute2\
      -I /usr/include/x86_64-linux-gnu\
      -Wno-int-to-void-pointer-cast
      
    /usr/local/dos-mitigation/common/ebpf/bin/tc_load_ingress syn_pow $interface
  fi
done
