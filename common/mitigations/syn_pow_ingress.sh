#!/bin/bash

ip_to_net() {
    IFS='.' read -r o1 o2 o3 o4 <<< "$1"
    echo $(( (o1 << 24) | (o2 << 16) | (o3 << 8) | o4 ))
}

_toggle=$1
_iters=$2

if [ -z "$3" ]; then
    _devs=($(/usr/local/dos-mitigation/common/bin/list_exp_devs))
else
    _devs=($3)
fi


MAP_PATH="/sys/fs/bpf/tc/globals/threshold_map"

# Remove any existing map (to clear old entries)
sudo rm "$MAP_PATH"

# Create the map if it doesnt exist
if ! sudo bpftool map show pinned "$MAP_PATH" &>/dev/null; then
    sudo bpftool map create "$MAP_PATH" \
        type hash \
        key 4 \
        value 4 \
        entries 1024 \
        name threshold_map
fi


# ====== FILL THRESHOLD TABLE ====================

file="/usr/local/dos-mitigation/common/thresholds.txt"

while IFS=',' read -r ipaddr threshold_k
do
	# Update ipaddr to network order
	net_ip=$(ip_to_net $ipaddr)

	# Convert integer to 4 bytes (little endian)
    	ip_bytes=$(printf '%d %d %d %d' \
        	$((net_ip        & 0xff)) \
       		$(((net_ip >> 8) & 0xff)) \
        	$(((net_ip >>16) & 0xff)) \
        	$(((net_ip >>24) & 0xff)))
	
	#Compute threshold for k
	# theta = 2^32 * ((k-1) / k
   pow_threshold_with_digits=$(echo "(($threshold_k - 1) / $threshold_k) * 4294967296.0" | bc -l)
	 # echo "Pow threshold is $pow_threshold_with_digits for threshold k $threshold_k"
	 pow_threshold=$(echo ${pow_threshold_with_digits%.*})
	
  # Convert integer to 4 bytes (little endian)
  	val_bytes=$(printf '%d %d %d %d' \
    	$((pow_threshold        & 0xff)) \
  		$(((pow_threshold >> 8) & 0xff)) \
  		$(((pow_threshold >>16) & 0xff)) \
 		  $(((pow_threshold >>24) & 0xff))) 

    # Insert into map
   	sudo bpftool map update pinned "$MAP_PATH" key $ip_bytes value $val_bytes

   	# Show result
	  # echo "Inserted key=$ip_bytes  ($net_ip) ($ipaddr) value=$val_bytes ($pow_threshold)"
   	# sudo bpftool map lookup pinned "$MAP_PATH" key $ip_bytes

done <$file

# =================================================

for _dev in "${_devs[@]}"; do
  /usr/local/dos-mitigation/common/ebpf/bin/tc_clear $_dev
  if [[ $_toggle -eq 1 ]]; then
    # theta = 2^32 * ((k-1) / k)
    pow_threshold=$(echo "(($_iters - 1) / $_iters) * 4294967296.0" | bc -l)
    # strip decimals
    pow_threshold=${pow_threshold%.*}
    clang -O2 -target bpf -D POW_THRESHOLD=$pow_threshold -c /usr/local/dos-mitigation/common/ebpf/syn_pow.c -o syn_pow\
      -I /usr/include/bpf\
      -I /usr/include/iproute2\
      -I /usr/include/x86_64-linux-gnu\
      -Wno-int-to-void-pointer-cast
      
    /usr/local/dos-mitigation/common/ebpf/bin/tc_load_ingress syn_pow $interface
  fi
done