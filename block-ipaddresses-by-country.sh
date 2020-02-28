#!/bin/bash

# internet-facing network interface
iface=eth0

# local port numbers to check for connections from unwanted IP addresses
ports=(22 443)

# whitelisted country codes
whitelist=(CA EG KW)

# get foreign IP addresses from connections to our specified local port numbers
estconns=`netstat -tun | awk '{print $4":"$5}' | awk -F: '{print $1":"$2":"$3}' | tail -n+3`
ipaddrs=()
for port in ${ports}; do
    conn=`echo ${estconns} | grep ":${port}:"`
    if [ -n "${conn}" ]; then
        ipaddrs+=(`echo ${conn} | awk -F: '{print $3}'`)
    fi
done

# remove duplicates
ipaddrs=`echo ${ipaddrs} | awk '!a[$0]++'`

whoisres=/tmp/whoisres

for ipaddr in ${ipaddrs}; do
    whois ${ipaddr} > ${whoisres}

    # extract country code from whois result
    country=`cat ${whoisres} | grep 'country:' | awk '{print $2}'`

    # extract IP address range from whois result
    inetnum=`cat ${whoisres} | grep 'inetnum:' | awk '{print $2"-"$4}'`

    found=0
    for entry in "${whitelist[@]}"; do
        if [[ ${country} == ${entry} ]]; then
            found=1
            break
        fi
    done
    if [[ ${found} -eq 0 && -n ${inetnum} ]]; then

        # block using iptables
        iptables -A INPUT -i ${iface} -m iprange --src-range ${inetnum} -j DROP

    fi
done
