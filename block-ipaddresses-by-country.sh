#!/bin/bash

# internet-facing network interface
iface=eth0

# local port numbers to check for connections from unwanted IP addresses
ports=(22 3306 25060 443 80 5900 222)

# whitelisted country codes
whitelist=(CA EG KW)

if [[ $1 == '-v' ]]; then
   debug=1
fi

# get foreign IP addresses from connections to our specified local port numbers
estconnsres=/tmp/estconns
netstat -tun | awk '{print $4":"$5}' | awk -F: '{print $1":"$2":"$3}' | tail -n+3 > ${estconnsres}

if [[ ${debug} == 1 ]]; then
   echo "Foreign connections:"
   cat ${estconnsres}
fi

estconnportres=/tmp/estconnportres
ipaddrs=()
for port in ${ports[@]}; do
    if [[ ${debug} == 1 ]]; then
       echo "Checking for port "${port}
    fi
    cat ${estconnsres} | grep ":${port}:" > ${estconnportres}
    if [ -s ${estconnportres} ]; then
        for entry in `cat ${estconnportres}`; do
           if [[ ${debug} == 1 ]]; then
              echo "Adding entry: "${entry}
           fi
           ipaddrs+=(`echo ${entry} | awk -F: '{print $3}'`)
        done
    fi
done

if [[ ${debug} == 1 ]]; then
   echo "IP address list:"
   for entry in ${ipaddrs[@]}; do
      echo ${entry}
   done
fi

whoisres=/tmp/whoisres

for ipaddr in ${ipaddrs[@]}; do
    whois ${ipaddr} > ${whoisres}

    # extract country code from whois result
    country=`cat ${whoisres} | grep 'country:' | awk '{print $2}'`

    # extract IP address range from whois result
    inetnum=`cat ${whoisres} | grep 'inetnum:' | awk '{print $2"-"$4}'`
    if [[ -z ${inetnum} ]]; then
       inetnum=`cat ${whoisres} | grep 'NetRange:' | head -n 1 | awk '{print $2"-"$4}'`
    fi

    found=0
    for entry in "${whitelist[@]}"; do
        if [[ ${country} == ${entry} ]]; then
            found=1
            break
        fi
    done
    if [[ ${found} == 1 ]]; then
         if [[ ${debug} == 1 ]]; then
            echo "Allowing ${ipaddr}"
         fi
         continue
    fi
    if [[ ${debug} == 1 ]]; then
        echo "Blackist ${ipaddr} in range ${inetnum}"
    fi
    if [[ ${found} -eq 0 && -n ${inetnum} ]]; then
        res=`iptables -L INPUT | grep ${inetnum}`
        if [[ -n ${res} ]]; then
           echo "The following rule already exists:"
           echo ${res}
        else
           # block using iptables
           echo "Executing: iptables -A INPUT -i ${iface} -m iprange --src-range ${inetnum} -j DROP"
           iptables -A INPUT -i ${iface} -m iprange --src-range ${inetnum} -j DROP
        fi
    fi
done
