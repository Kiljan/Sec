#!/bin/bash

declare -a StringArray=("@8.8.8.8" "@1.1.1.1" "@9.9.9.9" "@208.67.222.222" "@185.228.168.9" "@76.76.19.19" "@94.140.14.14")

echo "W parametrach mozna podawc wiele domen po spacji. Przyklad:"
echo "==> multipleDnsScan.sh twitter.com lol.com google.com"
echo "Servery DNS znajduja sie bezposrednio w skrypcie multipleDnsScan.sh)"

echo ""
echo ""

for i in "$@"
do
for j in "${StringArray[@]}"
do
echo "Wyniki dla domeny ==>" $i "oraz servera DNS ==>" $j
dig $i any +noall +answer $j
done
done

#Provider Primary DNS Secondary DNS
#Google 8.8.8.8         8.8.4.4
#Quad9         9.9.9.9         149.112.112.112
#OpenDNS Home 208.67.222.222 208.67.220.220
#Cloudflare 1.1.1.1         1.0.0.1
#CleanBrowsing 185.228.168.9 185.228.169.9
#Alternate DNS 76.76.19.19 76.223.122.150
#AdGuard DNS 94.140.14.14 94.140.15.15
