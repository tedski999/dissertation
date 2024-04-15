pairs="172.0.0.2,<DCU_ECHConfig> 172.0.0.5,<TCD_ECHConfig> 172.0.0.8,<UCD_ECHConfig>"
while true; do
	dcu=$(shuf -e $pairs); tcd=$(shuf -e $pairs); ucd=$(shuf -e $pairs); echo "
	update delete dcu.example.com
	update add dcu.example.com 60 A ${dcu%%,*}
	update add dcu.example.com 60 HTTPS 1 . ech=${dcu#*,}
	update delete tcd.example.com
	update add tcd.example.com 60 A ${tcd%%,*}
	update add tcd.example.com 60 HTTPS 1 . ech=${tcd#*,}
	update delete ucd.example.com
	update add ucd.example.com 60 A ${ucd%%,*}
	update add ucd.example.com 60 HTTPS 1 . ech=${ucd#*,}
	send" | nsupdate -l
	sleep 1
done
