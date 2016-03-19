#!/bin/bash
#Mike Kelly
#@lixmk

echo " "
echo "###################################################################################"
echo "# int-auto-recon.sh performs recon, enumeration, and vulnerability identification #"
echo "#                                                                                 #"
echo "#                         Some Alpha ass shit right here.                         #"
echo "#                 Probably riddled with typos, don't run in prod.                 #"
echo "#                                                                                 #"
echo "#             WARNING: This is NOT QUIET. In fact, it's FUCKING LOUD.             #"
echo "#             WARNING: This is NOT QUIET. In fact, it's FUCKING LOUD.             #"
echo "#             WARNING: This is NOT QUIET. In fact, it's FUCKING LOUD.             #"
echo "#                                                                                 #"
echo "#        Please check the readme for a list of tools used and dependacies.        #"
echo "###################################################################################"
echo " "

EXPECTED_ARGS=1;
if [ $# -ne $EXPECTED_ARGS ]
then
	echo "Usage: `basename $0` <target file (nmap format)>"
	exit 1
fi

#Creating directory structure
mkdir ./int-auto-recon
mkdir ./int-auto-recon/nmap
mkdir ./int-auto-recon/nmap/targets
mkdir ./int-auto-recon/ports
mkdir ./int-auto-recon/nikto
mkdir ./int-auto-recon/initial
mkdir ./int-auto-recon/medusa
mkdir ./int-auto-recon/ssh-ciphers
mkdir ./int-auto-recon/sslciphers
mkdir ./int-auto-recon/robots
mkdir ./int-auto-recon/enum4linux
mkdir ./int-auto-recon/enum4linux/users
mkdir ./int-auto-recon/enum4linux/shares

cd ./int-auto-recon/

#Checking whether or not to start responder
echo "Do you want to start Responder in a screen session?"
echo -n "'yes' or 'no': "
read -e RESPYN

if [ "$RESPYN" = "yes" ]
then
	echo -n "Local IP:"
	read -e LIP
	echo "Starting responder session with -i $LIP. Other tests continuing."
	echo ""
	screen -dmS responder -m responder -i $LIP 
else

	echo "No Responder session started. Testing will continue."
	echo ""
fi


#Nmap All TCP ports on all tagets
	echo '[*] Initiating Full TCP port scan of all targets'
	echo '[*] Timing updates provided every 120 seconds'
	nmap -Pn --stats-every 120s --max-rtt-timeout 250ms --max-retries 3 --open --top-ports=65535 -oA ./nmap/fullscan -iL ./ips.txt | egrep '(remaining|Stats: )'
	echo '[*] Full Scan Complete - Sorting Output'
	cat ./nmap/fullscan.gnmap | grep open | cut -d " " -f 2 | grep -v Nmap > ./nmap/targets/listening_hosts.txt
	echo '[*] Creating port file for next Nmap scan'
	cat ./nmap/fullscan.gnmap | grep -v Status | grep -v Nmap | cut -d ':' -f 3 | sed "s|/open/tcp/||g" |cut -f 1 | sed 's|///|\n|g' | sed 's/ //g' | sed 's/,//g' | cut -d '/' -f 1 | sort -u | sed ':a;N;$!ba;s/\n/,/g' | sed 's/,//' > ./nmap/targets/portfile.txt
	echo '[*] Port file complete'
	echo ""

#Nmap Script/Service Scan only againt listening hosts/ports
	ports=$(cat ./nmap/targets/portfile.txt)
	echo '[*] Initiating Script and Service scan of open ports on all responding hosts'
	echo "[*] Open ports: $ports"
	echo '[*] Timing updates provided every 60 seconds'
	nmap -Pn -sC -sV --open --stats-every 60s -oA ./nmap/script_service -iL ./nmap/targets/listening_hosts.txt -p $ports | egrep '(remaining|Stats: )'
	echo '[*] Script/Service Scan Complete'
	echo ""

#Sorting Nmap Outputs for common ports
	echo '[*] Sorting nmap output'
	cat ./nmap/fullscan.gnmap | grep '21/open' | cut -d " " -f 2 > ./ports/ftp.txt
	cat ./nmap/fullscan.gnmap | grep '22/open' | cut -d " " -f 2 > ./ports/ssh.txt
	cat ./nmap/fullscan.gnmap | grep '23/open' | cut -d " " -f 2 > ./ports/telnet.txt
	cat ./nmap/fullscan.gnmap | grep '53/open' | cut -d " " -f 2 > ./ports/dns.txt
	cat ./nmap/fullscan.gnmap | grep '80/open' | cut -d " " -f 2 > ./ports/80.txt
	cat ./nmap/fullscan.gnmap | grep '443/open' | cut -d " " -f 2 > ./ports/443.txt
	cat ./nmap/fullscan.gnmap | grep '8080/open' | cut -d " " -f 2 > ./ports/8080.txt
	cat ./nmap/fullscan.gnmap | grep '8443/open' | cut -d " " -f 2 > ./ports/8443.txt
	cat ./nmap/fullscan.gnmap | grep '1433/open' | cut -d " " -f 2 > ./ports/mssql.txt
	cat ./nmap/fullscan.gnmap | grep '3306/open' | cut -d " " -f 2 > ./ports/mysql.txt
	cat ./nmap/fullscan.gnmap | grep '3389/open' | cut -d " " -f 2 > ./ports/rdp.txt
	cat ./nmap/fullscan.gnmap | grep open | cut -d " " -f 2 | grep -v Nmap | sort -u > ./ports/allips.txt
	echo '[*] Sorting Complete'
	echo ""

#Creating csv of nmap results
	echo '[*] Creating .csv of Nmap script/service results'
	xmlstarlet sel --net -T -t -m "//state[@state='open']" -m ../../.. -v "address[@addrtype='ipv4']/@addr" -o "," -v hostnames/hostname[1]/@name -o "," -v os/osmatch[1]/@name -o "," -b -m .. -v @portid -o '/' -v @protocol -o "," -m service -i  "@tunnel" -v @tunnel -o "|" -b -v @name -o "," -v @product -o ' ' -v @version -v @extrainfo -o "," -m ../script  -v @id -o ',' -b -n -b -b -n -b -b ./nmap/script_service.xml | grep -v '^$' | sed 's/ *$//;s/,*$//' | sed "s/' */'/g" | awk -F'\t' '{ sub(/[,;][^()]*/,"",$3);for (i=1; i<NF; i++){printf "%s%s",$i,FS};printf "%s\n",$i}' | awk -F'\t' '{ sub(/ or [^()]*/,"",$3);for (i=1; i<NF; i++){printf "%s%s",$i,FS};printf "%s\n",$i}' | sed "s/\tssl|\([^\t]*\)/\t\1s/;s/\thttpss\t/\thttps\t/" | sort -uV | cut -d ',' -f 1,2,4,5,6 | sed '1iIP,Host,Port,Services,Notes' > nmap.csv
	echo '[*] csv saved as nmap.csv'
	echo ""

#Creating host port table for Report
	echo '[*] Creating Host/Port table'
	/root/tools/josko_pentest/net_discovery_reporter.rb -f ./nmap/script_service.xml
	echo '[*] Thanks JoSko! Creation complete, saved to ./Net_Discovery_Report.docx'
	echo ""

#Launching EyeWitness against Web, RDP, VNC
	echo '[*] Launching EyeWitness for Web'
	/root/tools/eyewitness/EyeWitness.py -f ./nmap/script_service.xml -d ./eyewitnessWEB --results 10000 --web --no-prompt
	echo '[*] EyeWitness for Web Complete'
	echo ""

	echo '[*] Launching EyeWitness for RDP'
	/root/tools/eyewitness/EyeWitness.py -f ./nmap/script_service.xml -d ./eyewitnessRDP --results 10000 --rdp --no-prompt
	echo '[*] EyeWitness for RDP Complete'
	echo ""

	echo '[*] Launching EyeWitness for VNC'
	/root/tools/eyewitness/EyeWitness.py -f ./nmap/script_service.xml -d ./eyewitnessVNC --results 10000 --web --no-prompt
	echo '[*] EyeWitness for VNC Complete'
	echo ""

#Tar'ing up the basics
	echo '[*] Adding intital results to initial.tar'
	cp ./nmap ./initial/
	cp ./Net_Discovery_Report.docx ./initial/
	cp -R ./eyewitness* ./initial/
	tar -cf initial.tar ./initial/
	rm -rf ./initial/
	echo "[*] Tar'ing complete"
	echo ""

#Enumerating Windows hosts for null sessions. Will pull lists of usernames
	echo '[*] Enumerating username from Windows boxes with null sessions'
	for i in $(cat ./ports/445.txt); do
		enum4linux.pl -U $i >> ./enum4linux/users/$i.txt;
	done
	cat ./enum4linux/users/*.txt | grep index | cut -d " " -f 8 | cut -f 1 | sort -u > ./enum4linux/identified-users.txt
	echo '[*] User enumeration complete'
	echo ""

#Starting basic password guessing for identified users against possible domain controllers
#Only making two guesses to help prevent lockouts
#	TODO: Figure out better way to identify possible DC's 
#	TODO: Attempt to automate finding account lockout threshold and implimenting as a var.
	echo "[*] Guessing user-as-pass and Password1 for enumerated users against possible DC's"
	medusa -m SMBNT -H ./ports/dns.txt -U ./enum4linux/identified-users.txt -p Password1 -e s -O UAP-Password1-medusa.txt
	echo "[*] Password guessing complete"
	echo ""

#	TODO: Parse these results into enum4linux for full DC dump
#	TODO: Parse these results into enum4linux for finding accessible shares across all hosts with 445 (LOUD AF)
#	TODO: Parse these results into GPP recovery script

#SSH Cipher Enumeration
	echo '[*] Testing SSH Ciphers on port 22'
	nmap --script ssh2-enum-algos -iL ./ports/ssh.txt -p 22 -oA ./ssh-ciphers/ciphers
	echo '[*] SSH Cipher Enumeration Complete'
	echo ""

#SSL Cipher Scanning
	echo '[*] Testing SSL Ciphers on ports 443, 8443, and 3389'
	for i in $(cat ./ports/443.txt); do
		java -jar /root/tools/TestSSLServer.jar $i 443 > ./ssl-ciphers/$i.443.txt && echo "[*] $i:443 Complete";
	done
	for i in $(cat ./ports/8443.txt); do
		java -jar /root/tools/TestSSLServer.jar $i 8443 > ./ssl-ciphers/$i.8443txt && echo "[*] $i:8443 Complete";
	done
	for i in $(cat ./ports/rdp.txt); do
		java -jar /root/tools/TestSSLServer.jar $i 3389 > ./ssl-ciphers/$i.3389txt && echo "[*] $i:3389 Complete";
	done
	echo '[*] SSL Cipher Test Complete'
	echo ""

#Testing Complete
echo '[*] Most tests complete. Results written to ./int-auto-recon'
echo "[*] Don't forget to check the rspndr screen for some free hashes"

