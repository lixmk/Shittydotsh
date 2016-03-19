#!/bin/bash
# Mike Kelly
# @lixmk
# http://exfil.co
echo " "
echo "###################################################################################"
echo "# ext-auto-recon.sh performs recon, enumeration, and vulnerability identification #"
echo "#                                                                                 #"
echo "#             WARNING: This is NOT QUIET. In fact, it's FUCKING LOUD.             #"
echo "#             WARNING: This is NOT QUIET. In fact, it's FUCKING LOUD.             #"
echo "#             WARNING: This is NOT QUIET. In fact, it's FUCKING LOUD.             #"
echo "#                            (Not for convert testing)                            #"
echo "#                                                                                 #"
echo "#        Please check the readme for a list of tools used and dependacies.        #"
echo "#        This script can take a while, it's suggested to run within screen        #"
echo "###################################################################################"
echo " "

EXPECTED_ARGS=1;
if [ $# -ne $EXPECTED_ARGS ]
then
	echo "Usage: `basename $0` <target file (nmap format)>"
	exit 1
fi

mkdir ./ext-auto-recon
mkdir ./ext-auto-recon/nmap
mkdir ./ext-auto-recon/nmap/targets
mkdir ./ext-auto-recon/ports
mkdir ./ext-auto-recon/nikto
mkdir ./ext-auto-recon/initial
mkdir ./ext-auto-recon/medusa
mkdir ./ext-auto-recon/ssh-ciphers
mkdir ./ext-auto-recon/sslciphers
mkdir ./ext-auto-recon/robots

cd ./ext-auto-recon/

#All TCP ports on all tagets
    echo '[*] Initiating Full TCP port scan of all targets'
    echo '[*] Timing updates provided every 120 seconds'
    nmap -Pn --stats-every 120s --max-rtt-timeout 250ms --max-retries 3 --open --top-ports=65535 -oA ./nmap/fullscan -iL ./ips.txt | egrep '(remaining|Stats: )'
    echo '[*] Full Scan Complete - Sorting Output'
	cat ./nmap/fullscan.gnmap | grep open | cut -d " " -f 2 | grep -v Nmap > ./nmap/targets/listening_hosts.txt
	echo '[*] Creating port file for next Nmap scan'
	cat ./nmap/fullscan.gnmap | grep -v Status | grep -v Nmap | cut -d ':' -f 3 | sed "s|/open/tcp/||g" |cut -f 1 | sed 's|///|\n|g' | sed 's/ //g' | sed 's/,//g' | cut -d '/' -f 1 | sort -u | sed ':a;N;$!ba;s/\n/,/g' | sed 's/,//' > ./nmap/targets/portfile.txt
	echo '[*] Port file complete'
    echo ""

#Script/Service Scan
	ports=$(cat ./nmap/targets/portfile.txt)
	echo '[*] Initiating Script and Service scan of open ports on all responding hosts'
	echo "[*] Open ports: $ports"
	echo '[*] Timing updates provided every 120 seconds'
    nmap -Pn -sC -sV --open --stats-every 120s -oA ./nmap/script_service -iL ./nmap/targets/listening_hosts.txt -p $ports | egrep '(remaining|Stats: )'
	echo '[*] Script/Service Scan Complete'
	echo ""

#Quick Nmap UDP Scan (500, 161)
	echo '[*] Initiating UDP can for 161 and 500'
	echo '[*] Timing updates provided every 60 seconds'
	nmap -Pn -sU -sV --open --stats-every 60s -p 161,500 -oA ./nmap/udp -iL ./nmap/targets/listening_hosts | egrep '(remaining|Stats: )'
	echo '[*] UDP scan complete'
	echo ""

#Sorting Nmap Outputs
	echo '[*] Sorting nmap output'
	cat ./nmap/fullscan.gnmap | grep '21/open' | cut -d " " -f 2 > ./ports/ftp.txt
	cat ./nmap/fullscan.gnmap | grep '22/open' | cut -d " " -f 2 > ./ports/ssh.txt
	cat ./nmap/fullscan.gnmap | grep '23/open' | cut -d " " -f 2 > ./ports/telnet.txt
	cat ./nmap/fullscan.gnmap | grep '80/open' | cut -d " " -f 2 > ./ports/80.txt
	cat ./nmap/fullscan.gnmap | grep '443/open' | cut -d " " -f 2 > ./ports/443.txt
	cat ./nmap/fullscan.gnmap | grep '8080/open' | cut -d " " -f 2 > ./ports/8080.txt
	cat ./nmap/fullscan.gnmap | grep '8443/open' | cut -d " " -f 2 > ./ports/8443.txt
	cat ./nmap/fullscan.gnmap | grep '1433/open' | cut -d " " -f 2 > ./ports/mssql.txt
	cat ./nmap/fullscan.gnmap | grep '3306/open' | cut -d " " -f 2 > ./ports/mysql.txt
	cat ./nmap/fullscan.gnmap | grep '3389/open' | cut -d " " -f 2 > ./ports/rdp.txt
	cat ./nmap/udp.gnmap | grep '161/open' | cut -d " " -f 2 > ./ports/161.txt
	cat ./nmap/udp.gnmap | grep '500/open' | cut -d " " -f 2 > ./ports/500.txt
	cat ./nmap/fullscan.gnmap | grep open | cut -d " " -f 2 | grep -v Nmap | sort -u > ./ports/allips.txt
	echo '[*] Sorting Complete'
	echo ""

#Creating csv of nmap results
	echo '[*] Creating csv of Nmap results'
	xmlstarlet sel --net -T -t -m "//state[@state='open']" -m ../../.. -v "address[@addrtype='ipv4']/@addr" -o "," -v hostnames/hostname[1]/@name -o "," -v os/osmatch[1]/@name -o "," -b -m .. -v @portid -o '/' -v @protocol -o "," -m service -i  "@tunnel" -v @tunnel -o "|" -b -v @name -o "," -v @product -o ' ' -v @version -v @extrainfo -o "," -m ../script  -v @id -o ',' -b -n -b -b -n -b -b ./nmap/script_service.xml | grep -v '^$' | sed 's/ *$//;s/,*$//' | sed "s/' */'/g" | awk -F'\t' '{ sub(/[,;][^()]*/,"",$3);for (i=1; i<NF; i++){printf "%s%s",$i,FS};printf "%s\n",$i}' | awk -F'\t' '{ sub(/ or [^()]*/,"",$3);for (i=1; i<NF; i++){printf "%s%s",$i,FS};printf "%s\n",$i}' | sed "s/\tssl|\([^\t]*\)/\t\1s/;s/\thttpss\t/\thttps\t/" | sort -uV | cut -d ',' -f 1,2,4,5,6 | sed '1iIP,Host,Port,Services,Notes' > nmap.csv
	echo '[*] csv saved as nmap.csv'
	echo ""

#Creating host port table for Report
	echo '[*] Creating Host/Port table'
	/root/tools/josko_pentest/net_discovery_reporter.rb -f ./nmap/script_service.xml
	echo '[*] Thanks JoSko! Creation complete, saved to ./Net_Discovery_Report.docx'

#Launching EyeWitness
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

#Launching Nikto against valid targets
	cd ./nikto
	
	#Creating target list
    echo '[*] Creating target list'
    for i in $(cat ../ports/80.txt); do
    	echo "nikto -Tuning x6 -maxtime 60m -output "$i-80-nikto.txt" -host http://$i" >> targets.txt;
    done
    for i in $(cat ../ports/8080.txt); do
    	echo "nikto -Tuning x6 -maxtime 60m -output "$i-8080-nikto.txt" -host http://$i:8080" >> targets.txt;
    done
    for i in $(cat ../ports/443.txt); do
    	echo "nikto -Tuning x6 -maxtime 60m -output "$i-443-nikto.txt" -host https://$i" >> targets.txt;
    done
	for i in $(cat ../ports/8443.txt); do
		echo "nikto -Tuning x6 -maxtime 60m -output "$i-8443-nikto.txt" -host https://$i:8443" >> targets.txt;
	done

	#Splitting target list and launching backgrounded sessions
    	echo '[*] Splitting targets and launching backgrounded sessions'
    	split -e -n l/5 targets.txt nik2
    	for i in $(ls nik2*);
            do echo "   [*] Backgrounding Nikto Screen Session: $i"
                screen -dmS $i sh $i;
        	done
		echo '[*] Nikto sessions screened. Continuing additional tests'
		cd ../

#Medusa some targets
	echo '[*] Starting Basic Medusa password guesses'
	echo '[*] Backgrounding SSH guesses'
	screen -dmS ssh -m medusa -M ssh -H ./ports/ssh.txt -u root -p Password1 -e ns -O ./medusa/ssh.medusa
	echo '[*] Backgrounding FTP guesses'
	screen -dmS ssh -m medusa -M ftp -H ./ports/ftp.txt -U /root/wordlists/ftpusers.txt -p Password1 -e ns -O ./medusa/ftp.medusa

#SSH Cipher Enumeration
    echo '[*] Testing SSH Ciphers on port 22'
	nmap --script ssh2-enum-algos -iL ./ports/ssh.txt -p 22 -oA ./ssh-ciphers/ciphers
    echo ""

#SSL Cipher Scanning
	echo '[*] Testing SSL Ciphers on ports 443 and 8443'
	for i in $(cat ./ports/443.txt); do
		java -jar /root/tools/TestSSLServer.jar $i 443 > ./ssl-ciphers/$i.443.txt && echo "[*] $i:443 Complete";
	done
	for i in $(cat ./ports/8443.txt); do
		java -jar /root/tools/TestSSLServer.jar $i 8443 > ./ssl-ciphers/$i.8443txt && echo "[*] $i:8443 Complete";
	done
	echo '[*] SSL Cipher Test Complete'
	echo ""

#Checking for robots.txt
	echo '[*] Checking for robots.txt on common http(s) ports'

	#Checking hosts with 80 open
	echo '[*]Checking for robots.txt on port 80'
	for i in $(cat ./ports/80.txt); do
		wget --max-redirect 0 -q -t 1 -T 3 -O ./robots/$i-80 http://$i/robots.txt && fgrep -q "Disallow" ./robots/$i-80 || rm ./robots/$i-80; sed -i "1s/^/$i:80\n/" ./robots/$i-80 2> /dev/null && echo "   [*]Robots.txt found for $i:80";
	done

	#Checking hosts with 443 open
	echo '[*]Checking for robots.txt on port 443'
	for i in $(cat ./ports/443.txt); do
		wget --max-redirect 0 --no-check-certificate -q -t 1 -T 3 -O ./robots/$i-443 https://$i/robots.txt && fgrep -q "Disallow" ./robots/$i-443 || rm ./robots/$i-443; sed -i "1s/^/$i:443\n/" ./robots/$i-443 2> /dev/null && echo "   [*]Robots.txt found for $i:443";
	done

	#Checking hosts with 8080 open
	echo '[*]Checking for robots.txt on port 8080'
	for i in $(cat ./ports/8080.txt); do
		wget --max-redirect 0 -q -t 1 -T 3 -O ./robots/$i-8080 http://$i:8080/robots.txt && fgrep -q "Disallow" ./robots/$i-8080 || rm ./robots/$i-8080; sed -i "1s/^/$i:8080\n/" ./robots/$i-8080 2> /dev/null && echo "   [*]Robots.txt found for $i:8080";
	done

	#Checking hosts with 8443 open
	echo '[*]Checking for robots.txt on port 8443'
	for i in $(cat ./ports/8443.txt); do
		wget --max-redirect 0 --no-check-certificate -t 1 -T 3 --read-timeout=3 -O ./robots/$i-8443 https://$i:8443/robots.txt && fgrep -q "Disallow" ./robots/$i-8443 || rm ./robots/$i-8443; sed -i "1s/^/$i:8443\n/" ./robots/$i-8443 2> /dev/null && echo "   [*]Robots.txt found for $i:8443";
	done
	echo '[*] robots.txt tests complete'
	echo ""
	
#Checking common http(s) ports for TRACE
	echo '[*] Testing common http(s) ports for TRACE'
	#80
	for i in $(cat ./ports/80.txt);
    	do curl -k -i -s -X TRACE -H "Cookie: Hail=Spydra" -H "Header: Proof_Of_Concept" http://$i/ | fgrep -q "Cookie: Hail=Spydra" && echo -e "\e[1;31m[Success]\e[0mTrace successful for $i on port 80" | tee -a trace_results.txt
	done
	#443
	for i in $(cat ./ports/443.txt);
		do curl -k -i -s -X TRACE -H "Cookie: Hail=Spydra" -H "Header: Proof_Of_Concept" https://$i/ | fgrep -q "Cookie: Hail=Spydra" && echo -e "\e[1;31m[Success]\e[0m Trace successful for $i on port 443" | tee -a trace_results.txt
	done
	#8080
	for i in $(cat ./ports/8080.txt);
        do curl -k -i -s -X TRACE -H "Cookie: Hail=Spydra" -H "Header: Proof_Of_Concept" http://$i:8080/ | fgrep -q "Cookie: Hail=Spydra" && echo -e "\e[1;31m[Success]\e[0m Trace successful for $i on port 8080" | tee -a trace_results.txt
	done
	#8443
	for i in $(cat ./ports/8443.txt);
        do curl -k -i -s -X TRACE -H "Cookie: Hail=Spydra" -H "Header: Proof_Of_Concept" https://$i:8443/ | fgrep -q "Cookie: Hail=Spydra" && echo -e "\e[1;31m[Success]\e[0m Trace successful for $i on port 8443" | tee -a trace_results.txt
	done

#IKE VPN stuff
	sudo -v
	echo -e "[*] Running IKE tests.. "
	# Encryption algorithms: DES, Triple-DES, AES/128, AES/192 and AES/256
	ENCLIST="1 5 7/128 7/192 7/256"
	# Hash algorithms: MD5 and SHA1
	HASHLIST="1 2"
	# Authentication methods: Pre-Shared Key, RSA Signatures, Hybrid Mode and XAUTH
	AUTHLIST="1 3 64221 65001"
	# Diffie-Hellman groups: 1, 2 and 5
	GROUPLIST="1 2 5"
	#
	trans=""
	for ENC in $ENCLIST; do
		for HASH in $HASHLIST; do
	    	for AUTH in $AUTHLIST; do
	        	for GROUP in $GROUPLIST; do
	            	trans="$trans $ENC,$HASH,$AUTH,$GROUP"
	    		done
	    	done
		done
	done

	for b in $(cat ./ports/500.txt); do
    	echo -e "[*] Testing $b for Aggressive mode" 
        for i in $trans;  do
            sudo ike-scan --trans=$i -r 1 -A -M --id=admin --pskcrack=ike_results/$b.psk $b | fgrep -q "Aggressive Mode Handshake returned" && echo -e "[*] --trans=$i Returned Aggressive Mode Handshake - Writing PSK to ike_results/$b.psk" && echo "ike-scan --trans=$i -r 1 -A -M --id=admin --pskcrack=ike_results/$b.psk $b" >>  ike_results/results.txt
        done
	done
cd ../

#Testing Complete
#TODO - Consider leaving script live until all nikto sessions are completed
#TODO - If above completed, merge post-nikto.sh to ext-auto-recon
echo '[*] Most tests complete. Results written to ./ext-auto-recon'
echo '[*] Nikto sessions may still be running. Comfirm with "screen -dr nikto"'
echo '[*] Once all Nikto sessions are complete, consider running "post-nikto.sh'
echo "[*] Or don't, I don't care"
