################################
#       Post Nikto Stuff       #
# This should be run after the #
# nikto screens are completed  #
################################

#Checking Nikto Results for Cookies without HTTPOnly flag set
    echo "Checking Nikto Results for Cookies without HTTPOnly flag set"
    for i in $(ls ./init-recon/nikto/*-nikto.txt); do cat $i | fgrep -q "httponly flag" && echo -n $i | cut -d '/' -f 3 | sed 's/-/:/g' | sed 's/.txt//g' >> cookie_httponly.txt && cat $i | grep "httponly flag" | awk -F " " '{ print "   "$4}' >> cookie_httponly.txt; done

#Checking Nikto Results for Cookies without Secure flag set
    echo "Checking Nikto Results for Cookies without Secure flag set"
    for i in $(ls ./init-recon/nikto/*-nikto.txt); do cat $i | fgrep -q "without the secure flag" && echo -n $i | cut -d '/' -f 3 | sed 's/-/:/g' | sed 's/.txt//g' >> cookie_secure.txt && cat $i | grep "without the secure flag" | awk -F " " '{ print "   "$5}' >> cookie_secure.txt; done
