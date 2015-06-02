import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype
import sys
from datetime import datetime

#Rework of the dnsfinder so that it can be run in parallel more easily.


# Based on some of the code in;
# https://stackoverflow.com/questions/26137036/programmatically-check-if-domains-are-dnssec-protected
# https://stackoverflow.com/questions/5235569/using-the-dig-command-in-python
# https://stackoverflow.com/questions/3898363/python-dns-resolver-set-specific-dns-server
# http://www.dnspython.org/examples.html

def get_dnssec_status(dnsresolver, domain_name):

#    print "location 1"
    # Clean up the input with the final .
    if not domain_name.endswith("."):
        domain_name = domain_name + "."

    # get nameservers for target domain
    response = dnsresolver.query(domain_name, dns.rdatatype.NS)

#    print "location 2"

    # we'll use the first nameserver in this example
    nsname = response.rrset[0] # name
    try:
        response = dnsresolver.query(str(nsname), dns.rdatatype.A)
    except:
        raise Exception("timeout")
    nsaddr = response.rrset[0].to_text() # IPv4
    
#    print "location 3"

    # get DNSKEY for zone
    request = dns.message.make_query(domain_name,
                                     dns.rdatatype.DNSKEY,
                                     want_dnssec=True)
#    request.timeout = 1.0
#    request.lifetime = 1.0

#    print "location 4"

    # send the query
    response = dns.query.udp(request,nsaddr,timeout=1.0)
    if response.rcode() != 0:
        raise Exception("get_dnssec_status: rcode was not 0")

        # HANDLE QUERY FAILED (SERVER ERROR OR NO DNSKEY RECORD)

        # answer should contain two RRSET: DNSKEY and RRSIG(DNSKEY)

#    print "location 5"

    answer = response.answer
    if len(answer) != 2:
        # SOMETHING WENT WRONG
        raise Exception("get_dnssec_status: lenght of answer != 2, " +
                        str(len(answer)))

    # the DNSKEY should be self signed, validate it
    name = dns.name.from_text(domain_name)

#    print "location 6"

    try:
        dns.dnssec.validate(answer[0],answer[1],{name:answer[0]})
    except dns.dnssec.ValidationFailure:
        raise Exception("get_dnssec_status: Failed validation.")

    else:
        # WE'RE GOOD, THERE'S A VALID DNSSEC SELF-SIGNED KEY FOR example.com
        #print "valid"
        
#        print "location 7"

        return





if __name__ == "__main__":
    print len(sys.argv)
    if not (len(sys.argv) == 3 or len(sys.argv) == 4):
        print "Syntax:"
        print "    dnsfinder <start-entry> <# of entries> <optional:sourcefile>"
        print " sourcefile must be in a csv format with the domain in the"
        print " second column. Otherwise, will use the file:"
        print "    alexa-files/top-1m.csv"
        print " start-entry starts at 1, not 0."
        exit()

    startline = int(sys.argv[1])
    linecount = int(sys.argv[2])
    filename = "alexa-files/top-1m.csv"
    if len(sys.argv) == 4:
        filename = sys.argv[3]

    # Thanks to https://stackoverflow.com/questions/9135936/want-datetime-in-logfile-name
    logfilename = datetime.now().strftime('results_%Y_%m_%d_%H_%M_%S.log')


    dnsresolver = dns.resolver.Resolver()
    # Specific nameserver to my configuration. You will need to change this!
#    dnsresolver.nameservers = ["192.168.56.101"]
    dnsresolver.nameservers = ["8.8.8.8"]
    dnsresolver.timeout = 1.0
    dnsresolver.lifetime = 1.0
    
    input_file = open(filename, "r")
    log_file = open(logfilename, "w")

    linenum = 0

    for line in input_file:
        linenum += 1
        if linenum >= linecount + startline:
            break
        if linenum < startline:
            # skip the first <startline> lines
            continue
        
        entries = line.split(",")
        domain_name = entries[1].strip()
        print "Looking at " + domain_name
        try:
            get_dnssec_status(dnsresolver, domain_name)
            log_file.write("Successful " + domain_name + "\n")
        except:
            log_file.write("Error with " + domain_name + "\n")
        
    input_file.close()
    log_file.close()
    
    
