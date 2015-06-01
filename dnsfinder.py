import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype
import sys
from datetime import datetime



# Based on some of the code in;
# https://stackoverflow.com/questions/26137036/programmatically-check-if-domains-are-dnssec-protected
# https://stackoverflow.com/questions/5235569/using-the-dig-command-in-python
# https://stackoverflow.com/questions/3898363/python-dns-resolver-set-specific-dns-server
# http://www.dnspython.org/examples.html

def get_dnssec_status(dnsresolver, domain_name):

    # Clean up the input with the final .
    if not domain_name.endswith("."):
        domain_name = domain_name + "."

    # get nameservers for target domain
    response = dnsresolver.query(domain_name, dns.rdatatype.NS)

    # we'll use the first nameserver in this example
    nsname = response.rrset[0] # name
    response = dnsresolver.query(str(nsname), dns.rdatatype.A)
    nsaddr = response.rrset[0].to_text() # IPv4
    
    # get DNSKEY for zone
    request = dns.message.make_query(domain_name,
                                     dns.rdatatype.DNSKEY,
                                     want_dnssec=True)

    # send the query
    response = dns.query.udp(request,nsaddr)
    if response.rcode() != 0:
        raise Exception("get_dnssec_status: rcode was not 0")

        # HANDLE QUERY FAILED (SERVER ERROR OR NO DNSKEY RECORD)

        # answer should contain two RRSET: DNSKEY and RRSIG(DNSKEY)
    answer = response.answer
    if len(answer) != 2:
        # SOMETHING WENT WRONG
        raise Exception("get_dnssec_status: lenght of answer != 2, " +
                        str(len(answer)))

    # the DNSKEY should be self signed, validate it
    name = dns.name.from_text(domain_name)
    try:
        dns.dnssec.validate(answer[0],answer[1],{name:answer[0]})
    except dns.dnssec.ValidationFailure:
        raise Exception("get_dnssec_status: Failed validation.")

    else:
        # WE'RE GOOD, THERE'S A VALID DNSSEC SELF-SIGNED KEY FOR example.com
        print "valid"





if __name__ == "__main__":
    if len(sys.argv) != 2 or len(sys.argv) != 3:
        print "Syntax:"
        print "    dnsfinder <# of entries> <optional:sourcefile>"
        print " sourcefile must be in a csv format with the domain in the"
        print " second column. Otherwise, will use the file:"
        print "    alexa-files/top-1m.csv"
        exit

    linecount = int(sys.argv[1])
    filename = "alexa-files/top-1m.csv"
    if len(sys.argv) == 3:
        filename = sys.argv[2]

    # Thanks to https://stackoverflow.com/questions/9135936/want-datetime-in-logfile-name
    logfilename = datetime.now().strftime('results_%Y_%m_%d_%H_%M_%S.log')


    dnsresolver = dns.resolver.Resolver()
    # Specific nameserver to my configuration. You will need to change this!
#    dnsresolver.nameservers = ["192.168.56.101"]
    dnsresolver.nameservers = ["8.8.8.8"]
    
    
    
    
