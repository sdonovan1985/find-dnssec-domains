import subprocess
import sys
from datetime import datetime


def get_dig_cmd_output(cmd, domain):
    final_cmd = cmd
    final_cmd.append(domain)
    output = subprocess.check_output(final_cmd)
    return output

def log_output(filename, output):
    for line in output:
        filename.write(line)

    filename.write("\n\n\n")



if __name__ == "__main__":
    if not (len(sys.argv) == 3 or len(sys.argv) == 4):
        print "Syntax:"
        print "    python get_dig_from_list.py <start-entry> <# of entries> <optional:sourcefile>"
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
    logfilename = datetime.now().strftime('digfile_%Y_%m_%d_%H_%M_%S.log')

    # Add whatever dig commands necessary:
    digcmd = ["dig", "@192.168.56.101", "+dnssec"]

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

        output = get_dig_cmd_output(digcmd, domain_name)
        log_output(log_file, output)
        #do any processing of output here

        
    input_file.close()
    log_file.close()
    
