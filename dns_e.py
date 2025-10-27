import os
import subprocess
import shlex
import re
# Removed: from collections import OrderedDict # Not used
import sys

# --- Domain Validation Logic (Provided by user, included for completeness) ---

# domain validation: requires at least one dot and plausible labels / TLD
DOMAIN_RE = re.compile(
    r'^(?=.{1,253}$)'                             # whole length limit
    r'(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+'  # labels and dots
    r'[A-Za-z]{2,63}$'                           # TLD (letters only)
)

def is_valid_domain(d):
    """Return True if d looks like a valid domain name (simple but robust)."""
    return bool(DOMAIN_RE.match(d))

# --- Packet Filtering Function (New Core Logic) ---

def filter_dns_packets(input_pcap_file, output_pcap_file):
    """
    Filters an input PCAP file to extract only A-type DNS query packets
    and writes them to a new output PCAP file using tshark.

    The filter used is:
    "dns.flags.response == 0 && dns.qry.name && dns.qry.type == 1"
    """
    print("-> Processing {0}...".format(input_pcap_file))

    # 1. Check if the input file exists
    if not os.path.exists(input_pcap_file):
        print("   [Error] Input PCAP not found: {0}".format(input_pcap_file))
        return False

    # 2. Build the tshark command
    # -r: Read input file
    # -Y: Apply the display filter
    # -w: Write the captured packets matching the filter to the output file
    filter_expression = "dns.flags.response == 0 && dns.qry.name && dns.qry.type == 1"
    cmd = [
        "tshark",
        "-r", input_pcap_file,          # Pass raw file name
        "-Y", filter_expression,
        "-w", output_pcap_file          # Pass raw file name
    ]

    try:
        # Execute tshark by passing the command list directly.
        # This is the safest way to pass complex arguments.
        result = subprocess.run(
            cmd,
            check=True,  # Raise CalledProcessError for non-zero exit codes
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        print("   [Success] Filtered packets saved to {0}.".format(output_pcap_file))
        return True

    except subprocess.CalledProcessError as e:
        # tshark often outputs warnings/errors to stderr
        error_output = e.stderr or e.stdout or "No error output available."
        print("   [Error] tshark failed for {0}.".format(input_pcap_file))
        # Print the command that failed for easier debugging
        print("     Command: {0}".format(" ".join(cmd))) 
        print("     Tshark output: {0}".format((error_output).strip()))
        return False
    except FileNotFoundError:
        # This typically happens if 'tshark' is not in the system's PATH
        print("   [FATAL] 'tshark' command not found. Please ensure Wireshark/Tshark is installed and accessible in your system's PATH.")
        sys.exit(1)

# --- Main Execution Block ---

def main():
    """Defines the input files and executes the filtering process."""
    
    # Define the input PCAP files as requested (h1.pcap, h2.pcap, h3.pcap, h4.pcap)
    input_files = ["h1.pcap", "h2.pcap", "h3.pcap", "h4.pcap"]
    
    print("--- Starting PCAP DNS Filtering Process ---")
    
    for input_file in input_files:
        # Dynamically create the output file name (e.g., h1.pcap -> h1_dns.pcap)
        base_name, ext = os.path.splitext(input_file)
        output_file = "{0}_dns{1}".format(base_name, ext)
        
        # Run the filtering process
        filter_dns_packets(input_file, output_file)
        
    print("--- Filtering Complete ---")

# Placeholder for the original function, if domain extraction was still needed.
# For this task, we focus on the packet filtering as defined in main().
def extract_urls_from_pcap(pcap_file, host_node):
    # This logic is skipped because the primary goal is now packet filtering (-w)
    # instead of domain name extraction (-T fields).
    # If the file exists, it will be processed by filter_dns_packets() instead.
    print("Note: Domain extraction logic skipped for {0}. Executing packet filtering.".format(pcap_file))
    return []

if __name__ == "__main__":
    # In a typical environment, the files would be created by other processes.
    # To prevent immediate failure for missing files, we'll create empty dummy files
    # if they don't exist, though tshark will still complain if they're not valid PCAP.
    print("Creating dummy input files for demonstration...")
    for f in ["h1.pcap", "h2.pcap", "h3.pcap", "h4.pcap"]:
        if not os.path.exists(f):
            try:
                # Create an empty file.
                with open(f, 'w') as fp:
                    pass
            except OSError as e:
                print("Could not create dummy file {0}: {1}".format(f, e))
                
    main()