NUM_FILES = 10

def getIPaddrs(file):
    with open(file, "r") as f:
        src_addr, dest_addr = f.read().split(" ")
        dest_addr = dest_addr.strip() # Remove \n from dest_addr
    return src_addr, dest_addr

# Can probably just modify this to take two IP arguments and combine with getIPaddrs to reduce # of lines of code
def pack_ip(ip):
    unpack_bytes = ip.split(".")
    byte_arr = bytearray()
    for num in unpack_bytes:
        byte_arr.append(int(num))
    return bytes(byte_arr)

def createPsuedoIPHeader(src, dest, tcp_len):
    byte_arr = bytearray()
    zero = b'\x00'
    ptcl = b'\x06'
    components = [src, dest, zero, ptcl, tcp_len]
    for component in components:
        byte_arr.append(component)
    return byte_arr

def processTCPData(file):
    with open(file, "rb") as fp:
        tcp_data = fp.read()
        extracted_checksum = tcp_data[16:18]
        tcp_length = len(tcp_data)
        gen_new_zero_cksum_tcp = tcp_data[:16] + b'\x00\x00' + tcp_data[18:]
        if len(gen_new_zero_cksum_tcp) % 2 == 0:
            gen_new_zero_cksum_tcp += b'\x00'
        return tcp_length, extracted_checksum, gen_new_zero_cksum_tcp

def main():
    src, dest = getIPaddrs("tcp_data/tcp_addrs_0.txt")
    src_bytes, dest_bytes = pack_ip(src), pack_ip(dest)
    tcp_len, extracted_cksum, zero_cksum_tcp = processTCPData("tcp_data/tcp_data_0.dat")
    ipPsuedoHeader = createPsuedoIPHeader(src_bytes, dest_bytes, tcp_len)
    return

if __name__ == "__main__":
    main()


# Read in the tcp_addrs_0.txt file.
# Split the line in two, the source and destination addresses.
# Write a function that converts the dots-and-numbers IP addresses into bytestrings.
# Read in the tcp_data_0.dat file.
# Write a function that generates the IP pseudo header bytes from the IP addresses from tcp_addrs_0.txt and the TCP length from the tcp_data_0.dat file.
# Build a new version of the TCP data that has the checksum set to zero.
# Concatenate the pseudo header and the TCP data with zero checksum.
# Compute the checksum of that concatenation
# Extract the checksum from the original data in tcp_data_0.dat.
# Compare the two checksums. If they’re identical, it works!
# Modify your code to run it on all 10 of the data files. The first 5 files should have matching checksums! The second five files should not! That is, the second five files are simulating being corrupted in transit.


