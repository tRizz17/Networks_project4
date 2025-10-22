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
    byte_str = b''
    zero = b'\x00'
    ptcl = b'\x06'
    components = [src, dest, zero, ptcl, tcp_len]
    for component in components:
        byte_str += component
    return byte_str

def processTCPData(file):
    with open(file, "rb") as fp:
        tcp_data = fp.read()
        extracted_checksum = int.from_bytes(tcp_data[16:18], 'big')
        tcp_length = len(tcp_data)
        tcp_len_bytes = tcp_length.to_bytes(2, 'big')
        zero_cksum_tcp = tcp_data[:16] + b'\x00\x00' + tcp_data[18:]
        if len(zero_cksum_tcp) % 2 == 1:
            zero_cksum_tcp += b'\x00'
        return tcp_len_bytes, extracted_checksum, zero_cksum_tcp

def computeChecksum(header, tcp):
    data = header + tcp
    offset = 0 
    total = 0 
    while offset < len(data):
        word = int.from_bytes(data[offset:offset + 2], "big")
        total += word
        total = (total & 0xffff) + (total >> 16)
        offset += 2
    return (~total) & 0xffff

def main():
    count = 0
    while count < NUM_FILES:
        src, dest = getIPaddrs(f"tcp_data/tcp_addrs_{count}.txt")
        src_bytes, dest_bytes = pack_ip(src), pack_ip(dest)
        tcp_len, extracted_cksum, zero_cksum_tcp = processTCPData(f"tcp_data/tcp_data_{count}.dat")
        ipPsuedoHeader = createPsuedoIPHeader(src_bytes, dest_bytes, tcp_len)
        checksum = computeChecksum(ipPsuedoHeader, zero_cksum_tcp)
        if checksum == extracted_cksum:
            print(f"PASS: {checksum} == {extracted_cksum}")
        else:
            print(f"FAIL: {checksum} != {extracted_cksum}")
        count += 1

if __name__ == "__main__":
    print(main())


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


