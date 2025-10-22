NUM_FILES = 10

def getIPaddrs(file):
    with open(file, "r") as f:
        src_addr, dest_addr = f.read().split(" ")
        dest_addr = dest_addr.strip() # remove /n from dest_addr
    return src_addr, dest_addr

def pack_ip(ip):
    unpack_bytes = ip.split(".")
    byte_arr = bytearray()
    for num in unpack_bytes:
        byte_arr.append(int(num))
    return bytes(byte_arr)

def createPsuedoIPHeader(src, dest, tcp_len):
    zero, ptcl = b'\x00', b'\x06'
    return src + dest + zero + ptcl + tcp_len

def processTCPData(file):
    with open(file, "rb") as fp:
        tcp_data = fp.read()
        extracted_checksum = int.from_bytes(tcp_data[16:18], 'big')
        tcp_len = len(tcp_data).to_bytes(2, 'big')
        zero_cksum_tcp = tcp_data[:16] + b'\x00\x00' + tcp_data[18:]
        if len(zero_cksum_tcp) % 2 == 1:
            zero_cksum_tcp += b'\x00'
        return tcp_len, extracted_checksum, zero_cksum_tcp

def computeChecksum(header, tcp):
    data = header + tcp
    offset, total = 0, 0
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
        tcp_len, extracted_cksum, zero_cksum_tcp = processTCPData(f"tcp_data/tcp_data_{count}.dat")
        src_bytes, dest_bytes = pack_ip(src), pack_ip(dest)
        ipPsuedoHeader = createPsuedoIPHeader(src_bytes, dest_bytes, tcp_len)
        checksum = computeChecksum(ipPsuedoHeader, zero_cksum_tcp)
        print("PASS") if checksum == extracted_cksum else print("FAIL")
        count += 1

if __name__ == "__main__":
    main()