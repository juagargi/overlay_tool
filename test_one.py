# based on https://github.com/samuel/python-ping/blob/master/ping.py
import socket
import struct
import os
import time
import select
import json


ICMP_ECHO_REQUEST = 8 # Seems to be the same on Solaris.
TIMEOUT = 4


class Node:
    def __init__(self, label, ip):
        self._label = label
        self._address = ip
    def label(self):
        return self._label
    def address(self):
        return self._address


def ping(dst):
    def checksum(source_string):
        """
        I'm not too confident that this is right but testing seems
        to suggest that it gives the same answers as in_cksum in ping.c
        """
        sum = 0
        countTo = (len(source_string)/2)*2
        count = 0
        while count<countTo:
            thisVal = source_string[count + 1]*256 + source_string[count]
            sum = sum + thisVal
            sum = sum & 0xffffffff # Necessary?
            count = count + 2

        if countTo<len(source_string):
            sum = sum + source_string[len(source_string) - 1]
            sum = sum & 0xffffffff # Necessary?

        sum = (sum >> 16)  +  (sum & 0xffff)
        sum = sum + (sum >> 16)
        answer = ~sum
        answer = answer & 0xffff

        # Swap bytes. Bugger me if I know why.
        answer = answer >> 8 | (answer << 8 & 0xff00)

        return answer

    def prepare_ping_packet(ID):
        my_checksum = 0
        # Header is type (8), code (8), checksum (16), id (16), sequence (16)
        header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, ID, 1)
        bytesInDouble = struct.calcsize("d")
        data = bytes((192 - bytesInDouble) * "Q", "ascii")
        data = struct.pack("d", time.time()) + data

        # Calculate the checksum on the data and the dummy header.
        my_checksum = checksum(header + data)

        # Now that we have the right checksum, we put that in. It's just easier
        # to make up a new header than to stuff it into the dummy.
        header = struct.pack(
            "bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), ID, 1
        )
        packet = header + data
        return packet

    def receive_one_ping(my_socket, ID, timeout):
        """
        receive the ping from the socket.
        """
        timeLeft = timeout
        while True:
            startedSelect = time.time()
            whatReady = select.select([my_socket], [], [], timeLeft)
            howLongInSelect = (time.time() - startedSelect)
            if whatReady[0] == []: # Timeout
                return
            timeReceived = time.time()
            recPacket, addr = my_socket.recvfrom(1024)
            icmpHeader = recPacket[20:28]
            type, code, checksum, packetID, sequence = struct.unpack(
                "bbHHh", icmpHeader
            )
            # Filters out the echo request itself. 
            # This can be tested by pinging 127.0.0.1 
            # You'll see your own request
            if type != 8 and packetID == ID:
                bytesInDouble = struct.calcsize("d")
                timeSent = struct.unpack("d", recPacket[28:28 + bytesInDouble])[0]
                return timeReceived - timeSent
            timeLeft = timeLeft - howLongInSelect
            if timeLeft <= 0:
                return

    ID = os.getpid() & 0xFFFF    
    dest_addr = socket.gethostbyname(dst.address())
    packet = prepare_ping_packet(ID)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    except PermissionError as err:
        if err.errno == 1:
            msg = err.strerror + ". Sending ICMP messages requires root"
            pe = PermissionError(msg)
            pe.errno = 1
            raise pe
        raise
    sock.sendto(packet, (dest_addr, 1)) # Don't know about the 1
    delay = receive_one_ping(sock, ID, TIMEOUT)
    if not delay:
        delay = TIMEOUT

    return delay * 1000

def measure(f, count, dst):
    measures = []
    for _ in range(0, count):
        measures.append(f(dst))
    return measures

def main():
    # load all nodes:
    nodes = []
    with open("nodes.txt", "r") as f:
        lines = f.readlines()
    for line in lines:
        fields = [f for f in line.strip().split(' ') if f]
        n = Node(fields[0], fields[1])
        nodes.append(n)
    # build the edges of the (directed) graph for all properties:
    properties = [ping,]
    measures = {}
    for p in properties:
        this_dimension = {}
        for n in nodes:
            this_dimension[n.label()] = measure(p, 4, n)
        measures[p.__name__] = this_dimension
    # reverse fold the map
    measures = {
        node_name: {prop: measures[prop][node_name]} 
        for prop in measures.keys()
        for node_name in measures[prop].keys()
    }

    # { node_name: { a_property: values     for a_property,all_nodes in measures.items() }  for node_name,values in all_nodes.items()  }   
    measures_json = json.dumps(measures)
    print(measures_json)
    

if __name__ == "__main__":
    main()

