import hashlib
import struct
import json
import logging
import socket
import socketserver
import select
import sys


def get_chr_map(password):
    m = hashlib.sha512()
    m.update(password.encode('utf-8'))
    s = m.digest()
    keyNumbers = struct.unpack('Q'*8, s)
    # print(keyNumbers)
    keyNumber = keyNumbers[keyNumbers[0] % len(keyNumbers)]
    chrs = [i.to_bytes(1, byteorder='little', signed=False)
            for i in range(256)]
    for i in range(1, 1024):
        chrs.sort(key=lambda ch: int(keyNumber % (ch[0] + i)))
    return chrs


encrypt_table, decrypt_table = None, None
REMOTE_IP, REMOTE_PORT = None, None
SOCKS5_USERNAME, SOCKS5_PASSWORD = None, None


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


class Server(socketserver.StreamRequestHandler):
    def encrypt_data(self, data):
        return data.translate(encrypt_table)

    def decrypt_data(self, data):
        return data.translate(decrypt_table)

    def verify_auth(self):
        version = self.connection.recv(1)[0]
        assert version == 1
        username_len = self.connection.recv(1)[0]
        username = self.connection.recv(username_len).decode('utf-8')
        password_len = self.connection.recv(1)[0]
        password = self.connection.recv(password_len).decode('utf-8')
        if username == SOCKS5_USERNAME and password == SOCKS5_PASSWORD:
            response = struct.pack("!BB", version, 0)
            self.connection.sendall(response)
            return True
        response = struct.pack("!BB", version, 0xFF)
        self.connection.sendall(response)
        self.server.close_request(self.request)
        return False

    def handle(self):
        try:
            sock = self.connection        # local socket [127.1:port]
            # print(type(sock))
            # sock.recv(262)                # Sock5 Verification packet
            # Sock5 Response: '0x05' Version 5; '0x00' NO AUTHENTICATION REQUIRED
            # sock.send(b"\x05\x00")

            header = sock.recv(2)
            version, num_method = header[0], header[1]
            assert version == 5
            assert num_method > 0
            methods = []
            for i in range(num_method):
                methods.append(sock.recv(1)[0])
            if 2 not in set(methods):
                self.server.close_request(self.request)
                return
            sock.send(b"\x05\x02")
            if not self.verify_auth():
                return

            # After Authentication negotiation
            # Forward request format: VER CMD RSV ATYP (4 bytes)
            data = self.rfile.read(4)  # bytes obj
            mode = data[1]           # CMD == 0x01 (connect)
            if mode != 1:
                logging.warning(
                    'mode != 1! Please choose socks5 protocol to proxy!')
                return
            addrtype = data[3]       # indicate destination address type
            addr_to_send = data[3:4]
            if addrtype == 1:             # IPv4
                # 4 bytes IPv4 address (big endian)
                addr_ip = self.rfile.read(4)
                addr = socket.inet_ntoa(addr_ip)
                addr_to_send += addr_ip
            elif addrtype == 3:           # FQDN (Fully Qualified Domain Name)
                addr_len = self.rfile.read(1)           # Domain name's Length
                # Followed by domain name(e.g. www.google.com)
                addr = self.rfile.read(addr_len[0])
                addr_to_send += addr_len + addr
            else:
                logging.warning('addr_type not support')
                # not support
                return
            # print(addr_to_send)
            addr_port = self.rfile.read(2)
            # addr_to_send = ATYP + [Length] + dst addr/domain name + port
            addr_to_send += addr_port
            # prase the big endian port number. Note: The result is a tuple even if it contains exactly one item.
            port = struct.unpack('>H', addr_port)
            try:
                reply = b"\x05\x00\x00\x01"              # VER REP RSV ATYP
                # listening on 2222 on all addresses of the machine, including the loopback(127.0.0.1)
                reply += socket.inet_aton('0.0.0.0') + struct.pack(">H", 2222)
                self.wfile.write(reply)                 # response packet
                # reply immediately
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # turn off Nagling
                remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                remote.connect((REMOTE_IP, REMOTE_PORT))
                remote.send(self.encrypt_data(addr_to_send))  # encrypted
                logging.info('connecting %s:%d' % (addr, port[0]))
            except socket.error as e:
                logging.warning(e)
                return
            self.handle_tcp(sock, remote)
        except socket.error as e:
            logging.warning(e)

    def handle_tcp(self, sock, remote):
        try:
            fdset = [sock, remote]
            while True:
                # use select I/O multiplexing model
                r, w, e = select.select(fdset, [], [])
                if sock in r:                               # if local socket is ready for reading
                    data = sock.recv(4096)
                    if len(data) <= 0:                      # received all data
                        break
                    # send data after encrypting
                    result = self.send_data(remote, self.encrypt_data(data))
                    if result < len(data):
                        raise Exception('failed to send all data')

                # remote socket(proxy) ready for reading
                if remote in r:
                    data = remote.recv(4096)
                    if len(data) <= 0:
                        break
                    # send to local socket(application)
                    result = self.send_data(sock, self.decrypt_data(data))
                    if result < len(data):
                        raise Exception('failed to send all data')
        finally:
            sock.close()
            remote.close()

    def send_data(self, sock, data):
        bytes_sent = 0
        while True:
            r = sock.send(data[bytes_sent:])
            if r < 0:
                return r
            bytes_sent += r
            if bytes_sent == len(data):
                return bytes_sent


if __name__ == '__main__':
    # print(get_chr_map('123456'))

    with open('client_config.json', 'r') as f:
        config = json.load(f)
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)-4s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')
    encrypt_table = bytes.maketrans(
        b''.join([i.to_bytes(1, byteorder='little', signed=False) for i in range(256)]), b''.join(get_chr_map(config['password'])))
    decrypt_table = bytes.maketrans(
        b''.join(get_chr_map(config['password'])), b''.join([i.to_bytes(1, byteorder='little', signed=False) for i in range(256)]))
    # s = b''.join([i.to_bytes(1, byteorder='little', signed=False)
    #               for i in range(256)])
    # assert s == s.translate(encrypt_table).translate(decrypt_table)
    REMOTE_IP = config['server_ip']
    REMOTE_PORT = config['server_port']
    SOCKS5_USERNAME = config['socks5_username']
    SOCKS5_PASSWORD = config['socks5_password']
    try:
        server = ThreadingTCPServer(('', config['client_port']), Server)
        logging.info('starting client at port %d ...' % config['client_port'])
        server.serve_forever()
    except socket.error as e:
        logging.error(e)
