import hashlib
import struct
import socket
import socketserver
import json
import logging
import select


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


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


class Server(socketserver.StreamRequestHandler):
    def encrypt_data(self, data):
        return data.translate(encrypt_table)

    def decrypt_data(self, data):
        return data.translate(decrypt_table)

    def handle(self):
        try:
            sock = self.connection
            addrtype = self.decrypt_data(sock.recv(1))[0]  # receive addr type
            if addrtype == 1:
                addr = socket.inet_ntoa(self.decrypt_data(
                    self.rfile.read(4)))   # get dst addr
            elif addrtype == 3:
                addr = self.decrypt_data(
                    self.rfile.read(self.decrypt_data(sock.recv(1))[0]))  # read 1 byte of len, then get 'len' bytes name
            else:
                # not support
                logging.warn('addr_type not support')
                return
            # get dst port into small endian
            port = struct.unpack('>H', self.decrypt_data(self.rfile.read(2)))
            try:
                logging.info('connecting %s:%d' % (addr, port[0]))
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                remote.connect((addr, port[0]))         # connect to dst
            except socket.error as e:
                # Connection refused
                logging.warn(e)
                return
            self.handle_tcp(sock, remote)
        except socket.error as e:
            logging.warn(e)

    def handle_tcp(self, sock, remote):
        try:
            fdset = [sock, remote]
            while True:
                r, w, e = select.select(fdset, [], [])
                if sock in r:
                    data = sock.recv(4096)
                    if len(data) <= 0:
                        break
                    result = self.send_data(remote, self.decrypt_data(data))
                    if result < len(data):
                        raise Exception('failed to send all data')
                if remote in r:
                    data = remote.recv(4096)
                    if len(data) <= 0:
                        break
                    result = self.send_data(sock, self.encrypt_data(data))
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
    with open('config.json', 'r') as f:
        config = json.load(f)
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)-4s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')
    encrypt_table = bytes.maketrans(
        b''.join([i.to_bytes(1, byteorder='little', signed=False) for i in range(256)]), b''.join(get_chr_map(config['password'])))
    decrypt_table = bytes.maketrans(
        b''.join(get_chr_map(config['password'])), b''.join([i.to_bytes(1, byteorder='little', signed=False) for i in range(256)]))
    try:
        server = ThreadingTCPServer(('', config['server_port']), Server)
        logging.info('starting server at port %d ...' % config['server_port'])
        server.serve_forever()
    except socket.error as e:
        logging.error(e)
