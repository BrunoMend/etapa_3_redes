import socket
import asyncio
import struct

ETH_P_IP = 0x0800
FLAG_MF = 1 << 13
FLAG_DF = 1 << 14
FLAGS = 0xE000
FRAGMENTOFSET = 0x1FFF


# Coloque aqui o endereço de destino para onde você quer mandar o ping
dest_addr = '186.219.82.1'

#Array vazio de conexões
conexoes = {}

class Conexao:
	def __init__(self, id_conexao, total_length):
		#Informacoes para a conexao
		self.id_conexao = id_conexao

		# datagram vazio do tamanho total para ser montado
		self.datagram = bytearray(total_length)
        #controle de fragment_offset
        self.fragment_offset_recv = {}

        #salva o tamanho total do datagram
        self.total_length = total_length

        #tamanho de datagrams já recebido
        self.recv_datagram_length = 0

    #recebe o segmento com o fragment_offset para incluir no datagram
    def make_datagram(self, segment, fragment_offset):
        if fragment_offset in fragment_offset_recv:
            return
        else:
            self.fragment_offset_recv.append(fragment_offset)

        self.datagram[fragment_offset] = segment
        self.recv_datagram_length += segment.length
        if(self.total_length == self.recv_datagram_length):
            print(self.datagram)


#Converte endereco para string
def addr2str(addr):
	return '%d.%d.%d.%d' % tuple(int(x) for x in addr)

#Converte string para endereco
def str2addr(addr):
	return bytes(int(x) for x in addr.split('.'))

#Cabecalho da camada de rede - IP Datagram Format
def handle_ipv4_header(packet):
	#Versao do procotolo IP
	version = packet[0] >> 4
	#Verifica se a versao do IP eh a 4
	assert version == 4
    
	#Endereco fonte
	src_addr = addr2str(packet[12:16])
	#Endereco destino
	dst_addr = addr2str(packet[16:20])
	
    #Tamanho do Cabecalho
	ihl = packet[0] & 0xf
	#Segmento contendo o protocolo TCP
	segment = packet[4*ihl:]

    #Tamanho total do segmento
    total_length = packet[2:3]
    #Posição dos dados no datagram
    fragment_offset = int.from_bytes(packet[6:8], 'big') & FRAGMENTOFSET
    #Flags da conexão
    flags = int.from_bytes(packet[6:8], 'big') & FLAGS

    #identificador da conexão
    identification = packet[4:6]
    #identificador da conexao
	id_conexao = (src_addr, dst_addr, identification)

	return id_conexao, segment, total_length, fragment_offset, flags

def send_ping(send_fd):
    print('enviando ping')
    # Exemplo de pacote ping (ICMP echo request) com payload grande
    msg = bytearray(b"\x08\x00\x00\x00" + 5000*b"\xba\xdc\x0f\xfe")
    msg[2:4] = struct.pack('!H', calc_checksum(msg))
    send_fd.sendto(msg, (dest_addr, 0))

    asyncio.get_event_loop().call_later(1, send_ping, send_fd)


def raw_recv(recv_fd):
    packet = recv_fd.recv(12000)
    print('recebido pacote de %d bytes' % len(packet))

	#Tratamento do cabecalho da camada de rede
	id_conexao, segment, total_length, fragment_offset, flags = handle_ipv4_header(packet)

    if (flags & FLAG_DF) == FLAG_DF:
        #descarta pacotes não fragmentados
        return
    

    if !(id_conexao in conexoes):
        conexoes.append(Conexao(id_conexao, total_length))

    conexoes[id_conexao].make_datagram(segment, fragment_offset)


def calc_checksum(segment):
    if len(segment) % 2 == 1:
        # se for ímpar, faz padding à direita
        segment += b'\x00'
    checksum = 0
    for i in range(0, len(segment), 2):
        x, = struct.unpack('!H', segment[i:i+2])
        checksum += x
        while checksum > 0xffff:
            checksum = (checksum & 0xffff) + 1
    checksum = ~checksum
    return checksum & 0xffff


if __name__ == '__main__':
    # Ver http://man7.org/linux/man-pages/man7/raw.7.html
    send_fd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    # Para receber existem duas abordagens. A primeira é a da etapa anterior
    # do trabalho, de colocar socket.IPPROTO_TCP, socket.IPPROTO_UDP ou
    # socket.IPPROTO_ICMP. Assim ele filtra só datagramas IP que contenham um
    # segmento TCP, UDP ou mensagem ICMP, respectivamente, e permite que esses
    # datagramas sejam recebidos. No entanto, essa abordagem faz com que o
    # próprio sistema operacional realize boa parte do trabalho da camada IP,
    # como remontar datagramas fragmentados. Para que essa questão fique a
    # cargo do nosso programa, é necessário uma outra abordagem: usar um socket
    # de camada de enlace, porém pedir para que as informações de camada de
    # enlace não sejam apresentadas a nós, como abaixo. Esse socket também
    # poderia ser usado para enviar pacotes, mas somente se eles forem quadros,
    # ou seja, se incluírem cabeçalhos da camada de enlace.
    # Ver http://man7.org/linux/man-pages/man7/packet.7.html
    recv_fd = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_IP))

    loop = asyncio.get_event_loop()
    loop.add_reader(recv_fd, raw_recv, recv_fd)
    asyncio.get_event_loop().call_later(1, send_ping, send_fd)
    loop.run_forever()
