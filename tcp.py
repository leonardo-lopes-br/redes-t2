import asyncio
from tcputils import *
from os import urandom
from math import ceil
from time import time

class Servidor:

    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita.
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if not self.rede.ignore_checksum and calc_checksum(
                segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4 * (flags >> 12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
            # TODO: talvez você precise passar mais coisas para o construtor de conexão
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no, ack_no)
            # TODO: você precisa fazer o handshake aceitando a conexão. Escolha se você acha melhor
            # fazer aqui mesmo ou dentro da classe Conexao.
            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))

class Conexao:
    def __init__(self, servidor, id_conexao, seq_no, ack_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        # self.timer = asyncio.get_event_loop().call_later(1, self._exemplo_timer)  # um timer pode ser criado assim; esta linha é só um exemplo e pode ser removida
        #self.timer.cancel()   # é possível cancelar o timer chamando esse método; esta linha é só um exemplo e pode ser removida
        self.timer = None
        self.src_addr = id_conexao[0]
        self.src_port = id_conexao[1]
        self.dst_addr = id_conexao[2]
        self.dst_port = id_conexao[3]
        self.seq_esperado = seq_no + 1  
        self.tam_segmento = ack_no  
        self.fila_seg_enviado = []
        self.tam_seg_enviado = 0  
        self.fila_seg_esperando = []
        self.tam_janela = 1 * MSS  
        self.verificado = False  
        self.SampleRTT = 1
        self.EstimatedRTT = self.SampleRTT
        self.DevRTT = self.SampleRTT / 2
        self.TimeoutInterval = 1
        self.envia_ack = seq_no + 1  
        self.envia_seq = int.from_bytes(urandom(4), byteorder='big')
        header = make_header(self.dst_port, self.src_port, self.envia_seq, self.envia_ack, FLAGS_SYN | FLAGS_ACK)
        segmento = fix_checksum(header, self.dst_addr, self.src_addr)
        self.servidor.rede.enviar(segmento, self.src_addr)

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        # TODO: trate aqui o recebimento de segmentos provenientes da camada de rede.
        # Chame self.callback(self, dados) para passar dados para a camada de aplicação após
        # garantir que eles não sejam duplicados e que tenham sido recebidos em ordem.
        
        if (flags & FLAGS_FIN == FLAGS_FIN):
            self.callback(self, b'')
            self.tam_segmento = ack_no
            header = make_header(self.dst_port, self.src_port, self.envia_seq, self.seq_esperado + 1, flags)
            segmento = fix_checksum(header, self.dst_addr, self.src_addr)
            self.servidor.rede.enviar(segmento, self.src_addr)
        elif (seq_no == self.seq_esperado):
            if payload:
                self.seq_esperado += len(payload)
                self.callback(self, payload)
            self.tam_segmento = ack_no
            if (flags & FLAGS_ACK == FLAGS_ACK):
                if payload:
                    header = make_header(self.dst_port, self.src_port, self.envia_seq, self.seq_esperado, flags)
                    segmento = fix_checksum(header, self.dst_addr, self.src_addr)
                    self.servidor.rede.enviar(segmento, self.src_addr)
                self.verificar_timeout(ack_no)
    
    def verificar_timeout(self, ack_no):
        segmento_valido = self.tam_seg_enviado > 0
        if self.timer is not None:
            self.timer.cancel()
            self.timer = None
            while self.fila_seg_enviado:
                firstTime, segmento, _, len_dados = self.fila_seg_enviado.pop(0)
                self.tam_seg_enviado -= len_dados
                _, _, seq, _, _, _, _, _ = read_header(segmento)
                if seq == ack_no:
                    break
            if firstTime != 0:
                self.SampleRTT = time() - firstTime
                if not self.verificado:
                    self.verificado = True
                    self.EstimatedRTT = self.SampleRTT
                    self.DevRTT = self.SampleRTT / 2
                else:
                    self.EstimatedRTT = (1 - 0.125) * self.EstimatedRTT + 0.125 * self.SampleRTT
                    self.DevRTT = (1 - 0.25) * self.DevRTT + 0.25 * abs(self.SampleRTT - self.EstimatedRTT)

                self.TimeoutInterval = self.EstimatedRTT + 4 * self.DevRTT
        segmento_consumido = self.tam_seg_enviado == 0
        if segmento_valido and segmento_consumido:
            self.tam_janela += MSS
        while self.fila_seg_esperando:
            segmento, src_addr, len_dados = self.fila_seg_esperando.pop(0)
            if self.tam_seg_enviado + len_dados > self.tam_janela:
                self.fila_seg_esperando.insert(0, (segmento, src_addr, len_dados))
                break
            self.tam_seg_enviado += len_dados
            self.servidor.rede.enviar(segmento, src_addr)
            self.fila_seg_enviado.append((time(), segmento, src_addr, len_dados))
        if self.fila_seg_enviado:
            self.timer = asyncio.get_event_loop().call_later(self.TimeoutInterval, self._timeout)

    def _timeout(self):
        self.timer = None
        self.tam_janela /= 2
        if len(self.fila_seg_enviado):
            _, segmento, addr, tam_dados = self.fila_seg_enviado.pop(0)
            self.fila_seg_enviado.insert(0, (0, segmento, addr, tam_dados))
            self.servidor.rede.enviar(segmento, addr)
            self.timer = asyncio.get_event_loop().call_later(self.TimeoutInterval, self._timeout)

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados):
        size = ceil(len(dados) / MSS)
        for i in range(size):
            self.envia_seq = self.tam_segmento
            header = make_header(self.dst_port, self.src_port, self.envia_seq, self.seq_esperado, FLAGS_ACK)
            header += (dados[i * MSS:min((i + 1) * MSS, len(dados))])
            len_dados = len(dados[i * MSS:min((i + 1) * MSS, len(dados))])
            self.tam_segmento += len_dados
            segmento = fix_checksum(header, self.dst_addr, self.src_addr)
            self.enviar_segmento(segmento, len_dados)

    def enviar_segmento(self, segmento, len_dados):
        if self.tam_seg_enviado + len_dados <= self.tam_janela:
            self.servidor.rede.enviar(segmento, self.src_addr)
            self.fila_seg_enviado.append((time(), segmento, self.src_addr, len_dados))
            self.tam_seg_enviado += len_dados
            if self.timer is None:
                self.timer = asyncio.get_event_loop().call_later(self.TimeoutInterval, self._timeout)
        else:
            self.fila_seg_esperando.append((segmento, self.src_addr, len_dados))

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        # TODO: implemente aqui o fechamento de conexão
        self.envia_seq = self.tam_segmento
        header = make_header(self.dst_port, self.src_port, self.envia_seq, self.seq_esperado + 1, FLAGS_FIN)
        segmento = fix_checksum(header, self.dst_addr, self.src_addr)
        self.servidor.rede.enviar(segmento, self.src_addr)
