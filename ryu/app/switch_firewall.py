# -*- coding: utf-8 -*-

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import print_function

import array

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib import snortlib
from ryu.ofproto.ofproto_v1_3 import OFPG_ANY
from mitigacao import *

class SimpleSwitchSnort(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'snortlib': snortlib.SnortLib}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchSnort, self).__init__(*args, **kwargs)
        self.snort = kwargs['snortlib']
        self.snort_port = 3 # por padrao, todos os pacotes vão para a porta 3
        self.mac_to_port = {}
        self.mac_flood = []  # lista com mac de flood
        self.dictDatapath = {}
        self.mitigacao = mitigacao()
        self.mac_flood = self.mitigacao.loadFile()
        self.mac_white = self.mitigacao.loadWhiteFile()
	socket_config = {'unixsock': False}

        self.snort.set_config(socket_config)
        self.snort.start_socket_server()

    def get_package(self, pkt):
        pkt = packet.Packet(array.array('B', pkt))
	return pkt

    def packet_print(self, pkt):
        pkt = packet.Packet(array.array('B', pkt))

        eth = pkt.get_protocol(ethernet.ethernet)
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        _icmp = pkt.get_protocol(icmp.icmp)

        if _icmp:
            self.logger.info("%r", _icmp)

        if _ipv4:
            self.logger.info("%r", _ipv4)

        if eth:
            self.logger.info("%r", eth)

	    return eth

        '''Function : _dump_alert
        args: ev - pacote contendo a msg enviada pelo snort
        Description: Função que ao receber os alertas encaminha esse pacote para a classe mitigacao
        a qual ira dar o Tratamento necessario, de acordo com o a classe do ataque.
        '''
    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):
       msg = ev.msg
       self.mac_flood = self.mitigacao.checkmessenger(ev,self.mac_flood,self.dictDatapath,self.get_package(msg.pkt))


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        msg = ev.msg

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.

        match = parser.OFPMatch()
       	actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)


# Este evento é gerado sempre, fica ocioso esperando receber pacotes
    '''Function : _packet_in_handler
    args: ev - Pacotes vindos de maquinas que querem se conectar a rede
    Description: Função "principal", nela e que todas as maquinas que desejam se conectar a rede devem passar
    Para tratamento dos pacotes, antes de enviar para o switch um pedido de criação de nova regra
    e testado se aquele mac que quer se conectar a rede e um mac contido primeiramente na whitelist
    e se ele não esta contido na blacklist
    '''

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath # http://ryu.readthedocs.io/en/latest/ryu_app_api.html#ryu-controller-controller-datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']  #porta que foi recebida a msg

        pkt = packet.Packet(msg.data)  #dado da msg
        eth = pkt.get_protocols(ethernet.ethernet)[0]  #protocols

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        
        ''' dictDatapath -  Dicionario no qual eu associo o mac que esta buscando uma conexão
        com seu datapath, table_id e Porta de entrada para que quando o mesmo mac vier a atacar
         o switch eu consigo obter todas essas informações a partir do mac dele'''

	    self.dictDatapath[src] = [datapath, msg.table_id, in_port]
        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.  />>
        self.mac_to_port[dpid][src] = in_port  #fonte da msg

        if dst in self.mac_to_port[dpid]:  # se dentro dessa lista tem o destinatario da msg
            out_port = self.mac_to_port[dpid][dst]    # pego o destinatario e coloco como porta de saida
        else:
            out_port = ofproto.OFPP_FLOOD  # se não eu coloco essa constante como porta de saida oq ser FPP_FLOOD

        actions = [parser.OFPActionOutput(out_port),
                   parser.OFPActionOutput(self.snort_port)]



	if src in self.mac_white:
        	if src not in self.mac_flood and dst not in self.mac_flood:
			    print ('Criando regra de fluxo...')
		        if out_port != ofproto.OFPP_FLOOD:  #All physical ports, except the input port and those disabled by Spanning Tree Protocol.
			        match = parser.OFPMatch(in_port=in_port, eth_dst=dst)  # oq ser isso
        			self.add_flow(datapath, 1, match, actions)

               		data = None
            		if msg.buffer_id == ofproto.OFP_NO_BUFFER:
               			data = msg.data

               		out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port, actions=actions, data=data)
    	      		datapath.send_msg(out)
		#else:
			#print(' Packet_in nao atendido - MAC Suspeito! ')
	#else:
		#print(' MAC nao cadastrao - Contate o Administrador! ')
