# -*- coding: utf-8 -*-

from ryu.lib.packet import ethernet

import os

class mitigacao(object):
	##"""docstring for Mitigacao"""

	def __init__(self):
		super(mitigacao, self).__init__()

'''
Function : remove_table_flows
args: datapath -  dados da messagem que será enviada para o switch
	  table_id -  ID da tabela na qual esta contida a regra de fluxo
	  match - Elemento vazio neste caso
	  instructions - Elemento vazio neste caso
Description: A função gera json( Sequencia de Caracteres pré configuradas), e utilizando o argumento Ofproto.OFPFC_DELETE
Quando enviado para o switch ele deletar a regra com  o mac e port_in correspondentes.

'''
	def remove_table_flows(self, datapath, table_id, match, instructions):
            ##"""Create OFP flow mod message to remove flows from table."""
            ofproto = datapath.ofproto
            flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath, 0, 0 ,table_id , ofproto.OFPFC_DELETE,0, 0,11111,ofproto.OFPCML_NO_BUFFER,ofproto.OFPP_ANY,ofproto.OFPG_ANY,0, match, instructions)
            datapath.send_msg(flow_mod)
'''
Function : modify_table_flows
args: datapath -  dados da messagem que será enviada para o switch
	  table_id -  ID da tabela na qual esta contida a regra de fluxo
	  match - Contem o mac destino  e a porta de entrada do pacote criador da regra
	  instructions - Contem qual tipo de ação deve ser tomada
Description: A função gera json, e utilizando o argumento Ofproto.OFPFC_MODIFY
Quando enviado para o switch ele modifica a tabela com o argumento actions que esta dentro do instructions.
'''
	def modify_table_flows(self, datapath, table_id, match, instructions):

	##"""Create OFP flow mod message to remove flows from table."""
	    ofproto = datapath.ofproto
	    flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath, 0, 0 ,table_id , ofproto.OFPFC_MODIFY,0, 0,11111,ofproto.OFPCML_NO_BUFFER,ofproto.OFPP_ANY,ofproto.OFPG_ANY,ofproto.OFPFF_SEND_FLOW_REM, match, instructions)
        datapath.send_msg(flow_mod)

'''
Function : checkmessenger
args: ev -  dados da messagem que será enviada para o switch
	  mac_flood -  ID da tabela na qual esta contida a regra de fluxo
	  dictDatapath - Contem o mac destino  e a porta de entrada do pacote criador da regra
	  pkt - Contem qual tipo de ação deve ser tomada
Description: A função gera json, e utilizando o argumento Ofproto.OFPFC_MODIFY
Quando enviado para o switch ele modifica a tabela com o argumento actions que esta dentro do instructions.
'''


	def checkmessenger(self,ev,mac_flood,dictDatapath,pkt):
	   msg = ev.msg
	   msgconvert = str(msg.alertmsg[0])

	   if msgconvert.find ("Class_3") !=-1:

         lista = open("blacklist.txt","a+")
		 escrevendo = str(pkt.get_protocol(ethernet.ethernet).src+"\n")

		 l = lista.readlines()

      	 print("#+++   Packet_Event treatment - Class 3 attack   +++#")
      	 print("#**  Attempt to suspicous activity on the network **#")
	 	 print (l)

		 if escrevendo not in l:
                        lista.write(escrevendo)
    	         		mac_flood.append(pkt.get_protocol(ethernet.ethernet).src)

      	 print("#*** Inserting suspect MAC Address in Blacklist ***#")
		 print("alertmsg: %s" % "".join(msg.alertmsg))
		 lista.close()
		 print(pkt.get_protocol(ethernet.ethernet).src)
         mc = pkt.get_protocol(ethernet.ethernet).src #saving mac address to remove
         parser = dictDatapath[mc][0].ofproto_parser

         empty_match = parser.OFPMatch(in_port=dictDatapath[mc][2])
         empty_match2 = parser.OFPMatch(eth_dst=mc)

		 self.remove_table_flows(dictDatapath[mc][0],dictDatapath[mc][1],empty_match,[])
		 self.remove_table_flows(dictDatapath[mc][0],dictDatapath[mc][1],empty_match2,[])
		 return mac_flood

	   if msgconvert.find ("Class_2") !=-1:

      	 print("#+++   Packet_Event treatment - Class 2 attack   +++#")
	  	 print("#**  Attempt to suspicous activity on the network **#")
		 print("alertmsg: %s" % "".join(msg.alertmsg))

		 #print(pkt.get_protocol(ethernet.ethernet).src)
         mc = pkt.get_protocol(ethernet.ethernet).src #saving mac address to remove
         parser = dictDatapath[mc][0].ofproto_parser

		 dst = pkt.get_protocol(ethernet.ethernet).dst
         empty_match = parser.OFPMatch(in_port=dictDatapath[mc][2],eth_dst=dst)

		 actions = [parser.OFPActionOutput(4)]
		 instructions = [parser.OFPInstructionActions(dictDatapath[mc][0].ofproto.OFPIT_APPLY_ACTIONS,actions)]
		 self.modify_table_flows(dictDatapath[mc][0],dictDatapath[mc][1],empty_match,instructions)
		 return mac_flood

	'''
	Function : loadFile
	args:
	Description: Função que carrega os mac que estão dentro do arquivo blacklist.txt
	'''

	def loadFile(self):
		#leitura do arquivo

		mac_flood=[]

		if os.stat("blacklist.txt").st_size == 0:
			return mac_flood
		else:
		    arc = open("blacklist.txt","r")
		    for i in arc.readlines():
		        s = i.replace("\n","")
			#print i
		        mac_flood.append(s)

	        return mac_flood

	'''Function : loadWhiteFile
	args:
	Description: Função que carrega os mac que estão dentro do arquivo whitelist.txt
	'''

	def loadWhiteFile(self):
		mac_flood=[]

		if os.stat("whitelist.txt").st_size == 0:
			return mac_flood
		else:
		    arc = open("whitelist.txt","r")
		    for i in arc.readlines():
		        s = i.replace("\n","")
			#print i
		        mac_flood.append(s)

	        return mac_flood
