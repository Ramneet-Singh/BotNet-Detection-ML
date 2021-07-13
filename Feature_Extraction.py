from scapy.all import *
from scapy.layers.http import *
import os
import csv


def create_features(label, srcAddr, dstAddr, srcPort, dstPort, proto=4, fps=0, byte_size=0, payl=0, time=0, dur=0, incoming=False, http=4):
    features = {
        'malicious': label,
        'srcAddr': srcAddr,
        'dstAddr': dstAddr
    }
    features['srcPort'] = srcPort
    features['dstPort'] = dstPort
    if proto == 2:
        features['proto'] = 2
    elif proto == 6:
        features['proto'] = 0
    elif proto == 17:
        features['proto'] = 1
    else:
        features['proto'] = 3
    features['PX'] = 1
    if byte_size <= 62:
        features['NNP'] = 1
    else:
        features['NNP'] = 0
    if 63 <= byte_size and byte_size <= 400:
        features['NSP'] = 1
    else:
        features['NSP'] = 0
    if(features['PX'] > 0):
        features['PSP'] = (features['NSP']/features['PX'])*100
        features['PNP'] = (features['NNP']/features['PX'])*100
    else:
        features['PSP'] = 0
        features['PNP'] = 0
    if not incoming:
        features['out'] = 1
        features['in'] = 0
    else:
        features['in'] = 1
        features['out'] = 0
    if features['out'] > 0:
        features['IOPR'] = features['in']/features['out']
    else:
        features['IOPR'] = 0
    features['dur'] = dur
    features['FPS'] = fps
    features['TBT'] = byte_size
    features['APL'] = payl
    features['PV'] = 0.0
    if(features['dur'] > 0):
        features['BS'] = features['TBT']/features['dur']
        features['PPS'] = features['PX']/features['dur']
    else:
        features['BS'] = 0
        features['PPS'] = 0
    features['AIT'] = 0
    features['HTTPM'] = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0}
    features['HTTPM'][http] = 1
    features['time'] = time

    return features


def update_features(features, nnp=False, nsp=False, incoming=False, byte_size=0, payl=0, time=0, dur=0, http=4):

    features['PX'] = features['PX'] + 1
    if nnp:
        features['NNP'] = features['NNP'] + 1
        features['PNP'] = (features['NNP']/features['PX'])*100
    if nsp:
        features['NSP'] = features['NSP'] + 1
        features['PSP'] = (features['NSP']/features['PX'])*100
    if incoming:
        features['in'] = features['in'] + 1
    else:
        features['out'] = features['out'] + 1
    if(features['out'] > 0):
        features['IOPR'] = features['in'] / features['out']
    features['TBT'] = features['TBT'] + byte_size
    av = features['APL']
    sd = features['PV']
    n = features['PX'] - 1
    if(n+1 > 0):
        features['APL'] = ((av * n) + payl)/(n + 1)
    if(n > 0):
        features['PV'] = ((((n-1)*sd**2) + (n * av**2) -
                           ((n + 1)*features['APL']**2) + payl**2)/n)**0.5
    features['dur'] = features['dur'] + 1
    if(features['dur'] > 0):
        features['BS'] = features['TBT']/features['dur']
        features['PPS'] = features['PX']/features['dur']
    del_t = time - features['time']
    features['time'] = time
    if(n+1 > 0):
        features['AIT'] = ((features['AIT'] * n) + del_t) / (n + 1)
    features['HTTPM'][http] = features['HTTPM'][http] + 1

    return features


def flows_from_pcap(label, filePath):
    flows = {}
    fpcap = PcapReader(filePath)
    f_dup = PcapReader(filePath)
    pkt_nxt = next(f_dup)
    c = 0
    num = 0
    total_bytes = 0
    for pkt in fpcap:
        num = num+1
        dur = 0
        try:
            pkt_nxt = next(f_dup)
            dur = pkt_nxt.time - pkt.time
        except:
            dur = 0.0001

        srcAddr, dstAddr, sport, dport, proto = '', '', 0, 0, 3
        pload, http_meth = 0, 4
        tcp_close = False
        try:
            bs = pkt.len + 14
            total_bytes += pkt.len
        except:
            continue

        if 'Ethernet' in pkt or 'cooked linux' in pkt:
            flag = False
            if('Ethernet' in pkt):
                eth = pkt['Ethernet']
                if eth.type == 2048:
                    flag = True
            else:
                lin = pkt['cooked linux']
                flag = lin.proto == 2048
            if flag is True:
                ip = pkt['IP']
                proto = ip.proto
                srcAddr = ip.src
                dstAddr = ip.dst
                if(os.path.basename(os.path.dirname(filePath)) == "p2pbox1"):
                    if((str(srcAddr) not in benign_ip["p2pbox1"]) and (str(dstAddr) not in benign_ip["p2pbox1"])):
                        continue
                if(os.path.basename(os.path.dirname(filePath)) == "p2pbox2"):
                    if((str(srcAddr) not in benign_ip["p2pbox2"]) and (str(dstAddr) not in benign_ip["p2pbox2"])):
                        continue
                if(os.path.basename(os.path.dirname(filePath)) == "torrent"):
                    if((str(srcAddr) not in benign_ip["torrent"]) and (str(dstAddr) not in benign_ip["torrent"])):
                        continue
                if(os.path.basename(os.path.dirname(filePath)) == "storm"):
                    if((str(srcAddr) not in malicious_ip["storm"]) and (str(dstAddr) not in malicious_ip["storm"])):
                        continue
                if(os.path.basename(os.path.dirname(filePath)) == "vinchuca"):
                    if((str(srcAddr) not in malicious_ip["vinchuca"]) and (str(dstAddr) not in malicious_ip["vinchuca"])):
                        continue
                if(os.path.basename(os.path.dirname(filePath)) == "zeus"):
                    if((str(srcAddr) not in malicious_ip["zeus"]) and (str(dstAddr) not in malicious_ip["zeus"])):
                        continue
                if proto == 17 and pkt.haslayer('UDP'):
                    sport = pkt['UDP'].sport
                    dport = pkt['UDP'].dport
                    pload = len(pkt['UDP'].payload)
                elif proto == 6 and pkt.haslayer('TCP'):
                    sport = pkt['TCP'].sport
                    dport = pkt['TCP'].dport
                    pload = len(pkt['TCP'].payload)
                    if pkt.haslayer('HTTPRequest'):
                        meth = pkt['HTTPRequest'].Method
                        if meth == b'GET':
                            http_meth = 0
                        elif meth == b'POST':
                            http_meth = 1
                        elif meth == b'PUT':
                            http_meth = 2
                        elif meth == b'DELETE':
                            http_meth = 3
                        else:
                            http_meth = 4
                    tcp_close = ('F' in pkt['TCP'].flags) or (
                        'R' in pkt['TCP'].flags)
                elif proto == 1 and pkt.haslayer('ICMP'):
                    if pkt['ICMP'].haslayer('IP') and pkt['ICMP']['IP'].proto == 17 and pkt['ICMP'].haslayer('UDP'):
                        sport = pkt['ICMP']['UDP'].sport
                        dport = pkt['ICMP']['UDP'].dport
                        pload = len(pkt['ICMP']['UDP'].payload)
                    elif pkt['ICMP'].haslayer('IP') and pkt['ICMP']['IP'].proto == 6 and pkt['ICMP'].haslayer('TCP'):
                        sport = pkt['ICMP']['TCP'].sport
                        dport = pkt['ICMP']['TCP'].dport
                        pload = len(pkt['ICMP']['TCP'].payload)
                        if pkt['ICMP'].haslayer('HTTPRequest'):
                            meth = pkt['ICMP']['HTTPRequest'].Method
                            if meth == b'GET':
                                http_meth = 0
                            elif meth == b'POST':
                                http_meth = 1
                            elif meth == b'PUT':
                                http_meth = 2
                            elif meth == b'DELETE':
                                http_meth = 3
                            else:
                                http_meth = 4
                        tcp_close = ('F' in pkt['ICMP']['TCP'].flags) or (
                            'R' in pkt['ICMP']['TCP'].flags)
                    else:
                        continue
                else:
                    continue
            else:
                continue
        nnp = pload == 0
        nsp = 63 <= bs and bs <= 400
        tuple5 = (srcAddr, sport, dstAddr, dport, proto, True)
        tuple5_inv = (dstAddr, dport, srcAddr, sport, proto, True)
        if tuple5 in flows:
            features = flows[tuple5]
            flows[tuple5] = update_features(
                features, nnp, nsp, incoming=False, byte_size=bs, payl=pload, time=pkt.time, dur=dur, http=http_meth)
            if tcp_close:
                temp = flows[tuple5]
                del flows[tuple5]
                tuple5 = (srcAddr, sport, dstAddr, dport, proto, False)
                flows[tuple5] = temp
        elif tuple5_inv in flows:
            features = flows[tuple5_inv]
            flows[tuple5_inv] = update_features(
                features, nnp, nsp, incoming=True, byte_size=bs, payl=pload, time=pkt.time, dur=dur, http=http_meth)
            if tcp_close:
                temp = flows[tuple5_inv]
                del flows[tuple5_inv]
                tuple5_inv = (dstAddr, dport, srcAddr, sport, proto, False)
                flows[tuple5_inv] = temp
        else:
            flows[tuple5] = create_features(label, srcAddr, dstAddr, sport, dport, proto, fps=pload, byte_size=bs, payl=pload,
                                            time=pkt.time, dur=dur, incoming=False, http=http_meth)            # features_list

    for flow in flows:
        if(num > 0):
            flows[flow]['PPX'] = flows[flow]['PX']/num
        else:
            flows[flow]['PPX'] = 0
        if(total_bytes > 0):
            flows[flow]['PBT'] = flows[flow]['TBT']/total_bytes
        else:
            flows[flow]['PBT'] = 0
    return flows


benign_ip = {
    "p2pbox1":	["192.168.1.2"],
    "p2pbox2":	["192.168.2.2"],
    "torrent": 	["172.27.28.106"]
}

malicious_ip = {
    "storm": ["66.154.80.101",
              "66.154.80.105",
              "66.154.80.111",
              "66.154.80.125",
              "66.154.83.107",
              "66.154.83.113",
              "66.154.83.138",
              "66.154.83.80",
              "66.154.87.39",
              "66.154.87.41",
              "66.154.87.57",
              "66.154.87.58",
              "66.154.87.61"],
    "vinchuca": ["172.27.22.206"],
    "zeus": ["10.0.2.15"]
}

field_names = [
    'srcAddr',
    'dstAddr',
    'srcPort',
    'dstPort',
    'proto',
    'PPX',
    'PBT',
    'PX',
    'NNP',
    'NSP',
    'PSP',
    'PNP',
    'out',
    'in',
    'IOPR',
    'dur',
    'FPS',
    'TBT',
    'APL',
    'PV',
    'BS',
    'PPS',
    'AIT',
    'HTTPM0',
    'HTTPM1',
    'HTTPM2',
    'HTTPM3',
    'HTTPM4',
    'malicious'
]

with open('Results_2.csv', 'x') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=field_names)
    writer.writeheader()

    i = 0
    # Launch Benign
    for root, dirs, files in os.walk(os.path.join('Botnet_Detection_Dataset', 'Benign')):
        for name in files:
            filePath = os.path.join(root, name)
            if(name != "ip_details.txt"):
                flow_features = flows_from_pcap(0, filePath)
                for flow in flow_features:
                    if('dur' in flow_features[flow]):
                        flow_features[flow]['dur'] = float(
                            flow_features[flow]['dur'])
                    if('BS' in flow_features[flow]):
                        flow_features[flow]['BS'] = float(
                            flow_features[flow]['BS'])
                    if('PPS' in flow_features[flow]):
                        flow_features[flow]['PPS'] = float(
                            flow_features[flow]['PPS'])
                    if('AIT' in flow_features[flow]):
                        flow_features[flow]['AIT'] = float(
                            flow_features[flow]['AIT'])
                    if('time' in flow_features[flow]):
                        flow_features[flow]['time'] = float(
                            flow_features[flow]['time'])
                    if('HTTPM' in flow_features[flow]):
                        flow_features[flow]['HTTPM0'] = flow_features[flow]['HTTPM'][0]
                        flow_features[flow]['HTTPM1'] = flow_features[flow]['HTTPM'][1]
                        flow_features[flow]['HTTPM2'] = flow_features[flow]['HTTPM'][2]
                        flow_features[flow]['HTTPM3'] = flow_features[flow]['HTTPM'][3]
                        flow_features[flow]['HTTPM4'] = flow_features[flow]['HTTPM'][4]
                        del flow_features[flow]['HTTPM']
                    if('time' in flow_features[flow]):
                        del flow_features[flow]['time']
                    writer.writerow(flow_features[flow])
                i = i+1
                print(i, "Files Processed:", filePath, len(flow_features))

    # Launch Botnet
    for root, dirs, files in os.walk(os.path.join('Botnet_Detection_Dataset', 'Botnet', 'storm')):
        for name in files:
            filePath = os.path.join(root, name)
            if(name != "storm-IP" and name != "vinchuca_IP" and name != "zeus_IP"):
                flow_features = flows_from_pcap(1, filePath)
                for flow in flow_features:
                    if('dur' in flow_features[flow]):
                        flow_features[flow]['dur'] = float(
                            flow_features[flow]['dur'])
                    if('BS' in flow_features[flow]):
                        flow_features[flow]['BS'] = float(
                            flow_features[flow]['BS'])
                    if('PPS' in flow_features[flow]):
                        flow_features[flow]['PPS'] = float(
                            flow_features[flow]['PPS'])
                    if('AIT' in flow_features[flow]):
                        flow_features[flow]['AIT'] = float(
                            flow_features[flow]['AIT'])
                    if('time' in flow_features[flow]):
                        flow_features[flow]['time'] = float(
                            flow_features[flow]['time'])
                    if('HTTPM' in flow_features[flow]):
                        flow_features[flow]['HTTPM0'] = flow_features[flow]['HTTPM'][0]
                        flow_features[flow]['HTTPM1'] = flow_features[flow]['HTTPM'][1]
                        flow_features[flow]['HTTPM2'] = flow_features[flow]['HTTPM'][2]
                        flow_features[flow]['HTTPM3'] = flow_features[flow]['HTTPM'][3]
                        flow_features[flow]['HTTPM4'] = flow_features[flow]['HTTPM'][4]
                        del flow_features[flow]['HTTPM']
                    if('time' in flow_features[flow]):
                        del flow_features[flow]['time']
                    writer.writerow(flow_features[flow])
                i = i+1
                print(i, "Files Processed:", filePath)
