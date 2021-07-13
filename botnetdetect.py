import csv
import os
import sys
from scapy.all import *
from scapy.layers.http import *
import lightgbm as lg
import numpy as np

model = lg.Booster(model_file=os.path.join(os.getcwd(), "Model_LightGBM.txt"))


def create_features(srcAddr, dstAddr, srcPort, dstPort, fps=0, byte_size=0, payl=0, dur=0, incoming=False):
    features = {
        'srcAddr': srcAddr,
        'dstAddr': dstAddr
    }
    features['srcPort'] = srcPort
    features['dstPort'] = dstPort
    features['PX'] = 1
    if 63 <= byte_size and byte_size <= 400:
        features['NSP'] = 1
    else:
        features['NSP'] = 0
    if(features['PX'] > 0):
        features['PSP'] = (features['NSP']/features['PX'])*100
    else:
        features['PSP'] = 0
    if not incoming:
        features['in'] = 0
    else:
        features['in'] = 1
    features['dur'] = dur
    features['FPS'] = fps
    features['TBT'] = byte_size
    features['APL'] = payl
    if(features['dur'] > 0):
        features['BS'] = features['TBT']/features['dur']
        features['PPS'] = features['PX']/features['dur']
    else:
        features['BS'] = 0
        features['PPS'] = 0

    return features


def update_features(features, nsp=False, incoming=False, byte_size=0, payl=0, dur=0):

    features['PX'] = features['PX'] + 1
    if nsp:
        features['NSP'] = features['NSP'] + 1
        features['PSP'] = (features['NSP']/features['PX'])*100
    if incoming:
        features['in'] = features['in'] + 1
    features['TBT'] = features['TBT'] + byte_size
    av = features['APL']
    n = features['PX'] - 1
    if(n+1 > 0):
        features['APL'] = ((av * n) + payl)/(n + 1)
    features['dur'] = features['dur'] + 1
    if(features['dur'] > 0):
        features['BS'] = features['TBT']/features['dur']
        features['PPS'] = features['PX']/features['dur']

    return features

# srcAddr         dstAddr  srcPort  dstPort           PPX    PSP  in  FPS  TBT    APL          BS       PPS


def flows_from_pcap(filePath):
    flows = {}
    fpcap = PcapReader(filePath)
    f_dup = PcapReader(filePath)
    pkt_nxt = next(f_dup)
    c = 0
    num = 0
    for pkt in fpcap:
        num = num+1
        dur = 0
        try:
            pkt_nxt = next(f_dup)
            dur = pkt_nxt.time - pkt.time
        except:
            dur = 0.0001

        srcAddr, dstAddr, sport, dport, proto = '', '', 0, 0, 3
        pload = 0
        tcp_close = False
        try:
            bs = pkt.len + 14
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
                srcAddr = ip.src
                dstAddr = ip.dst
                proto = ip.proto

                if proto == 17 and pkt.haslayer('UDP'):
                    sport = pkt['UDP'].sport
                    dport = pkt['UDP'].dport
                    pload = len(pkt['UDP'].payload)
                elif proto == 6 and pkt.haslayer('TCP'):
                    sport = pkt['TCP'].sport
                    dport = pkt['TCP'].dport
                    pload = len(pkt['TCP'].payload)
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
                        tcp_close = ('F' in pkt['ICMP']['TCP'].flags) or (
                            'R' in pkt['ICMP']['TCP'].flags)
                    else:
                        continue
                else:
                    continue
            else:
                continue
        nsp = 63 <= bs and bs <= 400
        tuple5 = (srcAddr, sport, dstAddr, dport, proto, True)
        tuple5_inv = (dstAddr, dport, srcAddr, sport, proto, True)
        if tuple5 in flows:
            features = flows[tuple5]
            flows[tuple5] = update_features(
                features, nsp, incoming=False, byte_size=bs, payl=pload, dur=dur)
            if tcp_close:
                temp = flows[tuple5]
                del flows[tuple5]
                tuple5 = (srcAddr, sport, dstAddr, dport, proto, False)
                flows[tuple5] = temp
        elif tuple5_inv in flows:
            features = flows[tuple5_inv]
            flows[tuple5_inv] = update_features(
                features, nsp, incoming=True, byte_size=bs, payl=pload, dur=dur)
            if tcp_close:
                temp = flows[tuple5_inv]
                del flows[tuple5_inv]
                tuple5_inv = (dstAddr, dport, srcAddr, sport, proto, False)
                flows[tuple5_inv] = temp
        else:
            flows[tuple5] = create_features(srcAddr, dstAddr, sport, dport, fps=pload, byte_size=bs, payl=pload,
                                            dur=dur, incoming=False)            # features_list

    for flow in flows:
        if(num > 0):
            flows[flow]['PPX'] = flows[flow]['PX']/num
        else:
            flows[flow]['PPX'] = 0
        if('PX' in flows[flow]):
            del flows[flow]['PX']
        if('NSP' in flows[flow]):
            del flows[flow]['NSP']
        if('dur' in flows[flow]):
            del flows[flow]['dur']
    return flows


field_names = [
    'srcAddr',
    'dstAddr',
    'srcPort',
    'dstPort',
    'PPX',
    'PSP',
    'in',
    'FPS',
    'TBT',
    'APL',
    'BS',
    'PPS'
]

if(__name__ == "__main__"):
    filePath = str(sys.argv[1])
    # Prepare Dictionary of Flow Features from filePath
    outfile = open(os.path.join(os.getcwd(), "results.txt"), 'x')
    csv_delimiter = "\t"
    columns = ["Flow=(srcAddr,srcPort,dstAddr,dstPort,proto)", "Prediction"]
    outfile.write(csv_delimiter.join(columns)+"\n")
    features_dict = flows_from_pcap(filePath)
    for flow in features_dict:
        if('BS' in features_dict[flow]):
            features_dict[flow]['BS'] = float(
                features_dict[flow]['BS'])
        if('PPS' in features_dict[flow]):
            features_dict[flow]['PPS'] = float(
                features_dict[flow]['PPS'])
        feature_vector = np.asarray([features_dict[flow]['srcPort'],
                                     features_dict[flow]['dstPort'],
                                     features_dict[flow]['PPX'],
                                     features_dict[flow]['PSP'],
                                     features_dict[flow]['in'],
                                     features_dict[flow]['FPS'],
                                     features_dict[flow]['TBT'],
                                     features_dict[flow]['APL'],
                                     features_dict[flow]['BS'],
                                     features_dict[flow]['PPS']])
        prediction = model.predict(feature_vector[np.newaxis, ...])
        if(prediction[0] >= 0.5):
            malicious = "malicious"
        else:
            malicious = "benign"
        outfile.write("("+str(flow[0])+","+str(flow[1])+","+str(flow[2]) +
                      ","+str(flow[3])+","+str(flow[4])+")"+"\t"+malicious+"\n")
