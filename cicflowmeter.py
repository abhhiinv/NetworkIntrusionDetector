import os
import time
import joblib
import numpy as np
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP

# ---------------------------------------------------------
# 1. LOAD ML COMPONENTS
# ---------------------------------------------------------
base = 'D:/Academic/ML/ModelTraining/output'
model = joblib.load(f'{base}/ensemble_model.pkl')
scaler = joblib.load(f'{base}/scaler.pkl')
label_encoder = joblib.load(f'{base}/label_encoder.pkl')

FEATURE_ORDER = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Length of Fwd Packets',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std',
    'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
    'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
    'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
    'FIN Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'Average Packet Size', 'Subflow Fwd Bytes',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
    'Active Mean', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Max', 'Idle Min'
]

# ---------------------------------------------------------
# 2. CUSTOM FLOW TRACKER (CICFlowMeter Clone)
# ---------------------------------------------------------
class Flow:
    def __init__(self, src_ip, src_port, dst_ip, dst_port, proto, timestamp):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.proto = proto
        
        self.start_time = timestamp
        self.end_time = timestamp
        
        self.fwd_pkt_lengths = []
        self.bwd_pkt_lengths = []
        self.fwd_timestamps = []
        self.bwd_timestamps = []
        
        self.fin_cnt = 0
        self.psh_cnt = 0
        self.ack_cnt = 0
        
        self.fwd_header_len = 0
        self.bwd_header_len = 0
        self.act_data_pkt_fwd = 0
        
        # Initialize TCP Window tracking variables
        self.init_win_bytes_fwd = -1
        self.init_win_bytes_bwd = -1

    def add_packet(self, pkt, direction, timestamp):
        self.end_time = timestamp
        pkt_len = len(pkt)
        
        # Track TCP Flags and Windows
        if TCP in pkt:
            flags = pkt[TCP].flags
            if 'F' in flags: self.fin_cnt += 1
            if 'P' in flags: self.psh_cnt += 1
            if 'A' in flags: self.ack_cnt += 1
            hdr_len = pkt[TCP].dataofs * 4 if pkt[TCP].dataofs else 20
            
            # Extract Init_Win_bytes
            if direction == 'fwd' and self.init_win_bytes_fwd == -1:
                self.init_win_bytes_fwd = pkt[TCP].window
            elif direction == 'bwd' and self.init_win_bytes_bwd == -1:
                self.init_win_bytes_bwd = pkt[TCP].window
                
        elif UDP in pkt:
            hdr_len = 8
        else:
            hdr_len = 0
            
        ip_hdr_len = pkt[IP].ihl * 4 if IP in pkt else 20
        total_hdr_len = ip_hdr_len + hdr_len

        if direction == 'fwd':
            self.fwd_pkt_lengths.append(pkt_len)
            self.fwd_timestamps.append(timestamp)
            self.fwd_header_len += total_hdr_len
            if TCP in pkt and len(pkt[TCP].payload) > 0:
                self.act_data_pkt_fwd += 1
        else:
            self.bwd_pkt_lengths.append(pkt_len)
            self.bwd_timestamps.append(timestamp)
            self.bwd_header_len += total_hdr_len

    def _safe_stats(self, data):
        if not data: return 0, 0, 0, 0
        return np.max(data), np.min(data), np.mean(data), np.std(data)

    def _calc_iat(self, timestamps):
        if len(timestamps) < 2: return 0, 0, 0, 0, 0
        # Convert to microseconds like CICFlowMeter
        iats = np.diff(timestamps) * 1e6 
        return np.sum(iats), np.mean(iats), np.std(iats), np.max(iats), np.min(iats)

    def extract_features(self):
        dur_s = max(self.end_time - self.start_time, 1e-6)
        dur_us = dur_s * 1e6
        
        tot_fwd_pkts = len(self.fwd_pkt_lengths)
        tot_bwd_pkts = len(self.bwd_pkt_lengths)
        tot_pkts = tot_fwd_pkts + tot_bwd_pkts
        
        totlen_fwd = sum(self.fwd_pkt_lengths)
        totlen_bwd = sum(self.bwd_pkt_lengths)
        tot_bytes = totlen_fwd + totlen_bwd
        
        fwd_max, fwd_min, fwd_mean, fwd_std = self._safe_stats(self.fwd_pkt_lengths)
        bwd_max, bwd_min, bwd_mean, bwd_std = self._safe_stats(self.bwd_pkt_lengths)
        all_max, all_min, all_mean, all_std = self._safe_stats(self.fwd_pkt_lengths + self.bwd_pkt_lengths)
        
        all_iat_tot, all_iat_mean, all_iat_std, all_iat_max, all_iat_min = self._calc_iat(sorted(self.fwd_timestamps + self.bwd_timestamps))
        fwd_iat_tot, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = self._calc_iat(self.fwd_timestamps)
        bwd_iat_tot, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = self._calc_iat(self.bwd_timestamps)

        # Build feature dict matching your model's exact naming
        return {
            'Destination Port': self.dst_port,
            'Flow Duration': dur_us,
            'Total Fwd Packets': tot_fwd_pkts,
            'Total Length of Fwd Packets': totlen_fwd,
            'Fwd Packet Length Max': fwd_max,
            'Fwd Packet Length Min': fwd_min,
            'Fwd Packet Length Mean': fwd_mean,
            'Fwd Packet Length Std': fwd_std,
            'Bwd Packet Length Max': bwd_max,
            'Bwd Packet Length Min': bwd_min,
            'Bwd Packet Length Mean': bwd_mean,
            'Bwd Packet Length Std': bwd_std,
            'Flow Bytes/s': tot_bytes / dur_s,
            'Flow Packets/s': tot_pkts / dur_s,
            'Flow IAT Mean': all_iat_mean,
            'Flow IAT Std': all_iat_std,
            'Flow IAT Max': all_iat_max,
            'Flow IAT Min': all_iat_min,
            'Fwd IAT Total': fwd_iat_tot,
            'Fwd IAT Mean': fwd_iat_mean,
            'Fwd IAT Std': fwd_iat_std,
            'Fwd IAT Max': fwd_iat_max,
            'Fwd IAT Min': fwd_iat_min,
            'Bwd IAT Total': bwd_iat_tot,
            'Bwd IAT Mean': bwd_iat_mean,
            'Bwd IAT Std': bwd_iat_std,
            'Bwd IAT Max': bwd_iat_max,
            'Bwd IAT Min': bwd_iat_min,
            'Fwd Header Length': self.fwd_header_len,
            'Bwd Header Length': self.bwd_header_len,
            'Fwd Packets/s': tot_fwd_pkts / dur_s,
            'Bwd Packets/s': tot_bwd_pkts / dur_s,
            'Min Packet Length': all_min,
            'Max Packet Length': all_max,
            'Packet Length Mean': all_mean,
            'Packet Length Std': all_std,
            'Packet Length Variance': all_std ** 2,
            'FIN Flag Count': self.fin_cnt,
            'PSH Flag Count': self.psh_cnt,
            'ACK Flag Count': self.ack_cnt,
            'Average Packet Size': tot_bytes / tot_pkts if tot_pkts > 0 else 0,
            'Subflow Fwd Bytes': totlen_fwd,
            'Init_Win_bytes_forward': self.init_win_bytes_fwd if self.init_win_bytes_fwd != -1 else 0,
            'Init_Win_bytes_backward': self.init_win_bytes_bwd if self.init_win_bytes_bwd != -1 else 0,
            'act_data_pkt_fwd': self.act_data_pkt_fwd,
            'min_seg_size_forward': 20,       # Default assumed TCP/IP min
            'Active Mean': 0, 'Active Max': 0, 'Active Min': 0, # Simplified
            'Idle Mean': 0, 'Idle Max': 0, 'Idle Min': 0        # Simplified
        }

# ---------------------------------------------------------
# 3. ENGINE LOOP
# ---------------------------------------------------------
print("Starting Custom Native IDS Engine...")

while True:
    try:
        print("\n[Sniffing] Capturing live traffic on 'Wi-Fi' for 10 seconds...")
        packets = sniff(iface="Wi-Fi", timeout=10)
        
        if len(packets) == 0:
            print("No traffic detected.")
            continue
            
        print(f"[Processing] {len(packets)} packets captured. Assembling flows...")
        
        flows = {}
        for pkt in packets:
            if IP in pkt and (TCP in pkt or UDP in pkt):
                src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
                src_port = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport
                dst_port = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
                proto = pkt[IP].proto
                timestamp = float(pkt.time)
                
                fwd_key = (src_ip, src_port, dst_ip, dst_port, proto)
                bwd_key = (dst_ip, dst_port, src_ip, src_port, proto)
                
                if fwd_key in flows:
                    flows[fwd_key].add_packet(pkt, 'fwd', timestamp)
                elif bwd_key in flows:
                    flows[bwd_key].add_packet(pkt, 'bwd', timestamp)
                else:
                    flows[fwd_key] = Flow(src_ip, src_port, dst_ip, dst_port, proto, timestamp)
                    flows[fwd_key].add_packet(pkt, 'fwd', timestamp)
                    
        if not flows:
            print("No TCP/UDP flows found in this chunk.")
            continue
            
        # Extract features and predict
        print(f"[Inference] Running ML Model on {len(flows)} unique flows...")
        for key, flow in flows.items():
            feats = flow.extract_features()
            
            # Format directly into the DataFrame order
            mapped_feats = [feats[col] for col in FEATURE_ORDER]
            vector = pd.DataFrame([mapped_feats], columns=FEATURE_ORDER)
            
            # ML Pipeline
            vector_scaled = scaler.transform(vector)
            pred = model.predict(vector_scaled)
            label = label_encoder.inverse_transform(pred)
            
            print(f"[*] {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port}  =>  {label[0]}")
            
    except KeyboardInterrupt:
        print("\nShutting down IDS...")
        break
    except Exception as e:
        print(f"\n[!] Error in processing loop: {e}")
        time.sleep(2)