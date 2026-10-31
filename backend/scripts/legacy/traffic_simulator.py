"""
Network Traffic Simulator
Generates realistic network flows and feeds them through ML detection pipeline
No admin privileges required - simulates packet capture
"""

import asyncio
import random
import time
import numpy as np
from datetime import datetime
from app.ml.ids_service import get_ids_service
from app.utils.logger import logger

class TrafficSimulator:
    """Simulates network traffic for IDS testing"""
    
    def __init__(self):
        self.running = False
        self.packets_generated = 0
        
        # Realistic IP pools
        self.internal_ips = [
            "192.168.1.100", "192.168.1.101", "192.168.1.102",
            "10.0.0.10", "10.0.0.20", "172.16.0.50"
        ]
        self.external_ips = [
            "8.8.8.8", "1.1.1.1", "142.250.185.46",  # Google, Cloudflare
            "151.101.1.140", "104.16.132.229",       # Reddit, Cloudflare
            "93.184.216.34", "52.85.151.23"          # Example.com, AWS
        ]
        self.attack_ips = [
            "203.0.113.45", "198.51.100.23", "192.0.2.100",
            "185.220.101.50", "45.142.122.98"
        ]
        
    def generate_benign_flow(self):
        """Generate normal network traffic features"""
        src_ip = random.choice(self.internal_ips)
        dst_ip = random.choice(self.external_ips)
        
        # Normal web browsing patterns
        features = {
            # Source/Dest
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': random.randint(49152, 65535),  # Ephemeral ports
            'dst_port': random.choice([80, 443, 53]),   # HTTP, HTTPS, DNS
            'protocol': 6,  # TCP
            
            # Flow timing (normal browsing)
            'flow_duration': random.uniform(0.1, 5.0),
            'flow_iat_mean': random.uniform(0.01, 0.5),
            'flow_iat_std': random.uniform(0.005, 0.2),
            'flow_iat_max': random.uniform(0.1, 1.0),
            'flow_iat_min': random.uniform(0.001, 0.05),
            
            # Packet counts (normal)
            'fwd_pkts_tot': random.randint(5, 50),
            'bwd_pkts_tot': random.randint(5, 50),
            'totlen_fwd_pkts': random.randint(500, 5000),
            'totlen_bwd_pkts': random.randint(1000, 10000),
            
            # Packet sizes (normal HTTP/HTTPS)
            'fwd_pkt_len_max': random.randint(500, 1500),
            'fwd_pkt_len_min': random.randint(40, 100),
            'fwd_pkt_len_mean': random.uniform(200, 800),
            'fwd_pkt_len_std': random.uniform(50, 300),
            
            'bwd_pkt_len_max': random.randint(500, 1500),
            'bwd_pkt_len_min': random.randint(40, 100),
            'bwd_pkt_len_mean': random.uniform(300, 1000),
            'bwd_pkt_len_std': random.uniform(100, 400),
            
            # Inter-arrival times (normal)
            'fwd_iat_tot': random.uniform(0.5, 3.0),
            'fwd_iat_mean': random.uniform(0.05, 0.3),
            'fwd_iat_std': random.uniform(0.01, 0.1),
            'fwd_iat_max': random.uniform(0.2, 0.8),
            'fwd_iat_min': random.uniform(0.001, 0.05),
            
            'bwd_iat_tot': random.uniform(0.5, 3.0),
            'bwd_iat_mean': random.uniform(0.05, 0.3),
            'bwd_iat_std': random.uniform(0.01, 0.1),
            'bwd_iat_max': random.uniform(0.2, 0.8),
            'bwd_iat_min': random.uniform(0.001, 0.05),
            
            # TCP flags (normal)
            'fwd_psh_flags': random.randint(1, 3),
            'bwd_psh_flags': random.randint(1, 3),
            'fwd_urg_flags': 0,
            'bwd_urg_flags': 0,
            
            # Header lengths
            'fwd_header_len': random.randint(20, 60),
            'bwd_header_len': random.randint(20, 60),
            
            # Packet rates (normal)
            'fwd_pkts_s': random.uniform(1, 20),
            'bwd_pkts_s': random.uniform(1, 20),
            
            # Segment sizes
            'fwd_seg_size_min': random.randint(20, 60),
            'bwd_seg_size_min': random.randint(20, 60),
            
            # Activity times
            'active_mean': random.uniform(0.5, 2.0),
            'active_std': random.uniform(0.1, 0.5),
            'active_max': random.uniform(1.0, 3.0),
            'active_min': random.uniform(0.1, 0.5),
            
            'idle_mean': random.uniform(0.1, 1.0),
            'idle_std': random.uniform(0.05, 0.3),
            'idle_max': random.uniform(0.5, 2.0),
            'idle_min': random.uniform(0.01, 0.1),
            
            # Flags and other
            'init_fwd_win_byts': random.randint(8000, 65535),
            'init_bwd_win_byts': random.randint(8000, 65535),
            'fwd_act_data_pkts': random.randint(3, 20),
            'fwd_seg_size_avg': random.uniform(200, 800),
            'bwd_seg_size_avg': random.uniform(300, 1000),
            'subflow_fwd_pkts': random.randint(5, 50),
            'subflow_fwd_byts': random.randint(500, 5000),
            'subflow_bwd_pkts': random.randint(5, 50),
            'subflow_bwd_byts': random.randint(1000, 10000),
        }
        
        return features
    
    def generate_attack_flow(self, attack_type):
        """Generate attack traffic with specific patterns"""
        src_ip = random.choice(self.attack_ips)
        dst_ip = random.choice(self.internal_ips)
        
        if attack_type == 'DoS':
            # High packet rate, small packets, short duration
            features = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([80, 443, 22]),
                'protocol': 6,
                'flow_duration': random.uniform(0.001, 0.1),  # Very short
                'fwd_pkts_tot': random.randint(1, 5),  # Many small flows
                'bwd_pkts_tot': 0,  # No response
                'totlen_fwd_pkts': random.randint(40, 200),  # Small
                'totlen_bwd_pkts': 0,
                'fwd_pkt_len_mean': random.uniform(40, 60),
                'fwd_pkts_s': random.uniform(1000, 10000),  # Very high rate
                'flow_iat_mean': random.uniform(0.0001, 0.001),  # Very fast
                'fwd_psh_flags': 0,
                'bwd_psh_flags': 0,
                'fwd_urg_flags': 0,
                'init_fwd_win_byts': 0,
                'init_bwd_win_byts': 0,
            }
        elif attack_type == 'Port Scan':
            # Many connections to different ports
            features = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': random.randint(40000, 65535),
                'dst_port': random.randint(1, 1024),  # Scanning low ports
                'protocol': 6,
                'flow_duration': random.uniform(0.001, 0.05),
                'fwd_pkts_tot': 1,  # SYN only
                'bwd_pkts_tot': random.choice([0, 1]),  # May or may not respond
                'totlen_fwd_pkts': 60,
                'totlen_bwd_pkts': random.choice([0, 60]),
                'fwd_pkts_s': random.uniform(100, 1000),
                'flow_iat_mean': random.uniform(0.001, 0.01),
                'fwd_psh_flags': 0,
                'fwd_urg_flags': 0,
                'init_fwd_win_byts': 1024,
            }
        elif attack_type == 'Brute Force':
            # Repeated login attempts
            features = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': random.randint(40000, 65535),
                'dst_port': random.choice([22, 21, 3389]),  # SSH, FTP, RDP
                'protocol': 6,
                'flow_duration': random.uniform(0.5, 2.0),
                'fwd_pkts_tot': random.randint(10, 30),
                'bwd_pkts_tot': random.randint(10, 30),
                'totlen_fwd_pkts': random.randint(300, 1000),
                'totlen_bwd_pkts': random.randint(300, 1000),
                'fwd_pkt_len_mean': random.uniform(50, 100),
                'fwd_pkts_s': random.uniform(5, 15),
                'flow_iat_mean': random.uniform(0.1, 0.5),
                'fwd_psh_flags': random.randint(2, 5),
            }
        elif attack_type == 'Bot':
            # Automated traffic patterns
            features = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': random.randint(30000, 50000),
                'dst_port': random.choice([80, 443, 8080]),
                'protocol': 6,
                'flow_duration': random.uniform(1.0, 10.0),
                'fwd_pkts_tot': random.randint(50, 200),
                'bwd_pkts_tot': random.randint(50, 200),
                'totlen_fwd_pkts': random.randint(2000, 10000),
                'totlen_bwd_pkts': random.randint(2000, 10000),
                'fwd_pkt_len_mean': random.uniform(100, 500),
                'fwd_pkts_s': random.uniform(20, 100),
                'flow_iat_mean': random.uniform(0.01, 0.05),  # Very regular
                'flow_iat_std': random.uniform(0.001, 0.01),  # Low variance
                'fwd_psh_flags': random.randint(5, 20),
            }
        else:
            # Default to benign
            return self.generate_benign_flow()
        
        # Fill in remaining features with defaults
        all_features = self.generate_benign_flow()
        all_features.update(features)
        return all_features
    
    async def simulate_traffic(self, benign_ratio=0.7, interval=2.0):
        """
        Generate simulated traffic
        benign_ratio: probability of generating benign vs attack traffic
        interval: seconds between flow generations
        """
        ids_service = get_ids_service()
        attack_types = ['DoS', 'Port Scan', 'Brute Force', 'Bot']
        
        logger.info(f"🚀 Traffic simulator started (benign_ratio={benign_ratio}, interval={interval}s)")
        
        while self.running:
            try:
                # Decide if this is benign or attack
                if random.random() < benign_ratio:
                    flow = self.generate_benign_flow()
                    flow_type = "Benign"
                else:
                    attack_type = random.choice(attack_types)
                    flow = self.generate_attack_flow(attack_type)
                    flow_type = f"Attack ({attack_type})"
                
                # Create feature vector (71 features in correct order)
                feature_vector = self._create_feature_vector(flow)
                
                # Feed to IDS for analysis
                await ids_service._process_flow(
                    src_ip=flow['src_ip'],
                    dst_ip=flow['dst_ip'],
                    src_port=flow['src_port'],
                    dst_port=flow['dst_port'],
                    protocol=flow['protocol'],
                    features=feature_vector
                )
                
                self.packets_generated += 1
                
                if self.packets_generated % 10 == 0:
                    logger.info(f"📊 Simulator: {self.packets_generated} flows generated ({flow_type})")
                
                await asyncio.sleep(interval)
                
            except Exception as e:
                logger.error(f"Simulator error: {e}", exc_info=True)
                await asyncio.sleep(interval)
    
    def _create_feature_vector(self, flow):
        """Convert flow dict to numpy array in correct feature order"""
        # These are the 71 features your model expects
        features_order = [
            'dst_port', 'protocol', 'flow_duration', 'flow_iat_mean', 'flow_iat_std',
            'flow_iat_max', 'flow_iat_min', 'fwd_pkts_tot', 'bwd_pkts_tot',
            'totlen_fwd_pkts', 'totlen_bwd_pkts', 'fwd_pkt_len_max', 'fwd_pkt_len_min',
            'fwd_pkt_len_mean', 'fwd_pkt_len_std', 'bwd_pkt_len_max', 'bwd_pkt_len_min',
            'bwd_pkt_len_mean', 'bwd_pkt_len_std', 'fwd_header_len', 'bwd_header_len',
            'fwd_pkts_s', 'bwd_pkts_s', 'pkt_len_max', 'pkt_len_min', 'pkt_len_mean',
            'pkt_len_std', 'pkt_len_var', 'fwd_header_len_1', 'fwd_seg_size_min',
            'bwd_seg_size_min', 'active_mean', 'active_std', 'active_max', 'active_min',
            'idle_mean', 'idle_std', 'idle_max', 'idle_min', 'fwd_iat_tot', 'fwd_iat_mean',
            'fwd_iat_std', 'fwd_iat_max', 'fwd_iat_min', 'bwd_iat_tot', 'bwd_iat_mean',
            'bwd_iat_std', 'bwd_iat_max', 'bwd_iat_min', 'fwd_psh_flags', 'bwd_psh_flags',
            'fwd_urg_flags', 'bwd_urg_flags', 'fwd_act_data_pkts', 'fwd_seg_size_avg',
            'bwd_seg_size_avg', 'init_fwd_win_byts', 'init_bwd_win_byts', 'subflow_fwd_pkts',
            'subflow_fwd_byts', 'subflow_bwd_pkts', 'subflow_bwd_byts', 'fwd_win_byts_min',
            'fwd_win_byts_mean', 'fwd_win_byts_max', 'bwd_win_byts_min', 'bwd_win_byts_mean',
            'bwd_win_byts_max', 'down_up_ratio', 'fwd_byts_b_avg', 'fwd_pkts_b_avg',
            'bwd_byts_b_avg', 'bwd_pkts_b_avg'
        ]
        
        # Fill missing features with computed or default values
        if 'pkt_len_max' not in flow:
            flow['pkt_len_max'] = max(flow.get('fwd_pkt_len_max', 0), flow.get('bwd_pkt_len_max', 0))
        if 'pkt_len_min' not in flow:
            flow['pkt_len_min'] = min(flow.get('fwd_pkt_len_min', 1500), flow.get('bwd_pkt_len_min', 1500))
        if 'pkt_len_mean' not in flow:
            flow['pkt_len_mean'] = (flow.get('fwd_pkt_len_mean', 0) + flow.get('bwd_pkt_len_mean', 0)) / 2
        if 'pkt_len_std' not in flow:
            flow['pkt_len_std'] = (flow.get('fwd_pkt_len_std', 0) + flow.get('bwd_pkt_len_std', 0)) / 2
        
        # Default values for missing features
        for feature in features_order:
            if feature not in flow:
                flow[feature] = 0.0
        
        # Create numpy array
        feature_vector = np.array([float(flow.get(f, 0.0)) for f in features_order])
        return feature_vector
    
    async def start(self, benign_ratio=0.7, interval=2.0):
        """Start the traffic simulator"""
        if self.running:
            logger.warning("Simulator already running")
            return
        
        self.running = True
        await self.simulate_traffic(benign_ratio, interval)
    
    def stop(self):
        """Stop the traffic simulator"""
        self.running = False
        logger.info(f"🛑 Traffic simulator stopped ({self.packets_generated} flows generated)")


# Global simulator instance
_simulator = None

def get_simulator():
    """Get or create simulator instance"""
    global _simulator
    if _simulator is None:
        _simulator = TrafficSimulator()
    return _simulator


async def start_simulator(benign_ratio=0.7, interval=2.0):
    """Start traffic simulation"""
    simulator = get_simulator()
    await simulator.start(benign_ratio, interval)


def stop_simulator():
    """Stop traffic simulation"""
    simulator = get_simulator()
    simulator.stop()


if __name__ == "__main__":
    # Test the simulator
    async def test():
        simulator = get_simulator()
        simulator.running = True
        await simulator.simulate_traffic(benign_ratio=0.5, interval=1.0)
    
    asyncio.run(test())
