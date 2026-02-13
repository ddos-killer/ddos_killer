from typing import List, Tuple
from datetime import datetime
import time
from .Logger import logger

class BlacklistManager:
    """Gestion optimisée de la blacklist avec expiration"""
    
    def __init__(self):
        self.entries: List[Tuple[float, str, str, dict, str, str, str]] = []  # (expiry_time, flow_name, flow_data, match)
    
    def add(self, flow_name: str, switch_id: str, block_duration: int, 
            match: dict, src_ip: str = None, dst_ip: str = None, 
            metric_name: str = None):
        """Ajoute une entrée avec expiration"""
        expiry = time.time() + block_duration
        self.entries.append((expiry, flow_name, switch_id, match, src_ip, dst_ip, metric_name))
        # Maintenir la liste triée par expiration
        self.entries.sort(key=lambda x: x[0])
        logger.info(f"Blacklist entry added: {src_ip}→{dst_ip} until {datetime.fromtimestamp(expiry)}")
    
    def get_expired(self) -> List[Tuple[str, int, dict, str, str]]:
        """Retourne toutes les entrées expirées"""
        now = time.time()
        expired = []
        
        # Tant que le premier élément est expiré
        while self.entries and self.entries[0][0] < now:
            _, flow_name, switch_id, match, src_ip, dst_ip, metric_name = self.entries.pop(0)
            expired.append((flow_name, int(switch_id), match, src_ip, dst_ip))
        
        return expired
    
    def is_blocked(self, src_ip: str, dst_ip: str, metric_name: str) -> bool:
        """Vérifie si une paire IP est déjà bloquée (dans n'importe quel sens)"""
        for entry in self.entries:
            _, _, _, _, entry_src, entry_dst, entry_metric = entry
            
            if entry_metric != metric_name:
                continue
            
            # Vérifier les deux sens
            if (entry_src == src_ip and entry_dst == dst_ip) or \
               (entry_src == dst_ip and entry_dst == src_ip):
                return True
        
        return False
    
    def entry_exists(self, flow_name: str) -> bool:
        return any(entry[1] == flow_name for entry in self.entries)
    
    def __len__(self):
        return len(self.entries)