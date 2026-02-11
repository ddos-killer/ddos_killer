from typing import List, Tuple
from datetime import datetime
import time
from .Logger import logger

class BlacklistManager:
    """Gestion optimisée de la blacklist avec expiration"""
    
    def __init__(self):
        self.entries: List[Tuple[float, str, int, dict]] = []  # (expiry_time, flow_name, flow_data, match)
    
    def add(self, flow_name: str, switch_id: int, block_duration: int, match: dict = None):
        """Ajoute une entrée avec expiration"""
        expiry = time.time() + block_duration
        self.entries.append((expiry, flow_name, switch_id, match or {}))
        # Maintenir la liste triée par expiration
        self.entries.sort(key=lambda x: x[0])
        logger.info(f"Blacklist entry added: {match.get('ip', 'unknown')} until {datetime.fromtimestamp(expiry)}")
    
    def get_expired(self) -> List[Tuple[str, int, dict]]:
        """Retourne toutes les entrées expirées"""
        now = time.time()
        expired = []
        
        # Tant que le premier élément est expiré
        while self.entries and self.entries[0][0] < now:
            _, flow_name, switch_id, match = self.entries.pop(0)
            expired.append((flow_name, switch_id, match))
        
        return expired
    
    def __len__(self):
        return len(self.entries)