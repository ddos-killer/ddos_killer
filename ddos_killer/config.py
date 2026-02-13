import os
from dotenv import load_dotenv
from dataclasses import dataclass

load_dotenv()

@dataclass
class Config:
    TARGETED_SWITCH = os.getenv("TARGETED_SWITCH", "00:00:00:00:00:00:00:01")
    TARGETED_SWITCH_IP = os.getenv('TARGETED_SWITCH_IP', 'localhost')
    SFLOW_RT_URL = f"http://{os.getenv('SFLOW_RT_IP', 'localhost')}:8008"
    RYU_URL = f"http://{os.getenv('RYU_IP', 'localhost')}:8080"
    SFLOW_RT_IP = os.getenv('SFLOW_RT_IP', 'localhost')
    RYU_IP = os.getenv('RYU_IP', 'localhost')
    CONTROLLER_IP = os.getenv('CONTROLLER', 'localhost')
    PROTECTED_SUBNET = os.getenv('PROTECTED_SUBNET')
    BLOCK_TIME = 30
    FW_PRIORITY = 1000
    POLL_INTERVAL = 3
    CLEANUP_INTERVAL = 10

    GROUPS = {"external": ["0.0.0.0/0"], "internal": ["0.0.0.0/0"]}
    DEFENSE = {"icmp": True, "sip_flood": True, "syn": False, "dns_amplifier": False, "udp": True}
