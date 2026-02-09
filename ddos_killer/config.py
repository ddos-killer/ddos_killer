import os
from dotenv import load_dotenv
from dataclasses import dataclass

load_dotenv()

@dataclass
class Config:
    TARGETED_SWITCH = os.getenv("TARGETED_SWITCH_MAC", "00:00:00:00:00:00:00:01")
    TARGETED_SWITCH_IP = os.getenv('TARGETED_SWITCH_IP', 'localhost')
    SFLOW_RT_URL = f"http://{os.getenv('SFLOW_RT_IP', 'localhost')}:8008"
    FLOODLIGHT_URL = f"http://{os.getenv('FLOODLIGHT_IP', 'localhost')}:8080"
    SFLOW_RT_IP = os.getenv('SFLOW_RT_IP', 'localhost')
    FLOODLIGHT_IP = os.getenv('FLOODLIGHT_IP', 'localhost')
    CONTROLLER_IP = os.getenv('CONTROLLER', 'localhost')
    PROTECTED_SUBNET = os.getenv('PROTECTED_SUBNET')
    BLOCK_TIME = 360
    FW_PRIORITY = "32767"
    POLL_INTERVAL = 3
    CLEANUP_INTERVAL = 10

    GROUPS = {"external": ["0.0.0.0/0"], "internal": ["0.0.0.0/0"]}
    DEFENSE = {"icmp": True, "syn": False, "dns_amplifier": False, "udp": False}
