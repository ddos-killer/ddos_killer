import os
from dotenv import load_dotenv
from dataclasses import dataclass

load_dotenv()

@dataclass
class Config:
    TARGETED_SWITCH = os.getenv("TARGETTED_SWITCH_MAC", "00:00:00:00:00:00:00:01")
    SFLOW_RT = f"http://{os.getenv('SFLOW_RT_IP', 'localhost')}:8008"
    FLOODLIGHT = f"http://{os.getenv('FLOODLIGHT_IP', 'localhost')}:8080"
    BLOCK_TIME = 360
    FW_PRIORITY = "32767"
    POLL_INTERVAL = 3
    CLEANUP_INTERVAL = 10

    GROUPS = {"external": ["0.0.0.0/0"], "internal": ["0.0.0.0/0"]}
    DEFENSE = {"icmp": True, "syn": False, "dns_amplifier": False, "udp": False}
