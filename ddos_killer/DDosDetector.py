import asyncio
import time
import aiohttp
import json
from dataclasses import dataclass
from .config import Config
from .BlacklistManager import BlacklistManager
from .Logger import logger


@dataclass
class AttackSignature:
    """Signature d'une attaque"""

    name: str
    keys: str
    metric_name: str
    threshold: int
    ip_proto: str
    value_type: str = "bytes"

    # Champs optionnels spécifiques au protocole
    icmpv4_type_block: str = None  # Type ICMP à bloquer
    icmpv4_type_allow: str = None  # Type ICMP à autoriser
    udp_src: str = None
    udp_dst: str = None
    tcp_flags: str = None

    bidirectional_block: bool = False


class DDosDetector:
    """Détecteur/Mitigueur DDoS asynchrone"""

    def __init__(self, config: Config):
        self.config = config
        self.blacklist = BlacklistManager()
        self.events = []
        self.event_id = -1
        self.session: aiohttp.ClientSession = None

        # Définir les signatures d'attaques
        self.attack_signatures = {
            "icmp": AttackSignature(
                name="ICMP Flood",
                keys="inputifindex,ethernetprotocol,macsource,macdestination,ipprotocol,ipsource,ipdestination",
                metric_name="icmp_flood",
                ip_proto="0x01",
                threshold=30000,  # 50kBps
                icmpv4_type_block="8",
                icmpv4_type_allow="0",
            ),
            # Attaques SIP
            "sip_invite_flood": AttackSignature(
                name="SIP INVITE Flood",
                keys="ipsource,ipdestination,tcpdestinationport",
                metric_name="sip_invite_flood",
                ip_proto="0x11",
                threshold=20,  # INVITE/sec
                udp_dst="5060",
                bidirectional_block=False,
            ),
            "sip_register_flood": AttackSignature(
                name="SIP REGISTER Flood",
                keys="ipsource,ipdestination",
                metric_name="sip_register_flood",
                ip_proto="0x11",
                threshold=10,
                udp_dst="5060",
                bidirectional_block=False,
            ),
            "sip_options_scan": AttackSignature(
                name="SIP OPTIONS Scan",
                keys="ipsource",
                metric_name="sip_options_scan",
                ip_proto="0x11",
                threshold=100,
                udp_dst="5060",
                bidirectional_block=False,
            ),
        }

    async def __aenter__(self):
        """Context manager pour gérer la session HTTP"""
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def initialize_detection(self):
        # Health checks
        sflow_ok = await self._check_sflow_rt()
        flood_ok = await self._check_floodlight()

        if not sflow_ok or not flood_ok:
            logger.error(
                f"Initialization aborted: "
                f"sFlow-RT={'OK' if sflow_ok else 'DOWN'}, "
                f"Floodlight={'OK' if flood_ok else 'DOWN'}"
            )
            return False

        """Configure sFlow-RT avec les groupes et métriques"""
        try:
            await self.add_default_forwarding_rule()
            # Configuration des groupes
            async with self.session.put(
                f"{self.config.SFLOW_RT_URL}/group/lf/json", json=self.config.GROUPS
            ) as resp:
                logger.info(f"Groups configured: {resp.status}")

            # Configuration des détections activées
            for attack_type, enabled in self.config.DEFENSE.items():
                if enabled and attack_type in self.attack_signatures:
                    await self._configure_attack_detection(
                        self.attack_signatures[attack_type]
                    )
            return True

        except Exception as e:
            logger.error(f"Initialization error: {e}")
            return False

    async def _check_sflow_rt(self) -> bool:
        try:
            async with self.session.get(
                f"{self.config.SFLOW_RT_URL}/agents/json", timeout=2
            ) as resp:
                return resp.status == 200
        except Exception as e:
            logger.error(f"sFlow-RT unreachable: {e}")
            return False

    async def _check_floodlight(self) -> bool:
        try:
            async with self.session.get(
                f"{self.config.FLOODLIGHT_URL}/wm/staticflowpusher/list/all/json",
                timeout=2,
            ) as resp:
                return resp.status == 200
        except Exception as e:
            logger.error(f"Floodlight unreachable: {e}")
            return False

    async def _configure_attack_detection(self, signature: AttackSignature):
        """Configure la détection pour un type d'attaque"""
        flows = {"keys": signature.keys, "value": signature.value_type}
        threshold = {"metric": signature.metric_name, "value": signature.threshold}

        try:
            async with self.session.put(
                f"{self.config.SFLOW_RT_URL}/flow/{signature.metric_name}/json",
                json=flows,
            ) as resp:
                logger.info(f"{signature.name} flow configured: {resp.status}")

            async with self.session.put(
                f"{self.config.SFLOW_RT_URL}/threshold/{signature.metric_name}/json",
                json=threshold,
            ) as resp:
                logger.info(f"{signature.name} threshold configured: {resp.status}")

        except Exception as e:
            logger.error(f"Error configuring {signature.name}: {e}")

    async def cleanup_expired_blocks(self):
        """Nettoie périodiquement les règles expirées"""
        while True:
            try:
                expired = self.blacklist.get_expired()

                for flow_data, metadata in expired:
                    flow_rule = json.loads(flow_data)
                    flow_name = flow_rule["name"]

                    delete_data = {
                        "name": flow_name,
                        "switch": self.config.TARGETED_SWITCH,  # ← Important !
                    }

                    async with self.session.delete(
                        f"{self.config.FLOODLIGHT_URL}/wm/staticflowentrypusher/json",
                        json=delete_data,
                        headers={'Content-Type': 'application/json'}
                    ) as resp:
                        result = await resp.json()
                        logger.info(
                            f"Unblocked {metadata.get('ip', 'unknown')}: {result.get('status')}"
                        )

            except Exception as e:
                logger.error(f"Cleanup error: {e}")

            await asyncio.sleep(self.config.CLEANUP_INTERVAL)

    async def poll_events(self):
        """Polling des événements sFlow-RT"""
        while True:
            try:
                event_url = f"{self.config.SFLOW_RT_URL}/events/json?maxEvents=10&timeout=60&eventID={self.event_id}"

                async with self.session.get(event_url) as resp:
                    events = await resp.json()

                if events:
                    self.event_id = events[0]["eventID"]
                    events.reverse()

                    for event in events:
                        await self._process_event(event)

            except asyncio.TimeoutError:
                logger.warning("Event polling timeout")
            except Exception as e:
                logger.error(f"Event polling error: {e}")

            await asyncio.sleep(self.config.POLL_INTERVAL)

    async def _process_event(self, event: dict):
        """Traite un événement de détection"""
        metric_name = event.get("metric")

        # Trouver la signature correspondante
        signature = next(
            (
                sig
                for sig in self.attack_signatures.values()
                if sig.metric_name == metric_name
            ),
            None,
        )

        if not signature:
            return

        try:
            # Récupérer les métriques détaillées
            metric_url = f"{self.config.SFLOW_RT_URL}/metric/ALL/{event['dataSource']}.{metric_name}/json"

            async with self.session.get(metric_url) as resp:
                metrics = await resp.json()

            if not metrics:
                return

            metric = metrics[0]

            if metric.get("metricValue", 0) > signature.threshold and metric.get(
                "topKeys"
            ):
                for top_key in metric["topKeys"]:
                    if top_key.get("value") and top_key.get("key"):
                        if top_key["value"] > signature.threshold:
                            await self._block_source(top_key["key"], signature)
                            break  # Bloquer seulement le premier

        except Exception as e:
            logger.error(f"Error processing event: {e}")

    def _is_protected_ip(self, ip: str) -> bool:

        if ip in self.config.CONTROLLER_IP:
            return True

        if ip in self.config.TARGETED_SWITCH_IP:
            return True

        return False

    def build_rules(self, signature: AttackSignature, src_ip: str, dst_ip: str):
        """Construit les règles block + allow"""

        block_rule = {
            "switch": self.config.TARGETED_SWITCH,
            "name": f"{signature.metric_name}_block_{src_ip}_{dst_ip}",
            "priority": self.config.FW_PRIORITY,
            "ip_proto": signature.ip_proto,
            "active": "true",
            "eth_type": "0x0800"
        }

        allow_rule = {
            "switch": self.config.TARGETED_SWITCH,
            "name": f"{signature.metric_name}_allow_{dst_ip}_{src_ip}",
            "priority": int(self.config.FW_PRIORITY) + 1,
            "ip_proto": signature.ip_proto,
            "active": "true",
            "eth_type": "0x0800",
            "actions": "output=normal",
        }

        # Ajouter les champs optionnels s'ils existent
        if signature.ip_proto == "0x01":
            if signature.icmpv4_type_block:
                block_rule["icmpv4_type"] = signature.icmpv4_type_block
                block_rule["ipv4_src"] = src_ip
                block_rule["ipv4_dst"] = dst_ip
                allow_rule["ipv4_src"] = src_ip
                allow_rule["ipv4_dst"] = dst_ip
            if signature.icmpv4_type_allow:
                allow_rule["icmpv4_type"] = signature.icmpv4_type_allow
        elif signature.ip_proto == "0x11" and signature.udp_dst:
            block_rule["udp_dst"] = signature.udp_dst
            allow_rule["udp_src"] = signature.udp_dst
            block_rule["ipv4_src"] = src_ip
            block_rule["ipv4_dst"] = dst_ip
            allow_rule["ipv4_src"] = dst_ip
            allow_rule["ipv4_dst"] = src_ip
        else:
            allow_rule = None
            block_rule["ipv4_src"] = src_ip
            block_rule["ipv4_dst"] = dst_ip
        if signature.tcp_flags:
            block_rule["tcp_flags"] = signature.tcp_flags

        return block_rule, allow_rule
    
    async def add_default_forwarding_rule(self):
        """Règles par défaut pour le forwarding normal"""
        
        # Règle 1 : Forwarding L2 normal (apprend les MAC)
        l2_forward = {
            "switch": self.config.TARGETED_SWITCH,
            "name": "default_l2_forward",
            "priority": "10",  # Entre 1 (CONTROLLER) et 1000 (tes règles)
            "active": "true",
            "actions": "output=normal"  # Learning switch behavior
        }
        
        # Règle 2 : Autoriser explicitement ARP
        arp_allow = {
            "switch": self.config.TARGETED_SWITCH,
            "name": "allow_arp",
            "priority": "100",
            "eth_type": "0x0806",  # ARP
            "active": "true",
            "actions": "output=normal"
        }
        
        # Règle 3 : Autoriser le trafic sFlow (UDP 6343)
        sflow_allow = {
            "switch": self.config.TARGETED_SWITCH,
            "name": "allow_sflow",
            "priority": "100",
            "eth_type": "0x0800",
            "ip_proto": "0x11",  # UDP
            "udp_dst": "6343",   # Port sFlow
            "active": "true",
            "actions": "output=normal"
        }
        
        # Règle 4 : Autoriser le trafic de contrôle OpenFlow
        openflow_allow = {
            "switch": self.config.TARGETED_SWITCH,
            "name": "allow_openflow",
            "priority": "200",
            "eth_type": "0x0800",
            "ip_proto": "0x06",  # TCP
            "tcp_dst": "6653",   # Port OpenFlow
            "active": "true",
            "actions": "output=normal"
        }
        
        for rule in [l2_forward, arp_allow, sflow_allow, openflow_allow]:
            try:
                async with self.session.post(
                    f'{self.config.FLOODLIGHT_URL}/wm/staticflowentrypusher/json',
                    json=rule,
                    headers={'Content-Type': 'application/json'}
                ) as resp:
                    result = await resp.json()
                    logger.info(
                        f"✅ Infrastructure rule '{rule['name']}': "
                        f"{result.get('status')}"
                    )
            except Exception as e:
                logger.error(f"Error installing {rule['name']}: {e}")

    async def _block_source(self, key: str, signature: AttackSignature):
        """Bloque une source malveillante"""
        parts = key.split(",")

        if len(parts) < 7:
            logger.warning(f"Invalid key format: {key}")
            return

        src_ip = parts[5]
        dst_ip = parts[6]

        if self._is_protected_ip(src_ip):
            logger.warning(f"Skipping protected IP: {src_ip}")
            return

        block_rule, allow_rule = self.build_rules(signature, src_ip, dst_ip)

        logger.info(block_rule)
        logger.info(allow_rule)

        self.events.append(
            {
                "timestamp": time.time(),
                "metric": signature.metric_name,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "attack": signature.name,
            }
        )

        try:
            async with self.session.post(
                f"{self.config.FLOODLIGHT_URL}/wm/staticflowentrypusher/json",
                data=json.dumps(block_rule),
            ) as resp:
                result = await resp.json()
                logger.warning(
                    f"🚨 BLOCKED {src_ip} -> {dst_ip} ({signature.name}): {result.get('status')}"
                )

            # Ajouter à la blacklist avec métadonnées
            self.blacklist.add(
                json.dumps(block_rule),
                self.config.BLOCK_TIME,
                {"ip": src_ip, "attack_type": signature.name},
            )

            if allow_rule:
                async with self.session.post(
                    f"{self.config.FLOODLIGHT_URL}/wm/staticflowentrypusher/json",
                    data=json.dumps(allow_rule),
                ) as resp:
                    result = await resp.json()
                    logger.info(
                        f"✅ ALLOWED {allow_rule['ipv4_dst']} -> {allow_rule['ipv4_src']} ({signature.name}): {result.get('status')}"
                    )

                # Ajouter à la blacklist avec métadonnées
                self.blacklist.add(
                    json.dumps(allow_rule),
                    self.config.BLOCK_TIME,
                    {"ip": src_ip, "attack_type": signature.name},
                )

        except Exception as e:
            logger.error(f"Error blocking {src_ip}: {e}")

    async def run(self):
        """Lance le détecteur avec toutes ses tâches"""
        initialized = await self.initialize_detection()

        if not initialized:
            logger.error("Engine not started: infrastructure not ready")
            return False

        logger.info("Engine started")

        # Lancer les tâches en parallèle
        await asyncio.gather(
            self.poll_events(), self.cleanup_expired_blocks(), return_exceptions=True
        )
