import asyncio
import time
import aiohttp
import json
from dataclasses import dataclass
from .config import Config
from .BlacklistManager import BlacklistManager
from .Logger import logger

# Classe de typage des attaques
@dataclass
class AttackSignature:
    """Signature d'une attaque"""

    name: str
    keys: str
    metric_name: str
    threshold: int
    ip_proto: int
    value_type: str = "bytes"

    # Champs spécifiques au protocole
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

        # Définition des signatures d'attaques
        self.attack_signatures = {
            "icmp": AttackSignature(
                name="ICMP Flood",
                keys="inputifindex,ethernetprotocol,macsource,macdestination,ipprotocol,ipsource,ipdestination",
                metric_name="icmp_flood",
                ip_proto=1,
                threshold=30000,  # 30kBps
                icmpv4_type_block="8",
                icmpv4_type_allow="0",
            ),
            # Attaques SIP
            "sip_flood": AttackSignature(
                name="SIP Flood",
                keys="ipsource,ipdestination,udpdestinationport",
                metric_name="sip_flood",
                ip_proto=17,
                threshold=15000,  # 50 kB/s de trafic SIP
                udp_dst="5060",
                bidirectional_block=False,
            ),
        }

    # Fonction de mofidication des seuils de détection
    async def set_threshold(self, attack_type: str, threshold: int): 
        if self.attack_signatures[attack_type]:
            self.attack_signatures[attack_type].threshold = threshold
            await self._configure_attack_detection(self.attack_signatures[attack_type])
        else:
            return False
        
        return True

    async def __aenter__(self):
        """Context manager pour gérer la session HTTP"""
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    # Vérification de l'infrastructure (Ryu + sFlow-RT) et envoi des types de détection voulus à sFlow-RT 
    async def initialize_detection(self):
        # Health checks
        sflow_ok = await self._check_sflow_rt()
        ryu_ok = await self._check_ryu()

        if not sflow_ok or not ryu_ok:
            logger.error(
                f"Initialization aborted: "
                f"sFlow-RT={'OK' if sflow_ok else 'DOWN'}, "
                f"Ryu={'OK' if ryu_ok else 'DOWN'}"
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

    # Vérification que sFlow-RT fonctionne bien
    async def _check_sflow_rt(self) -> bool:
        try:
            async with self.session.get(
                f"{self.config.SFLOW_RT_URL}/agents/json", timeout=2
            ) as resp:
                return resp.status == 200
        except Exception as e:
            logger.error(f"sFlow-RT unreachable: {e}")
            return False

    # Vérification que Ryu fonctionne bien
    async def _check_ryu(self) -> bool:
        try:
            async with self.session.get(
                f"{self.config.RYU_URL}/stats/switches",
                timeout=2,
            ) as resp:
                return resp.status == 200
        except Exception as e:
            logger.error(f"Floodlight unreachable: {e}")
            return False

    # Envoi des données spécifiques de détection à sFlow-RT 
    async def _configure_attack_detection(self, signature: AttackSignature):
        """Configure la détection pour un type d'attaque"""
        flows = {"keys": signature.keys, "value": signature.value_type}
        threshold = {"metric": signature.metric_name, "value": signature.threshold}

        # Filtre pour ICMP TYPE 8 (echo request)
        if signature.ip_proto == 1 and signature.icmpv4_type_block:
            flows['filter'] = f'icmptype={signature.icmpv4_type_block}'
        
        # Filtre pour SIP
        elif signature.udp_dst:
            flows['filter'] = f'udpdestinationport={signature.udp_dst}'

        try:
            logger.info(f"Configuring {signature.name}")
            # Envoi des flows (règles de détection)
            async with self.session.put(
                f"{self.config.SFLOW_RT_URL}/flow/{signature.metric_name}/json",
                json=flows,
            ) as resp:
                logger.info(f"{signature.name} flow configured: {resp.status}")

            # Envoi des seuils de détection correspondant aux flows
            async with self.session.put(
                f"{self.config.SFLOW_RT_URL}/threshold/{signature.metric_name}/json",
                json=threshold,
            ) as resp:
                logger.info(f"{signature.name} threshold configured: {resp.status}")

        except Exception as e:
            logger.error(f"Error configuring {signature.name}: {e}")

    # Suppression des règles de blocage expirées (selon Config.BLOCK_TIME)
    async def cleanup_expired_blocks(self):
        """Nettoie périodiquement les règles expirées"""
        while True:
            try:
                blacklist_size_before = len(self.blacklist)
                logger.debug(f"🧹 Cleanup check... (blacklist: {blacklist_size_before} entries)")

                # Récupération de toutes les règles arrivées à expiration (délai défini dans la classe Config)                
                expired = self.blacklist.get_expired()

                if expired:
                    logger.info(f"♻️ Cleaning {len(expired)} expired rule(s)")

                # Parcours de toutes les règles expirées de la blacklist
                for flow_name, switch_id, match, src_ip, dst_ip in expired:
                    delete_data = {"dpid": int(switch_id), "match": match}

                    # Ordre de suppression de la règle envoyé au contrôleur
                    async with self.session.post(
                        f"{self.config.RYU_URL}/stats/flowentry/delete",
                        json=delete_data,
                        headers={"Content-Type": "application/json"},
                    ) as resp:
                        result = await resp.text()
                        
                        if resp.status == 200:
                            logger.info(f"✅ Unblocked {flow_name} ({src_ip}→{dst_ip})")
                        else:
                            logger.error(f"❌ Failed: {resp.status} - {result}")

            except Exception as e:
                logger.error(f"Cleanup error: {e}", exc_info=True)

            await asyncio.sleep(self.config.CLEANUP_INTERVAL)

    # Vérification des évènements déclenchés par sFlow-RT (selon les seuils précédemment définis)
    async def poll_events(self):
        """Polling des événements sFlow-RT"""
        last_check = time.time()
        
        while True:
            try:
                event_url = f'{self.config.SFLOW_RT_URL}/events/json?maxEvents=10&timeout=60&eventID={self.event_id}'
                
                # Récupération des évènements déclenchés par sFlow-RT via l'URL ci-dessus
                async with self.session.get(event_url) as resp:
                    events = await resp.json()
                
                if events:
                    self.event_id = events[0]["eventID"]
                    events.reverse()
                    
                    logger.info(f"📬 Received {len(events)} event(s)")
                    for event in events:
                        logger.warning(f"🔔 Event: {event.get('metric')}")
                        # Gestion usuelle des évènements (cas général)
                        await self._process_event(event)
                
                # ← POLLING ACTIF : vérifier les métriques régulièrement, ce qui permet de bloquer une attaque déjà en cours (cas spécifique)
                # même sans events
                now = time.time()
                if now - last_check > 10:  # Toutes les 10 secondes
                    await self._check_active_attacks()
                    last_check = now
            
            except asyncio.TimeoutError:
                logger.debug("Event polling timeout (normal)")
            except Exception as e:
                logger.error(f"Event polling error: {e}")
            
            await asyncio.sleep(self.config.POLL_INTERVAL)

    # Vérification des évènements sFlow-RT pour éventuellement déclencher une mitigation
    async def _check_active_attacks(self):
        """Vérification active des attaques actives"""
        logger.debug("🔍 Attacks active check...")
        
        for signature in self.attack_signatures.values():
            try:
                # Récupérer les métriques actuelles
                async with self.session.get(
                    f'{self.config.SFLOW_RT_URL}/metric/ALL/{signature.metric_name}/json'
                ) as resp:
                    metrics = await resp.json()
                
                for metric in metrics:
                    if metric.get('metricValue', 0) > signature.threshold:
                        logger.warning(
                            f"⚠️ Active attack detected: {signature.name} "
                            f"({metric.get('metricValue')} > {signature.threshold})"
                        )
                        
                        # Traiter comme un event
                        if metric.get('topKeys'):
                            for top_key in metric['topKeys']:
                                if top_key['value'] > signature.threshold:
                                    await self._block_source(top_key['key'], signature)
                                    break
            
            except Exception as e:
                logger.debug(f"Check error for {signature.name}: {e}")

    async def _process_event(self, event: dict):
        """Traite un événement de détection"""
        metric_name = event.get("metric")

        # Trouver la signature correspondante parmi celles définies dans self.attack_signatures
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
            ): # Seuil dépassé
                for top_key in metric["topKeys"]:
                    if top_key.get("value") and top_key.get("key"):
                        if top_key["value"] > signature.threshold:
                            await self._block_source(top_key["key"], signature)
                            break  # Bloquer seulement le premier

        except Exception as e:
            logger.error(f"Error processing event: {e}")

    # Vérification que l'IP que l'on s'apprête à bloquer n'est pas celle d'un élément important du réseau
    def _is_protected_ip(self, ip: str) -> bool:

        if ip in self.config.CONTROLLER_IP:
            return True

        if ip in self.config.TARGETED_SWITCH_IP:
            return True

        return False

    def build_rules(self, signature: AttackSignature, src_ip: str, dst_ip: str):
        """Construit les règles de blocage block et d'autorisation allow"""

        # Règle de blocage
        block_rule = {
            "dpid": self.config.TARGETED_SWITCH,
            "priority": self.config.FW_PRIORITY,
            "match": {
                "eth_type": 0x0800,
                "ip_proto": signature.ip_proto,
            },
            "actions": [], # Interdiction (DROP) du trafic
        }

        # Règle d'autorisation
        allow_rule = {
            "dpid": self.config.TARGETED_SWITCH,
            "priority": int(self.config.FW_PRIORITY) + 1,
            "match": {
                "ip_proto": signature.ip_proto,
                "eth_type": 0x0800,
            },
            "actions": [
                {
                    "type": "OUTPUT", # Autorisation du trafic
                    "port": "NORMAL",  # Ou port number
                }
            ],
        }

        # Ajouter les champs optionnels s'ils existent
        if signature.ip_proto == 1: # Blocage ICMP
            if signature.icmpv4_type_block:
                block_rule["match"]["icmpv4_type"] = signature.icmpv4_type_block
                block_rule["match"]["ipv4_src"] = src_ip
                block_rule["match"]["ipv4_dst"] = dst_ip
                allow_rule["match"]["ipv4_src"] = src_ip
                allow_rule["match"]["ipv4_dst"] = dst_ip
            if signature.icmpv4_type_allow:
                allow_rule["match"]["icmpv4_type"] = signature.icmpv4_type_allow
        elif signature.ip_proto == 17 and signature.udp_dst: # Blocage SIP (17 = UDP)
            block_rule["match"]["udp_dst"] = signature.udp_dst
            allow_rule["match"]["udp_src"] = signature.udp_dst
            block_rule["match"]["ipv4_src"] = src_ip
            block_rule["match"]["ipv4_dst"] = dst_ip
            allow_rule["match"]["ipv4_src"] = dst_ip
            allow_rule["match"]["ipv4_dst"] = src_ip
        else: # Cas générique si d'autre signatures sont ajoutés à la détection
            allow_rule = None
            block_rule["match"]["ipv4_src"] = src_ip
            block_rule["match"]["ipv4_dst"] = dst_ip

        return block_rule, allow_rule

    async def add_default_forwarding_rule(self):
        """Règles par défaut pour le forwarding normal"""

        # Règle 1 : Forwarding L2 normal (apprend les MAC)
        l2_forward = {
            "dpid": self.config.TARGETED_SWITCH,
            "priority": "10",  # Entre 1 (CONTROLLER) et 1000 (tes règles)
            "match": {},
            "actions": [
                {"type": "OUTPUT", "port": "NORMAL"}
            ],  # Learning switch behavior
        }

        # Règle 2 : Autoriser explicitement ARP
        arp_allow = {
            "dpid": self.config.TARGETED_SWITCH,
            "priority": "100",
            "match": {
                "eth_type": 0x0806,  # ARP
            },
            "actions": [{"type": "OUTPUT", "port": "NORMAL"}],
        }

        # Règle 3 : Autoriser le trafic sFlow (UDP 6343)
        sflow_allow = {
            "dpid": self.config.TARGETED_SWITCH,
            "priority": "100",
            "match": {
                "eth_type": 0x0800,
                "ip_proto": 17,  # UDP
                "udp_dst": 6343,  # Port sFlow
            },
            "actions": [{"type": "OUTPUT", "port": "NORMAL"}],
        }

        # Règle 4 : Autoriser le trafic de contrôle OpenFlow
        openflow_allow = {
            "dpid": self.config.TARGETED_SWITCH,
            "priority": "200",
            "match": {
                "eth_type": 0x0800,
                "ip_proto": 6,  # TCP
                "tcp_dst": 6653,  # Port OpenFlow
            },
            "actions": [{"type": "OUTPUT", "port": "NORMAL"}],
        }

        # Envoi de toutes les règles
        for rule in [l2_forward, arp_allow, sflow_allow, openflow_allow]:
            try:
                async with self.session.post(
                    f"{self.config.RYU_URL}/stats/flowentry/add",
                    json=rule,
                    headers={"Content-Type": "application/json"},
                ) as resp:
                    result = await resp.text()
                    logger.info(
                        f"✅ Infrastructure rule (Priority {rule['priority']}): "
                        f"{result}"
                    )
            except Exception as e:
                logger.error(f"Error installing (Priority {rule['priority']}): {e}")

    async def _block_source(self, key: str, signature: AttackSignature):
        """Bloque une source malveillante"""
        parts = key.split(",")

        keys_list = signature.keys.split(',')
        key_values = {}
        for i, key_name in enumerate(keys_list):
            if i < len(parts):
                key_values[key_name] = parts[i]

        src_ip = key_values.get('ipsource')
        dst_ip = key_values.get('ipdestination')

        # Vérification qu'on ne tente pas de bloquer le contrôleur ou le switch
        if self._is_protected_ip(src_ip):
            logger.warning(f"Skipping protected IP: {src_ip}")
            return
        
        # Vérification d'un éventuel blocage déjà actif (peu importe le sens)
        if self.blacklist.is_blocked(src_ip, dst_ip, signature.metric_name):
            logger.info(f"✋ {src_ip} ↔ {dst_ip} already blocked for {signature.name}")
            return

        # Construction des règles
        block_rule, allow_rule = self.build_rules(signature, src_ip, dst_ip)

        # Ajout à la liste des évènements passés pour vérification de la blacklist plus tard
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
            # Envoi de la règle de blocage
            async with self.session.post(
                f"{self.config.RYU_URL}/stats/flowentry/add",
                data=json.dumps(block_rule),
            ) as resp:
                await resp.text()
                logger.warning(
                    f"🚨 BLOCKED {src_ip} -> {dst_ip} ({signature.name}): {resp.status}"
                )

            # Ajouter la règle à la blacklist
            self.blacklist.add(
                flow_name=f"{signature.metric_name}_block_{src_ip}_{dst_ip}",
                switch_id=str(self.config.TARGETED_SWITCH),
                block_duration=self.config.BLOCK_TIME,
                match=block_rule["match"],
                src_ip=src_ip,
                dst_ip=dst_ip,
                metric_name=signature.metric_name
            )

            if allow_rule:
                # Envoi de la règle d'autorisation
                async with self.session.post(
                    f"{self.config.RYU_URL}/stats/flowentry/add",
                    data=json.dumps(allow_rule),
                ) as resp:
                    await resp.text()
                    src = allow_rule['match']['ipv4_src']
                    dst = allow_rule['match']['ipv4_dst']
                    if signature.name == "ICMP Flood":
                        allow_rule['match']['ipv4_dst'] 
                        allow_rule['match']['ipv4_src']
                        
                    logger.info(
                        f"✅ ALLOWED {src} -> {dst} ({signature.name}): {resp.status}"
                    )

                # Ajouter la règle à la blacklist
                self.blacklist.add(
                    flow_name=f"{signature.metric_name}_allow_{dst_ip}_{src_ip}",
                    switch_id=str(self.config.TARGETED_SWITCH),
                    block_duration=self.config.BLOCK_TIME,
                    match=allow_rule["match"],
                    src_ip=dst_ip,
                    dst_ip=src_ip,
                    metric_name=signature.metric_name
                )

        except Exception as e:
            logger.error(f"Error blocking {src_ip}: {e}")

    async def run(self):
        """Lance le détecteur avec toutes ses tâches"""
        
        # Vérification de l'état du contrôleur et de sFlow + configuration initiale de sFlow
        initialized = await self.initialize_detection()

        if not initialized:
            logger.error("Engine not started: infrastructure not ready")
            return False

        logger.info("Engine started")

        # Lancer les tâches de gestion des évènements sFlow et de nettoyage de la blacklist en parallèle
        await asyncio.gather(
            self.poll_events(), self.cleanup_expired_blocks(), return_exceptions=True
        )
