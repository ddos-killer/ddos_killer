import asyncio
from typing import Optional
from .DDosDetector import DDosDetector
from .config import Config
from .Logger import logger

class EngineController:
    def __init__(self):
        self.config = Config()
        self.detector = DDosDetector(self.config)
        self.task: Optional[asyncio.Task] = None

    async def start(self):
        if self.task and not self.task.done():
            return False

        async def runner():
            async with self.detector:
                await self.detector.run()

        self.task = asyncio.create_task(runner())
        logger.info("DDoS detector started")
        return True

    async def stop(self):
        if self.task:
            self.task.cancel()
            logger.info("DDoS detector stopped")
            return True
        return False

    def status(self):
        return {
            "running": self.task is not None and not self.task.done(),
            "blacklist_size": len(self.detector.blacklist),
        }
