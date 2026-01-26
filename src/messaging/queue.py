"""
Message Queue Abstraction
In-memory queue using asyncio for MVP (can be replaced with RabbitMQ later)
"""

import asyncio
from typing import AsyncGenerator, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime
from uuid import uuid4
import structlog

from src.config.settings import Settings

logger = structlog.get_logger()


@dataclass
class Message:
    """Message container for queue"""
    id: str
    queue_name: str
    body: Dict[str, Any]
    priority: int
    timestamp: datetime
    retry_count: int = 0


class MessageQueue:
    """
    Async message queue for inter-agent communication.
    Uses asyncio.Queue for MVP implementation.
    """

    def __init__(self, config: Settings):
        """
        Initialize message queue.

        Args:
            config: Application settings
        """
        self.config = config
        self.queues: Dict[str, asyncio.PriorityQueue] = {}
        self._running = False
        self._message_count = 0

    @classmethod
    async def connect(cls, config: Settings) -> "MessageQueue":
        """
        Create and connect message queue.

        Args:
            config: Application settings

        Returns:
            MessageQueue instance
        """
        queue = cls(config)
        queue._running = True
        logger.info("Message queue initialized", mode="in-memory")
        return queue

    async def publish(
        self,
        queue: str,
        message: Dict[str, Any],
        priority: int = 5
    ) -> str:
        """
        Publish message to queue.

        Args:
            queue: Queue name
            message: Message body (dict)
            priority: Message priority (0-9, higher = more important)

        Returns:
            Message ID
        """
        # Create queue if it doesn't exist
        if queue not in self.queues:
            self.queues[queue] = asyncio.PriorityQueue()
            logger.debug(f"Created queue: {queue}")

        # Create message
        msg = Message(
            id=str(uuid4()),
            queue_name=queue,
            body=message,
            priority=priority,
            timestamp=datetime.utcnow()
        )

        # Priority queue uses (priority, item) tuples
        # Lower priority number = higher priority (inverted for convenience)
        await self.queues[queue].put((10 - priority, msg))

        self._message_count += 1

        logger.debug(
            "Message published",
            queue=queue,
            message_id=msg.id,
            priority=priority
        )

        return msg.id

    async def consume(
        self,
        queue: str,
        timeout: Optional[float] = None
    ) -> AsyncGenerator[Message, None]:
        """
        Consume messages from queue (async generator).

        Args:
            queue: Queue name
            timeout: Optional timeout for getting messages

        Yields:
            Message instances
        """
        # Create queue if it doesn't exist
        if queue not in self.queues:
            self.queues[queue] = asyncio.PriorityQueue()
            logger.debug(f"Created queue: {queue}")

        logger.info(f"Consumer started for queue: {queue}")

        while self._running:
            try:
                if timeout:
                    # Get with timeout
                    priority, msg = await asyncio.wait_for(
                        self.queues[queue].get(),
                        timeout=timeout
                    )
                else:
                    # Get without timeout
                    priority, msg = await self.queues[queue].get()

                logger.debug(
                    "Message consumed",
                    queue=queue,
                    message_id=msg.id,
                    priority=msg.priority
                )

                yield msg

            except asyncio.TimeoutError:
                # Timeout reached, continue loop
                continue

            except Exception as e:
                logger.error("Error consuming message", queue=queue, error=str(e))
                await asyncio.sleep(1)  # Back off on error

    async def ack(self, message: Message) -> None:
        """
        Acknowledge message processing (mark as done).

        Args:
            message: Message to acknowledge
        """
        # For asyncio.Queue, we call task_done()
        if message.queue_name in self.queues:
            self.queues[message.queue_name].task_done()

        logger.debug("Message acknowledged", message_id=message.id)

    async def nack(self, message: Message, requeue: bool = True) -> None:
        """
        Negative acknowledge (message processing failed).

        Args:
            message: Message that failed
            requeue: Whether to requeue the message
        """
        if requeue and message.retry_count < self.config.max_retries:
            # Increment retry count and requeue
            message.retry_count += 1
            await self.publish(
                message.queue_name,
                message.body,
                priority=message.priority
            )
            logger.warning(
                "Message requeued",
                message_id=message.id,
                retry_count=message.retry_count
            )
        else:
            # Max retries reached or no requeue
            logger.error(
                "Message dropped after max retries",
                message_id=message.id,
                retry_count=message.retry_count
            )

        # Mark as done
        await self.ack(message)

    async def disconnect(self) -> None:
        """Disconnect and cleanup"""
        self._running = False

        # Clear all queues
        for queue_name, queue in self.queues.items():
            while not queue.empty():
                try:
                    queue.get_nowait()
                    queue.task_done()
                except asyncio.QueueEmpty:
                    break

        logger.info("Message queue disconnected")

    def get_queue_size(self, queue: str) -> int:
        """Get current size of a queue"""
        if queue in self.queues:
            return self.queues[queue].qsize()
        return 0

    def get_stats(self) -> Dict[str, Any]:
        """Get queue statistics"""
        queue_sizes = {
            name: queue.qsize()
            for name, queue in self.queues.items()
        }

        return {
            'running': self._running,
            'total_messages': self._message_count,
            'queues': list(self.queues.keys()),
            'queue_sizes': queue_sizes
        }
