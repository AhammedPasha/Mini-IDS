
import asyncio
import json
import queue
import threading

import websockets


WS_URL = "ws://127.0.0.1:8000/ws/alerts"


def _put_event(events, event):
    """Add an event without allowing the queue to grow indefinitely."""
    try:
        events.put_nowait(event)
    except queue.Full:
        try:
            events.get_nowait()
        except queue.Empty:
            pass

        try:
            events.put_nowait(event)
        except queue.Full:
            pass


async def _listen(events, stop_event):
    """Connect and reconnect to the IDS WebSocket server."""

    while not stop_event.is_set():
        try:
            async with websockets.connect(
                WS_URL,
                ping_interval=20,
                ping_timeout=20,
                open_timeout=5,
            ) as websocket:

                _put_event(events, {
                    "type": "connection_status",
                    "status": "connected",
                })

                while not stop_event.is_set():
                    try:
                        message = await asyncio.wait_for(
                            websocket.recv(),
                            timeout=1,
                        )

                        event = json.loads(message)

                        if event.get("type") == "connection_established":
                            continue

                        _put_event(events, event)

                    except asyncio.TimeoutError:
                        continue

        except Exception as exc:
            _put_event(events, {
                "type": "connection_status",
                "status": "disconnected",
                "error": str(exc),
            })

            await asyncio.sleep(3)


def _listener_worker(events, stop_event):
    asyncio.run(_listen(events, stop_event))


def start_listener():
    """Start a background WebSocket listener."""

    events = queue.Queue(maxsize=500)
    stop_event = threading.Event()

    thread = threading.Thread(
        target=_listener_worker,
        args=(events, stop_event),
        daemon=True,
    )

    thread.start()

    return events, stop_event, thread


def drain_events(events):
    """Retrieve all currently available events."""

    received = []

    while True:
        try:
            received.append(events.get_nowait())
        except queue.Empty:
            break

    return received
