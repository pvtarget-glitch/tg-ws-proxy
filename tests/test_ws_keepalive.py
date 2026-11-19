import asyncio
import unittest

from proxy.raw_websocket import RawWebSocket


async def _pair():
    got = asyncio.Queue()
    conns = []

    async def handle(r, w):
        conns.append(w)
        try:
            while True:
                b = await r.read(1024)
                if not b:
                    return
                await got.put(b)
        except Exception:
            return

    server = await asyncio.start_server(handle, '127.0.0.1', 0)
    port = server.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    return server, RawWebSocket(reader, writer), got


def _opcodes(chunks):
    return [c[0] & 0x0F for c in chunks]


class KeepaliveTest(unittest.IsolatedAsyncioTestCase):
    async def test_ping_sent_when_idle(self):
        server, ws, got = await _pair()
        ws.start_keepalive(check=0.05, idle=0.2)
        chunk = await asyncio.wait_for(got.get(), 2)
        self.assertEqual(chunk[0] & 0x0F, RawWebSocket.OP_PING)
        await ws.close()
        server.close()

    async def test_no_ping_while_traffic_flows(self):
        server, ws, got = await _pair()
        ws.start_keepalive(check=0.05, idle=0.3)
        for _ in range(8):
            await ws.send(b'x')
            await asyncio.sleep(0.1)
        chunks = []
        while not got.empty():
            chunks.append(got.get_nowait())
        self.assertNotIn(RawWebSocket.OP_PING, _opcodes(chunks))
        await ws.close()
        server.close()

    async def test_close_stops_keepalive(self):
        server, ws, got = await _pair()
        ws.start_keepalive(check=0.05, idle=0.1)
        task = ws._ka_task
        await ws.close()
        await asyncio.sleep(0.05)
        self.assertTrue(task.done())
        server.close()


if __name__ == '__main__':
    unittest.main()
