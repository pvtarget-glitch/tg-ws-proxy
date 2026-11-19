import asyncio
import sys
import time
import unittest

from unittest.mock import AsyncMock, Mock, patch
from types import SimpleNamespace

from proxy import bridge, cf_routes
from proxy.config import proxy_config
from proxy.raw_websocket import WsHandshakeError
from proxy.utils import PROTO_TAG_INTERMEDIATE


# Часы цикла событий на Windows идут шагом ~16 мс, поэтому там интервалы
# в тестах берутся с запасом.
S = 10 if sys.platform == 'win32' else 1

DOMAINS = ['a.example', 'b.example', 'c.example', 'd.example', 'e.example']


def targets(domains=DOMAINS, dc=2):
    return [cf_routes.Target(d, 'kws%d.%s' % (dc, d)) for d in domains]


class FakeWs:
    def __init__(self, host, secure):
        self.host, self.secure, self.closed = host, secure, False

    async def close(self):
        self.closed = True


class Net:
    """Имитация сети: поведение задаётся функцией (host, secure) -> действие."""

    def __init__(self, behaviour):
        self.behaviour = behaviour
        self.calls = []
        self.opened = []
        self.dpi_flags = []

    async def connect(self, host, domain, timeout=10.0, path='/apiws', *,
                      sni=None, secure=True, dpi=False):
        self.dpi_flags.append(dpi)
        self.calls.append((host, secure))
        action = self.behaviour(host, secure)
        if action == 'hang':
            await asyncio.sleep(3600)
        if isinstance(action, float):
            await asyncio.sleep(action)
            action = 'ok'
        if isinstance(action, BaseException):
            raise action
        ws = FakeWs(host, secure)
        self.opened.append(ws)
        return ws


class CfRoutesTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        cf_routes.health.reset()
        fast = dict(STAGGER=0.02 * S, PLAIN_DELAY=0.06 * S, ATTEMPT_TIMEOUT=0.2 * S,
                    BUDGET=0.6 * S, TLS_PROBE_INTERVAL=0.05 * S)
        self._patches = [patch.object(cf_routes, k, v) for k, v in fast.items()]
        self._patches += [patch.object(proxy_config, 'disable_secure', False),
                          patch.object(proxy_config, 'cf_plain_fallback', True)]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        cf_routes.health.reset()

    async def run_connect(self, net, domains=DOMAINS, group=cf_routes.GROUP_CF):
        with patch.object(cf_routes.RawWebSocket, 'connect', net.connect):
            started = time.monotonic()
            result = await cf_routes.connect(
                targets(domains), path='/apiws', group=group,
                label='test', what='DC2 CF proxy')
            return result, time.monotonic() - started

    async def test_healthy_tls_uses_first_domain_only(self):
        net = Net(lambda host, secure: 'ok')
        result, _ = await self.run_connect(net)
        ws, target, secure = result
        self.assertEqual((target.key, secure), ('a.example', True))
        self.assertEqual(net.calls, [('kws2.a.example', True)])
        self.assertTrue(cf_routes.tls_usable())

    async def test_fast_tls_failure_moves_to_next_domain_without_waiting(self):
        net = Net(lambda host, secure: ConnectionResetError()
                  if host == 'kws2.a.example' else 'ok')
        result, elapsed = await self.run_connect(net)
        self.assertEqual((result[1].key, result[2]), ('b.example', True))
        self.assertEqual(net.calls, [('kws2.a.example', True), ('kws2.b.example', True)])
        self.assertLess(elapsed, cf_routes.STAGGER)
        self.assertFalse(cf_routes.health.usable('a.example', True))
        self.assertTrue(cf_routes.health.usable('a.example', False))

    async def test_blocked_tls_falls_back_to_port_80_automatically(self):
        # ровно сценарий 16.11: TLS до всех доменов молчит, 80 порт работает
        net = Net(lambda host, secure: 'hang' if secure else 'ok')
        result, elapsed = await self.run_connect(net)
        self.assertIsNotNone(result)
        self.assertFalse(result[2])
        self.assertLess(elapsed, cf_routes.ATTEMPT_TIMEOUT)
        self.assertFalse(cf_routes.tls_usable())
        # зависшие TLS-попытки отменены, лишних открытых сокетов нет
        self.assertEqual(len(net.opened), 1)

        # следующее соединение сразу идёт на 80 порт, без ожидания TLS
        net2 = Net(lambda host, secure: 'hang' if secure else 'ok')
        result2, elapsed2 = await self.run_connect(net2)
        self.assertFalse(result2[2])
        self.assertEqual(net2.calls[0], ('kws2.a.example', False))
        self.assertLess(elapsed2, cf_routes.STAGGER)

    async def test_all_routes_blocked_gives_up_within_budget(self):
        net = Net(lambda host, secure: 'hang')
        result, elapsed = await self.run_connect(net, ['d%d.example' % i for i in range(20)])
        self.assertIsNone(result)
        self.assertLess(elapsed, cf_routes.BUDGET + 0.2 * S)
        self.assertEqual(net.opened, [])

    async def test_http_error_over_tls_does_not_retry_same_domain_on_port_80(self):
        def behaviour(host, secure):
            if host == 'kws2.a.example':
                return WsHandshakeError(503, 'HTTP/1.1 503 Service Unavailable')
            return 'ok'
        net = Net(behaviour)
        result, _ = await self.run_connect(net, ['a.example', 'b.example'])
        self.assertEqual((result[1].key, result[2]), ('b.example', True))
        self.assertFalse(cf_routes.health.usable('a.example', False))
        self.assertNotIn(('kws2.a.example', False), net.calls)

    async def test_no_secure_uses_only_port_80(self):
        net = Net(lambda host, secure: 'ok')
        with patch.object(proxy_config, 'disable_secure', True):
            result, _ = await self.run_connect(net)
        self.assertFalse(result[2])
        self.assertTrue(all(not secure for _, secure in net.calls))
        # ручной режим не считается "TLS заблокирован"
        self.assertTrue(cf_routes.tls_usable())

    async def test_plain_fallback_can_be_disabled(self):
        net = Net(lambda host, secure: 'hang' if secure else 'ok')
        with patch.object(proxy_config, 'cf_plain_fallback', False):
            result, _ = await self.run_connect(net)
        self.assertIsNone(result)
        self.assertTrue(all(secure for _, secure in net.calls))

    async def test_cooldown_is_ignored_when_every_route_is_cooling_down(self):
        for domain in DOMAINS:
            for secure in (True, False):
                cf_routes.health.failed(domain, secure, TimeoutError())
        net = Net(lambda host, secure: 'ok')
        result, _ = await self.run_connect(net)
        self.assertIsNotNone(result)
        self.assertTrue(result[2])

    async def test_late_extra_connections_are_closed(self):
        # a отвечает медленно, b стартует по лесенке и отвечает в тот же момент
        net = Net(lambda host, secure: (0.05 if host == 'kws2.a.example' else 0.03) * S)
        result, _ = await self.run_connect(net, ['a.example', 'b.example'])
        await asyncio.sleep(0.1 * S)
        self.assertIsNotNone(result)
        extra = [ws for ws in net.opened if ws is not result[0]]
        self.assertTrue(all(ws.closed for ws in extra))
        self.assertFalse(result[0].closed)

    async def test_background_probe_returns_to_tls_when_it_recovers(self):
        blocked = {'on': True}
        net = Net(lambda host, secure: 'hang' if (secure and blocked['on']) else 'ok')
        with patch.object(cf_routes.RawWebSocket, 'connect', net.connect):
            kwargs = dict(path='/apiws', group=cf_routes.GROUP_CF, label='t', what='x')
            first = await cf_routes.connect(targets(), **kwargs)
            self.assertFalse(first[2])
            self.assertFalse(cf_routes.tls_usable())

            blocked['on'] = False
            await asyncio.sleep(cf_routes.TLS_PROBE_INTERVAL + 0.01)
            second = await cf_routes.connect(targets(), **kwargs)
            self.assertFalse(second[2])  # это соединение ещё идёт по 80 порту
            await asyncio.sleep(0.05 * S)  # фоновая проверка TLS успела пройти
            self.assertTrue(cf_routes.tls_usable())

            third = await cf_routes.connect(targets(), **kwargs)
            self.assertTrue(third[2])

    async def test_groups_are_independent(self):
        net = Net(lambda host, secure: 'hang' if secure else 'ok')
        await self.run_connect(net, group=cf_routes.GROUP_WORKER)
        self.assertFalse(cf_routes.tls_usable(cf_routes.GROUP_WORKER))
        self.assertTrue(cf_routes.tls_usable(cf_routes.GROUP_CF))

    async def test_cancel_stops_pending_attempts(self):
        net = Net(lambda host, secure: 'hang')
        with patch.object(cf_routes.RawWebSocket, 'connect', net.connect):
            task = asyncio.create_task(cf_routes.connect(
                targets(), path='/apiws', group=cf_routes.GROUP_CF, label='t', what='x'))
            await asyncio.sleep(0.05 * S)
            before = len(asyncio.all_tasks())
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertLess(len(asyncio.all_tasks()), before)


class FallbackIntegrationTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        cf_routes.health.reset()

    def tearDown(self):
        cf_routes.health.reset()

    async def test_h2_is_skipped_while_tls_is_down(self):
        calls = []

        async def ws_route(*args, **kwargs):
            calls.append('ws')
            return True

        pool = SimpleNamespace(open=AsyncMock(return_value=object()))
        cf_routes.health._prefer_plain[cf_routes.GROUP_CF] = True
        with patch.object(proxy_config, 'fallback_cfproxy', True), \
                patch.object(proxy_config, 'cfproxy_worker_domains', []), \
                patch.object(bridge, '_cfproxy_fallback', side_effect=ws_route):
            ok = await bridge.do_fallback(
                Mock(), Mock(), b'', 'test', 2, False, True, '', Mock(),
                h2_pool=pool, proto_tag=PROTO_TAG_INTERMEDIATE)
        self.assertTrue(ok)
        self.assertEqual(calls, ['ws'])
        pool.open.assert_not_called()


if __name__ == '__main__':
    unittest.main()
