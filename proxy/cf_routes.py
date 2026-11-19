"""
Выбор рабочего маршрута до Cloudflare (CF-прокси и CF-worker).

Раньше домены перебирались строго по очереди с таймаутом 10 секунд на каждый,
а переход на 80 порт включался только вручную (--no-secure). Когда TLS до всех
доменов из списка режется по SNI, клиент ждал десятки секунд на каждое
соединение и выглядел как "бесконечное подключение".

Здесь:
  * кандидаты запускаются "лесенкой" (как Happy Eyeballs): следующий стартует
    сразу после отказа предыдущего либо через STAGGER секунд, если тот молчит;
  * отказавшие маршруты (домен + режим TLS/без TLS) уходят в cooldown и не
    тормозят следующие соединения;
  * если TLS не отвечает, автоматически пробуется 80 порт (если это не
    запрещено настройкой), а выбранный режим запоминается;
  * пока работаем без TLS, TLS изредка перепроверяется в фоне, чтобы вернуться
    на него, когда он снова доступен.
"""
import asyncio
import logging
import time

from collections import deque
from typing import Deque, Dict, List, NamedTuple, Optional, Sequence, Set, Tuple

from .config import proxy_config
from .raw_websocket import RawWebSocket, WsHandshakeError

log = logging.getLogger('tg-mtproto-proxy')

STAGGER = 1.0
MAX_PARALLEL = 4
ATTEMPT_TIMEOUT = 8.0
BUDGET = 15.0
PLAIN_DELAY = 3.0
COOLDOWN_INITIAL = 30.0
COOLDOWN_MAX = 300.0
TLS_PROBE_INTERVAL = 60.0

GROUP_CF = 'cf'
GROUP_WORKER = 'worker'


class Target(NamedTuple):
    key: str   # ключ для учёта отказов (базовый домен / домен воркера)
    host: str  # куда реально подключаемся


Candidate = Tuple[Target, bool]


def allowed_modes() -> Tuple[bool, ...]:
    """Разрешённые режимы подключения: True - TLS (443), False - без TLS (80)."""
    if proxy_config.disable_secure:
        return (False,)
    if proxy_config.cf_plain_fallback:
        return (True, False)
    return (True,)


class _RouteHealth:
    def __init__(self):
        self._failures: Dict[Tuple[str, bool], int] = {}
        self._retry_after: Dict[Tuple[str, bool], float] = {}
        self._prefer_plain: Dict[str, bool] = {}
        self._next_tls_probe: Dict[str, float] = {}
        self._probes: Set[asyncio.Task] = set()

    def reset(self) -> None:
        for task in list(self._probes):
            try:
                if not task.done():
                    task.cancel()
            except RuntimeError:
                pass
        self._probes.clear()
        self._failures.clear()
        self._retry_after.clear()
        self._prefer_plain.clear()
        self._next_tls_probe.clear()

    def usable(self, key: str, secure: bool) -> bool:
        return time.monotonic() >= self._retry_after.get((key, secure), 0)

    def prefer_plain(self, group: str) -> bool:
        return self._prefer_plain.get(group, False)

    def succeeded(self, key: str, secure: bool) -> None:
        self._failures.pop((key, secure), None)
        self._retry_after.pop((key, secure), None)

    def failed(self, key: str, secure: bool, exc: BaseException) -> None:
        routes = [(key, secure)]
        # HTTP-ответ означает, что до Cloudflare мы дошли: дело в самом домене
        # (лимит, 404 и т.п.), и 80 порт вернёт то же самое.
        if secure and isinstance(exc, WsHandshakeError):
            routes.append((key, False))
        now = time.monotonic()
        for route in routes:
            failures = self._failures.get(route, 0) + 1
            self._failures[route] = failures
            delay = min(COOLDOWN_INITIAL * 2 ** min(failures - 1, 6),
                        COOLDOWN_MAX)
            self._retry_after[route] = now + delay

    def note_winner(self, group: str, secure: bool, label: str,
                    tls_tried: bool = True) -> None:
        if secure:
            if self._prefer_plain.pop(group, False):
                log.info("[%s] CF %s: TLS is reachable again, back to port 443",
                         label, group)
            return
        # 80 порт выиграл: переключаемся на него, только если в этой же
        # попытке TLS действительно пробовали и он не ответил
        if not tls_tried or True not in allowed_modes():
            return
        if not self._prefer_plain.get(group, False):
            self._prefer_plain[group] = True
            self._next_tls_probe[group] = time.monotonic() + TLS_PROBE_INTERVAL
            log.warning("[%s] CF %s: TLS (443) is not answering, "
                        "switched to port 80 automatically", label, group)

    def maybe_probe_tls(self, targets: Sequence[Target], path: str,
                        group: str) -> None:
        """Пока работаем через 80 порт, изредка проверяем TLS в фоне."""
        if not self._prefer_plain.get(group, False):
            return
        now = time.monotonic()
        if now < self._next_tls_probe.get(group, 0):
            return
        target = next((t for t in targets if self.usable(t.key, True)), None)
        if target is None:
            return
        self._next_tls_probe[group] = now + TLS_PROBE_INTERVAL
        task = asyncio.ensure_future(self._probe_tls(target, path, group))
        self._probes.add(task)
        task.add_done_callback(self._probes.discard)

    async def _probe_tls(self, target: Target, path: str, group: str) -> None:
        try:
            ws = await _dial(target.host, path, True)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.failed(target.key, True, exc)
            log.debug("CF %s TLS probe via %s failed: %r",
                      group, target.host, exc)
            return
        self.succeeded(target.key, True)
        self.note_winner(group, True, 'probe')
        await _quiet_close(ws)


health = _RouteHealth()


def tls_usable(group: str = GROUP_CF) -> bool:
    return not health.prefer_plain(group)


async def _dial(host: str, path: str, secure: bool) -> RawWebSocket:
    return await asyncio.wait_for(
        RawWebSocket.connect(host, host, timeout=ATTEMPT_TIMEOUT, path=path,
                             secure=secure, dpi=proxy_config.cf_dpi_split),
        timeout=ATTEMPT_TIMEOUT)


async def _quiet_close(ws) -> None:
    try:
        await ws.close()
    except Exception:
        pass


def _build_queues(targets: Sequence[Target]
                  ) -> Tuple[Deque[Candidate], Deque[Candidate]]:
    modes = allowed_modes()
    seen: Set[str] = set()
    unique: List[Target] = []
    for target in targets:
        if target.key not in seen:
            seen.add(target.key)
            unique.append(target)

    def pick(secure: bool, respect_cooldown: bool) -> Deque[Candidate]:
        if secure not in modes:
            return deque()
        return deque((t, secure) for t in unique
                     if not respect_cooldown or health.usable(t.key, secure))

    tls, plain = pick(True, True), pick(False, True)
    if not tls and not plain:
        # Всё в cooldown (например, сеть пропадала целиком) - не простаиваем,
        # а пробуем заново в обычном порядке.
        tls, plain = pick(True, False), pick(False, False)
    return tls, plain


async def connect(targets: Sequence[Target], *, path: str, group: str,
                  label: str, what: str, budget: Optional[float] = None,
                  quiet: bool = False
                  ) -> Optional[Tuple[RawWebSocket, Target, bool]]:
    """
    Возвращает (ws, target, secure) для первого ответившего маршрута
    либо None, если за отведённое время не ответил никто.
    """
    tls_q, plain_q = _build_queues(targets)
    if not tls_q and not plain_q:
        return None
    level = logging.DEBUG if quiet else logging.WARNING

    loop = asyncio.get_running_loop()
    start = loop.time()
    deadline = start + (BUDGET if budget is None else budget)
    plain_first = health.prefer_plain(group) and bool(plain_q)
    plain_at = start if (plain_first or not tls_q) else start + PLAIN_DELAY
    if plain_first:
        health.maybe_probe_tls(targets, path, group)

    running: Dict[asyncio.Task, Candidate] = {}
    winner: Optional[Tuple[RawWebSocket, Target, bool]] = None
    next_start = start
    tls_tried = False

    def tls_active() -> bool:
        return bool(tls_q) or any(secure for _, secure in running.values())

    def pick(now: float) -> Optional[Candidate]:
        if plain_first:
            if plain_q:
                return plain_q.popleft()
            return tls_q.popleft() if tls_q else None
        if plain_q and (now >= plain_at or not tls_active()):
            return plain_q.popleft()
        return tls_q.popleft() if tls_q else None

    try:
        while winner is None:
            now = loop.time()
            if now >= deadline:
                break

            while len(running) < MAX_PARALLEL and now >= next_start:
                candidate = pick(now)
                if candidate is None:
                    break
                target, secure = candidate
                tls_tried = tls_tried or secure
                running[asyncio.ensure_future(
                    _dial(target.host, path, secure))] = candidate
                next_start = now + STAGGER

            queued = bool(tls_q) or bool(plain_q)
            if not running and not queued:
                break

            wake = deadline
            if queued and len(running) < MAX_PARALLEL:
                gate = next_start
                if not tls_q and plain_q and not plain_first:
                    gate = max(gate, plain_at)
                wake = min(wake, gate)
            timeout = max(0.0, wake - now)

            if not running:
                await asyncio.sleep(timeout or 0.01)
                continue

            done, _ = await asyncio.wait(
                list(running), timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                target, secure = running.pop(task)
                if task.cancelled():
                    continue
                exc = task.exception()
                if exc is None:
                    health.succeeded(target.key, secure)
                    if winner is None:
                        winner = (task.result(), target, secure)
                    else:
                        await _quiet_close(task.result())
                    continue
                health.failed(target.key, secure, exc)
                log.log(level, "[%s] %s failed via %s (%s): %r",
                        label, what, target.host,
                        'tls' if secure else 'port 80', exc)
                next_start = loop.time()
    finally:
        leftovers = list(running)
        for task in leftovers:
            task.cancel()
        if leftovers:
            results = await asyncio.gather(*leftovers, return_exceptions=True)
            for result in results:
                if result is not None and not isinstance(result, BaseException):
                    await _quiet_close(result)

    if winner is None:
        log.log(level, "[%s] %s: no route answered in %.0fs",
                label, what, loop.time() - start)
        return None

    health.note_winner(group, winner[2], label, tls_tried)
    return winner
