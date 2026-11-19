"""
Обход DPI для подключений к Cloudflare (CF-прокси и CF-worker).

ТСПУ обычно разбирает только первый TLS-рекорд / первый TCP-сегмент и ищет
в нём имя сервера (SNI) или заголовок Host. Поэтому:

  * TLS: первый рекорд (ClientHello) режется на два рекорда посередине имени
    сервера и уходит двумя отдельными сегментами. Для сервера это штатная
    фрагментация TLS (RFC 8446, 5.1), Cloudflare её принимает;
  * порт 80: HTTP-запрос уходит двумя сегментами с разрезом внутри Host.

Прямые подключения к Telegram это не затрагивает.
"""
import asyncio
import ssl
from typing import List, Optional, Tuple


def split_tls_record(buf: bytes, sni: bytes) -> Optional[List[bytes]]:
    """Делит первый TLS handshake-рекорд на два. None, если рекорда нет."""
    if len(buf) < 6 or buf[0] != 0x16 or buf[1] != 0x03:
        return None
    length = (buf[3] << 8) | buf[4]
    if length < 2 or len(buf) < 5 + length:
        return None
    payload = buf[5:5 + length]
    pos = payload.find(sni) if sni else -1
    cut = pos + 1 + len(sni) // 2 if pos >= 0 else 1
    cut = max(1, min(cut, length - 1))

    def record(part: bytes) -> bytes:
        return bytes((buf[0], buf[1], buf[2], len(part) >> 8, len(part) & 0xFF)) + part

    parts = [record(payload[:cut]), record(payload[cut:])]
    if len(buf) > 5 + length:
        parts.append(bytes(buf[5 + length:]))
    return parts


def split_http_request(req: bytes) -> int:
    """Точка разреза HTTP-запроса внутри значения Host (0 — не резать)."""
    needle = b'\r\nHost: '
    pos = req.find(needle)
    if pos < 0:
        return 0
    cut = pos + len(needle) + 2
    return cut if cut < len(req) else 0


class _SplitFirstWrite(asyncio.Transport):
    """
    Обёртка над TCP-транспортом для loop.start_tls: первую запись
    (ClientHello) режет на рекорды и отправляет отдельными write().
    Остальное делегирует настоящему транспорту.
    """

    _start_tls_compatible = True

    def __init__(self, inner: asyncio.Transport, sni: str):
        super().__init__()
        self._inner = inner
        self._sni: Optional[bytes] = sni.encode('idna') if sni else b''
        self._armed = True

    def write(self, data) -> None:
        if self._armed:
            self._armed = False
            parts = split_tls_record(bytes(data), self._sni)
            if parts:
                for part in parts:
                    self._inner.write(part)
                return
        self._inner.write(data)

    def writelines(self, list_of_data) -> None:
        for data in list_of_data:
            self.write(data)

    # --- делегирование ---
    def get_extra_info(self, name, default=None):
        return self._inner.get_extra_info(name, default)

    def is_closing(self) -> bool:
        return self._inner.is_closing()

    def close(self) -> None:
        self._inner.close()

    def abort(self) -> None:
        self._inner.abort()

    def set_protocol(self, protocol) -> None:
        self._inner.set_protocol(protocol)

    def get_protocol(self):
        return self._inner.get_protocol()

    def is_reading(self) -> bool:
        return self._inner.is_reading()

    def pause_reading(self) -> None:
        self._inner.pause_reading()

    def resume_reading(self) -> None:
        self._inner.resume_reading()

    def set_write_buffer_limits(self, high=None, low=None) -> None:
        self._inner.set_write_buffer_limits(high, low)

    def get_write_buffer_size(self) -> int:
        return self._inner.get_write_buffer_size()

    def get_write_buffer_limits(self):
        return self._inner.get_write_buffer_limits()

    def can_write_eof(self) -> bool:
        return self._inner.can_write_eof()

    def write_eof(self) -> None:
        self._inner.write_eof()

    def __getattr__(self, name):
        return getattr(self._inner, name)


async def open_tls_split(host: str, port: int, ssl_context: ssl.SSLContext,
                         server_hostname: str, sock_opts=None
                         ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """
    Как asyncio.open_connection(ssl=...), но ClientHello уходит разрезанным.
    sock_opts(transport) вызывается до рукопожатия (нужен TCP_NODELAY).
    """
    loop = asyncio.get_running_loop()
    reader, writer = await asyncio.open_connection(host, port)
    raw = writer.transport
    if sock_opts is not None:
        sock_opts(raw)
    protocol = raw.get_protocol()
    try:
        tls_transport = await loop.start_tls(
            _SplitFirstWrite(raw, server_hostname), protocol, ssl_context,
            server_hostname=server_hostname)
    except BaseException:
        raw.close()
        raise
    # Как StreamWriter.start_tls: подменяем транспорт в том же writer.
    # Новый StreamWriter создавать нельзя: в 3.11+ старый при сборке мусора
    # закрыл бы сырое TCP-соединение под TLS (StreamWriter.__del__).
    writer._transport = tls_transport
    if hasattr(protocol, '_replace_transport'):      # 3.12+
        protocol._replace_transport(tls_transport)
    elif hasattr(protocol, '_replace_writer'):       # 3.11
        protocol._replace_writer(writer)
    else:                                            # 3.8-3.10
        protocol._over_ssl = True
    return reader, writer


async def write_split_http(writer: asyncio.StreamWriter, req: bytes) -> None:
    """Отправляет HTTP-запрос двумя сегментами с разрезом внутри Host."""
    cut = split_http_request(req)
    if not cut:
        writer.write(req)
        await writer.drain()
        return
    writer.write(req[:cut])
    await writer.drain()
    await asyncio.sleep(0.005)
    writer.write(req[cut:])
    await writer.drain()
