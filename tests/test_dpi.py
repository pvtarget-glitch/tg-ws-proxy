import asyncio
import datetime
import os
import ssl
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from proxy import dpi


SNI = 'kws2.mytgproxy.example'


def _self_signed(tmp: str):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, SNI)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(SNI)]), False)
            .sign(key, hashes.SHA256()))
    cert_path = os.path.join(tmp, 'c.pem')
    key_path = os.path.join(tmp, 'k.pem')
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, 'wb') as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return cert_path, key_path


def _client_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _records(data: bytes):
    out, i = [], 0
    while i + 5 <= len(data):
        ln = (data[i + 3] << 8) | data[i + 4]
        if i + 5 + ln > len(data):
            break
        out.append((data[i], data[i + 5:i + 5 + ln]))
        i += 5 + ln
    return out


class SplitHelpersTest(unittest.TestCase):
    def test_tls_record_split(self):
        sni = SNI.encode()
        payload = b'\x01\x00\x00\x40' + b'\xaa' * 20 + sni + b'\xbb' * 30
        rec = b'\x16\x03\x01' + len(payload).to_bytes(2, 'big') + payload + b'TAIL'
        parts = dpi.split_tls_record(rec, sni)
        self.assertEqual(len(parts), 3)
        joined = b''
        for p in parts[:2]:
            self.assertEqual(p[:3], b'\x16\x03\x01')
            self.assertEqual(int.from_bytes(p[3:5], 'big'), len(p) - 5)
            self.assertNotIn(sni, p)
            joined += p[5:]
        self.assertEqual(joined, payload)
        self.assertEqual(parts[2], b'TAIL')
        self.assertIsNone(dpi.split_tls_record(b'GET / HTTP/1.1\r\n', sni))

    def test_http_split_inside_host(self):
        req = b'GET /apiws HTTP/1.1\r\nHost: kws2.example.co.uk\r\n\r\n'
        cut = dpi.split_http_request(req)
        self.assertTrue(req[:cut].endswith(b'Host: kw'))
        self.assertEqual(dpi.split_http_request(b'no host here'), 0)


class SplitOnTheWireTest(unittest.IsolatedAsyncioTestCase):
    async def test_real_tls_server_accepts_split_client_hello(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert, key = _self_signed(tmp)
            sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            sctx.load_cert_chain(cert, key)
            seen_sni = []
            sctx.sni_callback = lambda sock, name, ctx: seen_sni.append(name)

            async def handle(r, w):
                line = await r.readline()
                w.write(b'echo:' + line)
                await w.drain()
                w.close()

            server = await asyncio.start_server(handle, '127.0.0.1', 0, ssl=sctx)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.wait_for(
                dpi.open_tls_split('127.0.0.1', port, _client_ctx(), SNI), 5)
            writer.write(b'hello\n')
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readline(), 5), b'echo:hello\n')
            self.assertEqual(seen_sni, [SNI])
            writer.close()
            server.close()

    async def test_client_hello_is_split_into_two_records(self):
        got = bytearray()
        done = asyncio.Event()

        async def sniff(r, w):
            try:
                while True:
                    chunk = await asyncio.wait_for(r.read(8192), 0.5)
                    if not chunk:
                        break
                    got.extend(chunk)
            except asyncio.TimeoutError:
                pass
            done.set()
            w.close()

        server = await asyncio.start_server(sniff, '127.0.0.1', 0)
        port = server.sockets[0].getsockname()[1]
        task = asyncio.ensure_future(dpi.open_tls_split('127.0.0.1', port, _client_ctx(), SNI))
        await asyncio.wait_for(done.wait(), 5)
        task.cancel()
        try:
            await task
        except BaseException:
            pass
        recs = _records(bytes(got))
        self.assertGreaterEqual(len(recs), 2)
        self.assertEqual((recs[0][0], recs[1][0]), (0x16, 0x16))
        for _, payload in recs:
            self.assertNotIn(SNI.encode(), payload)
        self.assertIn(SNI.encode(), recs[0][1] + recs[1][1])
        server.close()

    async def test_split_http_request_arrives_intact(self):
        got = bytearray()

        async def handle(r, w):
            got.extend(await r.readuntil(b'\r\n\r\n'))
            w.close()

        server = await asyncio.start_server(handle, '127.0.0.1', 0)
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection('127.0.0.1', port)
        req = b'GET /apiws HTTP/1.1\r\nHost: kws2.example.co.uk\r\nUpgrade: websocket\r\n\r\n'
        await dpi.write_split_http(writer, req)
        await asyncio.sleep(0.1)
        self.assertEqual(bytes(got), req)
        writer.close()
        server.close()


if __name__ == '__main__':
    unittest.main()
