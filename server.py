import os
import re
import ssl
import time
import asyncio
import base64
import threading
from typing import AsyncGenerator

import fastapi
import uvicorn
from fastapi import HTTPException, status

from lib.security.cryption import generate_keypair, decrypt
from lib.security.signing import verify, build_registration_message
from lib.network.proxy import get_proxied_session, ProxyUnavailableError

_SAFE_HOST_RE = re.compile(r'^[a-zA-Z0-9.\-]{1,253}$')

fastapp = fastapi.FastAPI()
STOP_EVENT = threading.Event()

file_peers: dict = {}

_TIMESTAMP_TOLERANCE_S = 30


def _redact(message: str) -> str:
    import re
    return re.sub(r'(private_key|password|token|secret)=[^\s,}]+', r'\1=<redacted>', message, flags=re.IGNORECASE)


@fastapp.post('/fileshare/{file_id}')
async def register_fileshare(request: fastapi.Request, file_id: str):
    try:
        if not file_id.isalnum():
            raise HTTPException(status_code=400, detail="Invalid file ID")

        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")

        port = body.get('port')
        file_name = body.get('filename')
        file_size = body.get('size')
        peer_public_key_b64 = body.get('peer_public_key')
        signature_b64 = body.get('signature')
        timestamp = body.get('timestamp')
        client_host = body.get('host', '').strip()

        if not all([port, file_name, file_size, peer_public_key_b64, signature_b64, timestamp]):
            raise HTTPException(status_code=400, detail="Missing required fields")

        try:
            port = int(port)
            file_size = int(file_size)
            timestamp = int(timestamp)
            if not 1 <= port <= 65535:
                raise ValueError("port out of range")
        except (ValueError, TypeError):
            raise HTTPException(status_code=400, detail="Invalid port, size, or timestamp")

        if client_host and not _SAFE_HOST_RE.match(client_host):
            raise HTTPException(status_code=400, detail="Invalid host value")

        if abs(time.time() - timestamp) > _TIMESTAMP_TOLERANCE_S:
            raise HTTPException(status_code=400, detail="Request timestamp out of acceptable range")

        try:
            peer_public_key = base64.b64decode(peer_public_key_b64)
            signature = base64.b64decode(signature_b64)
        except Exception:
            raise HTTPException(status_code=400, detail="Malformed base64 in peer_public_key or signature")

        message = build_registration_message(file_id, client_host, port, file_name, file_size, timestamp)
        if not verify(peer_public_key, message, signature):
            raise HTTPException(status_code=403, detail="Signature verification failed")

        # Prefer client-supplied host; fall back to request source IP
        if client_host:
            peer_ip = client_host
        else:
            peer_ip = request.headers.get('cf-connecting-ip', '') or (request.client.host if request.client else '')
        if not peer_ip:
            raise HTTPException(status_code=400, detail="Failed to resolve peer address")

        download_url = f"http://{peer_ip}:{port}/{file_id}"
        public_key, private_key = generate_keypair()

        file_peers[file_id] = {
            'download_url': download_url,
            'file_name': file_name,
            'size': file_size,
            'private_key': private_key,
            'public_key': public_key,
            'peer_public_key': peer_public_key,
        }

        return fastapi.responses.JSONResponse(
            {'status': 'registered', 'url': download_url, 'encrypting_key': base64.b64encode(public_key).decode()},
            status_code=200,
        )

    except HTTPException:
        raise
    except Exception as exc:
        print(f"Error in register_fileshare: {_redact(str(exc))}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


@fastapp.get('/fileshare/{file_id}')
async def fileshare(file_id: str):
    if not file_id.isalnum():
        return fastapi.responses.JSONResponse({'error': 'Invalid file ID'}, status_code=400)

    peer = file_peers.get(file_id)
    if peer is None:
        return fastapi.responses.JSONResponse({'error': 'File not found', 'file_id': file_id}, status_code=404)

    download_url = peer.get('download_url')
    file_name = peer.get('file_name')
    file_size = peer.get('size')
    decrypting_key = peer.get('private_key')

    if not all([download_url, file_name, file_size, decrypting_key]):
        return fastapi.responses.JSONResponse({'error': 'Shared file is out-of-sync'}, status_code=500)

    try:
        session = get_proxied_session()
    except ProxyUnavailableError as exc:
        print(f"Proxy unavailable: {exc}")
        return fastapi.responses.JSONResponse({'error': 'No proxy available — cannot fulfil request'}, status_code=503)

    try:
        exists_resp = session.get(download_url + "/exists")
        if exists_resp.status_code != 200 or not exists_resp.json().get("exists"):
            return fastapi.responses.JSONResponse({'error': 'File does not exist on peer'}, status_code=404)
    except Exception as exc:
        print(f"Peer reachability check failed: {_redact(str(exc))}")
        return fastapi.responses.JSONResponse({'error': 'Cannot reach peer'}, status_code=502)

    async def generate() -> AsyncGenerator[bytes, None]:
        try:
            with session.get(download_url, stream=True) as resp:
                resp.raise_for_status()
                for chunk in resp.iter_content(None):
                    if not chunk:
                        break
                    if STOP_EVENT.is_set():
                        print(f"Transfer of {file_id} aborted by stop event")
                        break
                    decrypted = decrypt(decrypting_key, chunk)
                    if not decrypted:
                        break
                    yield decrypted
        except Exception as stream_exc:
            print(f"Stream error for {file_id}: {_redact(str(stream_exc))}")

    response = fastapi.responses.StreamingResponse(generate(), media_type='application/octet-stream')
    response.headers['Content-Disposition'] = f'attachment; filename={file_name}'
    response.headers['Content-Length'] = str(file_size)
    return response


@fastapp.exception_handler(Exception)
async def global_exception_handler(request: fastapi.Request, exc: Exception):
    print(f"Unhandled error: {_redact(str(exc))}")
    return fastapi.responses.JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal Server Error"},
    )


def _build_ssl_context() -> ssl.SSLContext | None:
    if not (os.path.exists('./key.pem') and os.path.exists('./cert.pem')):
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile='./cert.pem', keyfile='./key.pem')
    return ctx


def main():
    ssl_ctx = _build_ssl_context()
    port = 443 if ssl_ctx else 8080

    if ssl_ctx:
        async def _serve():
            config = uvicorn.Config(
                fastapp,
                port=port,
                host='0.0.0.0',
                log_level="info",
                ssl_keyfile='./key.pem',
                ssl_certfile='./cert.pem',
            )
            config.load()
            config.ssl = ssl_ctx
            server = uvicorn.Server(config)
            await server.serve()

        asyncio.run(_serve())
    else:
        uvicorn.run(fastapp, port=port, host='0.0.0.0', log_level="info")


if __name__ == '__main__':
    main()
