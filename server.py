import os

import fastapi
import requests
from typing import AsyncGenerator
# pip install "uvicorn[standard]"
import uvicorn
import asyncio
import json
import aiohttp

import base64
import threading
from fastapi import HTTPException, status

from lib.security.cryption import generate_keypair, decrypt
fastapp = fastapi.FastAPI()
STOP_EVENT = threading.Event()

# Data structure to hold file_id to set of download URLs
file_peers = dict()


@fastapp.post('/fileshare/{file_id}')
async def register_fileshare(request: fastapi.Request, file_id):
    try:
        # Enhanced input validation
        if not file_id.isalnum():
            raise HTTPException(status_code=400, detail="Invalid file ID")

        # Robust JSON parsing
        try:
            request_body = await request.json()
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON body")

        # Extract and validate necessary information
        peer_ip = request.headers.get('cf-connecting-ip', request.client.host)
        if not peer_ip:
            raise HTTPException(status_code=400, detail="Failed to link peer to server")

        port = request_body.get('port')
        file_name = request_body.get('filename')
        file_size = request_body.get('size')

        if not all([port, file_name, file_size]):
            raise HTTPException(status_code=400, detail="Missing required fields: 'port', 'filename', or 'size'")

        # Construct the download URL
        download_url = f"http://{peer_ip}:{port}/{file_id}"
        public_key, private_key = generate_keypair()

        file_peers[file_id] = {
            'download_url': download_url,
            'file_name': file_name,
            'size': file_size,
            'private_key': private_key,
            'public_key': public_key,
        }

        return fastapi.responses.JSONResponse({'status': 'registered', 'url': download_url, 'encrypting_key': base64.b64encode(public_key).decode('utf-8')}, status_code=200)

    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        # Log the exception for server-side debugging
        print(f"Error in register_fileshare: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


@fastapp.get('/fileshare/{file_id}')
async def fileshare(file_id):
    peer = file_peers.get(file_id, None)

    if peer is None:
        return fastapi.responses.JSONResponse({'error': 'File not found', 'file_id': file_id}, 404)

    download_url = peer.get('download_url', None)
    file_name = peer.get('file_name', None)
    file_size = peer.get('size', None)
    decrypting_key = peer.get('private_key', None)

    if not all([download_url, file_name, file_size, decrypting_key]):
        return fastapi.responses.JSONResponse({'error': 'Shared file is out-of-sync'})

    # Fetch file from the peer and stream it to the client
    try:
        with requests.get(download_url + "/exists") as exists_response:
            if exists_response.status_code != 200:
                raise Exception("Invalid response from peer")
            exists_data = exists_response.json()
            if not exists_data.get("exists"):
                raise Exception("File does not exist on peer")

        async def generate() -> AsyncGenerator[bytes, None]:
            try:
                with requests.get(download_url, stream=True) as resp:
                    resp.raise_for_status()
                    for chunk in resp.iter_content(None):
                        if not chunk:
                            break

                        decrypted_chunk = decrypt(decrypting_key, chunk)

                        if not decrypted_chunk or STOP_EVENT.is_set():
                            print(f"Stopping the file share of {file_id}")
                            break

                        yield decrypted_chunk

            except Exception as e:
                print(f"Error generating payload: {e}")

        response = fastapi.responses.StreamingResponse(generate(), media_type='application/octet-stream')
        response.headers['Content-Disposition'] = f'attachment; filename={file_name}'
        response.headers['Content-Length'] = str(file_size)
        return response

    except asyncio.TimeoutError:
        print(f"Timeout when connecting to peer")
    except Exception as e:
        print(f"Error in fileshare: {e}")
        return fastapi.responses.JSONResponse({'error': 'Shared file is out-of-sync or is no longer being shared'})


@fastapp.exception_handler(Exception)
async def global_exception_handler(request: fastapi.Request, exc: Exception):
    # Log the exception for server-side debugging
    print(f"Unhandled fastapi error: {exc}")
    return fastapi.responses.JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal Server Error"},
    )


def main():
    # Run the tracker server on port 5000
    ssl_keyfile = './key.pem' if os.path.exists('./key.pem') else None
    ssl_certfile = './cert.pem' if os.path.exists('./cert.pem') else None
    if all([ssl_keyfile, ssl_certfile]):
        port = 443
    else:
        port = 8080

    uvicorn.run(fastapp, port=port, host='0.0.0.0', log_level="info", ssl_keyfile=ssl_keyfile, ssl_certfile=ssl_certfile)


if __name__ == '__main__':
    main()
