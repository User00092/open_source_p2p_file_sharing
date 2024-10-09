import socket


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Bind to all interfaces on a random free port assigned by the OS
        s.bind(('', 0))
        # Get the port number assigned
        port = s.getsockname()[1]
    return port

