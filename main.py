import argparse
import sys

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument("--server", action='store_true', help="Run a server instance")

    if len(sys.argv) == 1:
        import client
        client.main()
        exit()

    args = parser.parse_args()

    if args.server:
        import server
        server.main()
        exit()
