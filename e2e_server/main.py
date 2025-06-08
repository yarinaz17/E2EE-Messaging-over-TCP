from server import *


def main():
    try:
        server = Server(5555)
        server.start()
    except Exception as ex:
        print(f"Exception {type(ex).__name__} occurred. {ex.args}")


if __name__ == "__main__":
    main()
