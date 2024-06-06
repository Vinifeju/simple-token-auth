from socket import socket, SOCK_STREAM, AF_INET, SO_REUSEADDR, SOL_SOCKET
from concurrent.futures import ThreadPoolExecutor
from auth import users, check_request_token, Data, InvalidToken, PermissionDenied, create_token
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)

# create base administrator and user
users['vinifeju'] = Data(user_name='vinifeju', user_role='admin', user_permissions_count=2)
users['maxf'] = Data(user_name='maxf', user_role='user', user_permissions_count=1)


logging.info(f"Administrator token: {create_token(users['vinifeju'].json)}")
logging.info(f"User token: {create_token(users['maxf'].json)}")


class RequestHandler:
    @classmethod
    def generate_http_response(cls, *, code: int = 200, status: str = 'OK', response_headers: dict = {}) -> str:
        http_base_response = [f'HTTP/1.1 {code} {status}', 'Server: python']
        
        for k, v in response_headers.items():
            http_base_response.append(f'{k}: {v}')
        
        http_base_response += ['', '']
        return '\r\n'.join(http_base_response)
    
    @classmethod
    def handle(cls, client_socket: socket) -> None:
        try:
            request = client_socket.recv(1024)
            request_headers = request.decode().split('\r\n')
            path = request_headers[0].split()[1].strip('/')
            
            match path:
                case '':
                    base_response = cls.generate_http_response(
                        response_headers={'content-type': 'text/html'}) + '<h1>Hello from socket server!</h1>'
                    client_socket.send(base_response.encode())

                case 'users-page':
                    user = check_request_token(request_headers, permissions=1)
                    user_response = cls.generate_http_response(
                        response_headers={'content-type': 'text/html'}
                    ) + f'Hello {user.user_name}, you are in default user page :|'
                    client_socket.send(user_response.encode())

                case 'admin-page':
                    admin = check_request_token(request_headers, permissions=2)
                    admin_response = cls.generate_http_response(
                        response_headers={'content-type': 'text/html'}
                    ) + f'Hello <b>{admin.user_name}</b>, you are logged in as an administrator >)'
                    client_socket.send(admin_response.encode())

        except InvalidToken as e:
            logging.warning(f"Invalid token error: {e}")
            invalid_token_response = cls.generate_http_response(
                code=401,
                status='Unauthorized',
                response_headers={'content-type': 'text/html'}
            ) + '<h3>Invalid token!</h3>'
            client_socket.send(invalid_token_response.encode())

        except PermissionDenied:
            logging.warning("Permission denied error")
            permission_denied_response = cls.generate_http_response(
                code=403,
                status='Forbidden',
                response_headers={'content-type': 'text/html'}
            ) + '<h3>Permission denied!</h3>'
            client_socket.send(permission_denied_response.encode())

        finally:
            client_socket.close()


def start_http_server(host: str = 'localhost', port: int = 1313) -> None:
    http_socket = socket(AF_INET, SOCK_STREAM)
    http_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    http_socket.bind((host, port))
    http_socket.listen()
    
    logging.info(f'Server started at {host}:{port}')
    
    with ThreadPoolExecutor() as executor:
        while True:
            http_connection, addr = http_socket.accept()
            logging.info(f'Connection from: {addr}')
            executor.submit(RequestHandler.handle, http_connection)


if __name__ == '__main__':
    start_http_server()
