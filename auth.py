from hashlib import sha256
from hmac import new as hmac_new, compare_digest
from base64 import b64encode, b64decode
from binascii import Error as BinasciiError
from json import dumps, loads
from dataclasses import dataclass, asdict
from conf import SECRET_KEY_BYTES
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)

users: dict[str, 'Data'] = {}


@dataclass(frozen=True)
class Data:
    user_name: str
    user_permissions_count: int
    user_role: str
    
    @property
    def json(self) -> str:
        return dumps(asdict(self))


class InvalidToken(Exception): ...


class PermissionDenied(Exception): ...


def sign_data(data_json: str) -> str:
    return hmac_new(SECRET_KEY_BYTES, data_json.encode(), digestmod=sha256).hexdigest()


def check_sign(data_json: str, sign: str) -> bool:
    return compare_digest(sign_data(data_json), sign)


def create_token(data_json: str) -> str:
    return b64encode(f'{data_json}.{sign_data(data_json)}'.encode()).decode()


def check_request_token(headers: list[str], permissions: int = 2) -> Data | None:
    try:
        authorization_header = next(i for i in headers if i.startswith('Authorization'))
        authorization_token_b64 = authorization_header.split()[-1]
        authorization_header_decoded = b64decode(authorization_token_b64).decode()
        
        user_json, token = authorization_header_decoded.split('.')
        user_data = loads(user_json)

        if not check_sign(user_json, token) or user_data['user_name'] not in users:
            raise InvalidToken
        
        elif user_data['user_permissions_count'] < permissions:
            raise PermissionDenied

    except (StopIteration, BinasciiError, UnicodeEncodeError, KeyError, UnicodeDecodeError) as e:
        logging.error(f"Token validation error: {e}")
        raise InvalidToken
    
    else:
        return Data(
            user_name=user_data['user_name'], 
            user_permissions_count=user_data['user_permissions_count'],
            user_role=user_data['user_role']
        )
