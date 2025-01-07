import base64
import hashlib
import hmac
import json
import time

SECRET_KEY = 'secret_key'


class Jwt:

    def __init__(self, secret_key):
        self.secret_key = secret_key

    @staticmethod
    def base64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

    @staticmethod
    def base64url_decode(data: str) -> bytes:
        padding = '=' * (4 - len(data) % 4)
        return base64.urlsafe_b64decode(data + padding)

    def sign(self, payload):
        encoded_header = self.base64url_encode(json.dumps({
            'alg': 'HS256',
            'typ': 'JWT',
        }).encode())

        encoded_payload = self.base64url_encode(json.dumps({
            'exp': int(time.time()) + 3600,
            **payload
        }).encode())

        signature = hmac.new(
            self.secret_key.encode(),
            f'{encoded_header}.{encoded_payload}'.encode(),
            hashlib.sha256
        ).hexdigest()

        return f'{encoded_header}.{encoded_payload}.{signature}'

    def validate(self, token):
        encoded_header, encoded_payload, signature = token.split('.')

        header = json.loads(self.base64url_decode(encoded_header).decode())
        payload = json.loads(self.base64url_decode(encoded_payload).decode())

        if 'exp' in payload and time.time() > payload['exp']:
            raise ValueError('The token is expired')

        signature_check = hmac.new(
            self.secret_key.encode(),
            f'{encoded_header}.{encoded_payload}'.encode(),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(signature, signature_check):
            raise ValueError('The signature is invalid')

        return payload, header


jwt = Jwt(SECRET_KEY)

token = jwt.sign({'sub': 1, 'username': 'oroz'})

print(token)

payload, header = jwt.validate(token)

print(payload)
