import secrets
import string
import os
import hashlib

from dotenv import load_dotenv
from cryptography.fernet import Fernet
from typing import Annotated, List, Optional
from fastapi import FastAPI, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

load_dotenv()

app = FastAPI()

MONGO_URL = 'mongodb://127.0.0.1:27017'
client = AsyncIOMotorClient(MONGO_URL)
db = client['mydatebase']
collection = db['items']

KEY = os.getenv('KEY', '1234').encode()
fernet = Fernet(KEY)
PyObjectId = Annotated[str, BeforeValidator(str)]


class Secret(BaseModel):
    id: Optional[PyObjectId] = Field(alias='_id', default=None)
    secret: str
    code_phrase: str
    secret_key: str
    salt: str
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True
    )


class ReadSecret(BaseModel):
    code_phrase: str
    secret: str


class ReadCodePhrase(BaseModel):
    code_phrase: str


@app.post('/generate', response_model_by_alias=False,)
async def generete_secret(secret: ReadSecret) -> str:
    '''
    Generate secret with code_phrase.
    Returns secret_key to access your secret.
    '''
    salt = os.urandom(32)

    characters = (
        string.ascii_letters + string.digits
        + secret.secret
    )
    secret_key: str = ''.join(secrets.choice(characters) for _ in range(32))
    code_phrase_bytes: bytes = hashlib.pbkdf2_hmac(
        'sha256', secret.code_phrase.encode('utf-8'), salt, 10000)
    secret_str_bytes: bytes = fernet.encrypt(
        secret.secret.encode('utf-8'))
    db_secret = Secret(
        secret_key=secret_key,
        secret=secret_str_bytes.decode('utf-8'),
        code_phrase=code_phrase_bytes.decode('ISO-8859-1'),
        salt=salt.decode('ISO-8859-1'),
    )
    await collection.insert_one(
        db_secret.model_dump(
            by_alias=True,
            exclude=['id']
        )
    )
    return secret_key


@app.post('/generate/{secret_key}')
async def get_secret(code_phrase: ReadCodePhrase, secret_key: str) -> str:
    '''
    Get secret via secret_key with code_phrase.
    Returns secret.
    '''
    secret = await collection.find_one({'secret_key': secret_key})
    if secret:
        if hashlib.pbkdf2_hmac(
            'sha256',
            code_phrase.code_phrase.encode('utf-8'),
            secret.get('salt').encode('ISO-8859-1'),
            10000
        ) == secret.get('code_phrase').encode('ISO-8859-1'):
            secret_decoded = Fernet(KEY).decrypt(secret.get('secret')).decode()
            return secret_decoded
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
