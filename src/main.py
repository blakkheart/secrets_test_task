from datetime import datetime, timedelta
import os
import hashlib
import secrets
import string
from typing import Annotated, Optional


from contextlib import asynccontextmanager
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, status, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field
import pytz


load_dotenv()

MONGO_URL = os.getenv('MONGO_URL', 'mongodb://127.0.0.1:27017')
client = AsyncIOMotorClient(MONGO_URL)
db = client['secrets_db']
collection = db['secrets']

KEY = os.getenv('KEY', '1234').encode()
SALT_SIZE = int(os.getenv('SALT_SIZE', 32))
HASH_NAME = os.getenv('HASH_NAME', 'sha256')
ITERATIONS = int(os.getenv('ITERATIONS', 10000))

fernet = Fernet(KEY)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await collection.create_index(
        'expire_at',
        expireAfterSeconds=0,
    )
    yield


app = FastAPI(lifespan=lifespan)


templates = Jinja2Templates(directory='src/templates')


PyObjectId = Annotated[str, BeforeValidator(str)]


class Secret(BaseModel):
    id: Optional[PyObjectId] = Field(alias='_id', default=None)
    secret: str
    code_phrase: str
    secret_key: str
    salt: str
    expire_at: datetime = Field(default=None)
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
    salt = os.urandom(SALT_SIZE)

    characters = (string.ascii_letters + string.digits)
    secret_key: str = ''.join(secrets.choice(characters) for _ in range(32))

    code_phrase_bytes: bytes = hashlib.pbkdf2_hmac(
        HASH_NAME, secret.code_phrase.encode('utf-8'), salt, ITERATIONS)

    secret_bytes: bytes = fernet.encrypt(
        secret.secret.encode('utf-8'))

    db_secret = Secret(
        secret_key=secret_key,
        secret=secret_bytes.decode('utf-8'),
        code_phrase=code_phrase_bytes.decode('ISO-8859-1'),
        salt=salt.decode('ISO-8859-1'),
        expire_at=datetime.now(tz=pytz.utc) + timedelta(days=7)
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
            HASH_NAME,
            code_phrase.code_phrase.encode('utf-8'),
            secret.get('salt').encode('ISO-8859-1'),
            ITERATIONS
        ) == secret.get('code_phrase').encode('ISO-8859-1'):
            secret_decoded = fernet.decrypt(secret.get('secret')).decode()
            await collection.delete_one({'secret_key': secret_key})
            return secret_decoded
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={'error': 'Incorrect code phrase!'}
        )
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={'error': 'No such secret key'}
    )


@app.get('/', response_class=HTMLResponse)
async def main_page(request: Request):
    return templates.TemplateResponse(
        request=request, name='index.html'
    )


@app.get('/get_a_secret', response_class=HTMLResponse)
async def get_a_secret_page(request: Request):
    return templates.TemplateResponse(
        request=request, name='get_a_secret.html'
    )
