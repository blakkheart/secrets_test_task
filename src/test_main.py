import pytest
from httpx import ASGITransport, AsyncClient

from src.main import app


@pytest.mark.asyncio
async def test_get_secret():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url='http://test'
    ) as ac:
        response = await ac.post(
            '/generate',
            json={
                "code_phrase": "code_phrase",
                "secret": "secret_phrase"
            }
        )

        assert response.status_code == 200
        secret_key = response.json()
        assert len(secret_key) == 32

        response = await ac.post(
            f'/generate/{secret_key}',
            json={
                "code_phrase": "wrong_code_prhase",
            }
        )

        assert response.status_code == 403

        response = await ac.post(
            f'/generate/{secret_key}',
            json={
                "code_phrase": "code_phrase",
            }
        )

        assert response.status_code == 200
        secret_phrase = response.json()
        assert secret_phrase == 'secret_phrase'

        response = await ac.post(
            f'/generate/{secret_key}',
            json={
                "code_phrase": "code_phrase",
            }
        )

        assert response.status_code == 404
