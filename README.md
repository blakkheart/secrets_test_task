
# 🔐 Secret API 🔐

## Описание

Проект выполнен в качестве тестового задания для компании Market Intelligence.

API сервис позволяет создать секрет, задать кодовую фразу для его открытия и cгенерировать код, по которому можно прочитать секрет только один раз.
-   Метод  `/generate`  принимает секрет и кодовую фразу и отдает  `secret_key` , по которому этот секрет можно получить.
-   Метод  `/secrets/{secret_key}`  принимает на вход кодовую фразу и отдает секрет.

Сервис асинхронно обрабатывает запросы.
Данные сервиса хранятся во внешнем хранилище, запуск которого описан в  `docker-compose`. 
Секреты и кодовые фразы не хранятся в базе в открытом виде.
Задано время жизни для секретов с помощью TTL индексов. В данной реализации секрет существует 7 дней с момента создания, после чего автоматически удаляется базой данных.
 

## Стэк технологий

- [FastAPI](https://fastapi.tiangolo.com/) — фреймворк.
- [MongoDB](https://www.mongodb.com/) — база данных приложения.
- [Motor](https://github.com/mongodb/motor) — драйвер для соединения MongoDB и FastAPI.
- [cryptography](https://pypi.org/project/cryptography/)  — для шифрования чувствительной информации.
- [pytest](https://docs.pytest.org/en/8.0.x/) + [pytest-asyncio](https://pypi.org/project/pytest-asyncio/) — для асинхронных тестов.
- [Docker](https://www.docker.com/) — контейнеризация приложения.
- [Jinja2](https://pypi.org/project/Jinja2/) + [Bootstrap](https://getbootstrap.com/)  — для небольшой визуальной части проекта.

## Установка

1. Склонируйте репозиторий:
```bash
git clone https://github.com/blakkheart/secrets_test_task.git
```
2. Перейдите в директорию проекта:
```bash
cd secrets_test_task
```
3. Установите и активируйте виртуальное окружение:
   - Windows
   ```bash
   python -m venv venv
   source venv/Scripts/activate
   ```
   - Linux/macOS
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
4. Обновите [pip](https://pip.pypa.io/en/stable/):
   - Windows
   ```bash
   (venv) python -m pip install --upgrade pip
   ```
   - Linux/macOS
   ```bash
   (venv) python3 -m pip install --upgrade pip
   ```
5. Установите зависимости из файла requirements.txt:
   ```bash
   (venv) pip install -r requirements.txt
   ```
Создайте и заполните файл `.env` по примеру с файлом `.env.example`, который находится в корневой директории.



## Использование  

1. Введите команду для запуска докер-контейнера:
	```bash
	docker compose up
	```
Cервер запустится по адресу **localhost:8000** и вы сможете получить доступ к API.
Доступны эндпоинты:
 - **localhost:8000/generate**   —   POST запрос c параметрами:
	 ```json
	 {
	 "code_phrase": "string",
	 "secret": "string"
	 }
	 ```
  - **localhost:8000/generate/{secret_key}**   —   POST запрос c параметрами:
	  ```json
	  {
	 "code_phrase": "string"
	 }
	  ```
  - **localhost:8000** - демо проекта.
  - **localhost:8000/docs** - документация проекта.

### Дополнительно
Можно запустить тесты из основной директории с помощью команды `pytest`

