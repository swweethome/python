import http.client
import json
import logging
import socket
import time
from datetime import datetime

from pydantic import BaseModel, Field, StrictInt, ValidationError

HOST = "127.0.0.1"
PORT = 8000
SEPARATOR = "-" * 60

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler("client.log", mode="w", encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("client")

class UserStats(BaseModel):
    name: str
    game: str
    level: int = Field(..., ge=0)
    score: int = Field(..., ge=0)
    playtime_hours: int = Field(..., ge=0)


class ScoreRequest(BaseModel):
    score: StrictInt


class ErrorResponse(BaseModel):
    error: str


def check_response(status, path, text):
    try:
        if status != 200:
            answer = ErrorResponse.model_validate_json(text)
            log.info(f"    ошибка от сервера: {answer.error}")
        elif path == "/users":
            users = {user_id: UserStats.model_validate(user) for user_id, user in json.loads(text).items()}
            log.info(f"    получено пользователей: {len(users)}")
        else:
            user = UserStats.model_validate_json(text)
            log.info(f"    {user.name}: игра {user.game}, уровень {user.level}, счёт {user.score}")
    except ValidationError as exc:
        log.error(f"    ответ сервера не соответствует формату: {exc}")


def send_request(method, path, body=None):
    log.info(f">>> {method} {path}")
    if body is not None:
        log.debug(f"    body: {body}")
    try:
        connection = http.client.HTTPConnection(HOST, PORT, timeout=5)
        if body is None:
            connection.request(method, path)
        else:
            connection.request(method, path, body=body.encode("utf-8"),
                               headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        text = response.read().decode("utf-8")
        connection.close()
        log.info(f"<<< {response.status} {response.reason}")
        log.info("    " + text)
        check_response(response.status, path, text)
        log.info(SEPARATOR)
        return response.status
    except ConnectionRefusedError:
        log.error("<<< Сервер недоступен (не запущен или упал)")
        log.info(SEPARATOR)
        return None


def send_and_disconnect():
    request_text = (
        "POST /users/user1/score HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Length: 50\r\n"
        "\r\n"
        '{"score": 1'
    )
    log.info(">>> POST /users/user1/score (обрыв: заявлено 50 байт, отправлено 11)")
    try:
        sock = socket.create_connection((HOST, PORT))
        sock.sendall(request_text.encode("utf-8"))
        sock.close()
        log.info("<<< соединение закрыто клиентом, ответ не ожидается")
    except ConnectionRefusedError:
        log.error("<<< Сервер недоступен (не запущен или упал)")
    log.info(SEPARATOR)


log.info("=" * 60)
log.info(f"Запуск клиента: {datetime.now().isoformat(timespec='seconds')}")
log.info("=" * 60)

log.info("КОРРЕКТНЫЕ ЗАПРОСЫ")
send_request("GET", "/users")
send_request("GET", "/users/user2")

send_request("POST", "/users/user1/score", ScoreRequest(score=500).model_dump_json())

log.info("НЕКОРРЕКТНЫЕ ЗАПРОСЫ")

send_request("GET", "/users/user99")                
send_request("GET", "/foo")                                   
send_request("POST", "/users/user1/score")                       
send_request("POST", "/users/user1/score", "{score: 100")        
send_request("POST", "/users/user1/score", '{"score": "abc"}')     
send_request("POST", "/users/user1/score", '{"score": "100"}')      
send_request("POST", "/users/user1/score", '{"points": 100}')    
send_request("POST", "/users/user1/score", '{"score": -99999999}')  
send_request("DELETE", "/users")                                   
send_and_disconnect()                                            

time.sleep(0.5)
log.info("ПРОВЕРКА: СЕРВЕР ЖИВ?")
status = send_request("GET", "/users/user1")
if status == 200:
    log.info("Сервер продолжает работать после всех плохих запросов")
else:
    log.error("Сервер не отвечает!")

log.info("Клиент завершил работу")
