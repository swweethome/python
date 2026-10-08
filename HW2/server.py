import json
import logging
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

from pydantic import BaseModel, ConfigDict, Field, StrictInt, ValidationError

HOST = "127.0.0.1"
PORT = 8000

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler("server.log", mode="w", encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("server")

class UserStats(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    name: str = Field(..., description="Имя игрока")
    game: str = Field(..., description="Название игры")
    level: int = Field(..., ge=0, description="Уровень игрока")
    score: int = Field(..., ge=0, description="Количество очков")
    playtime_hours: int = Field(..., ge=0, description="Время в игре (часы)")


class ScoreRequest(BaseModel):
    score: StrictInt = Field(..., description="Сколько очков добавить")


class ErrorResponse(BaseModel):
    error: str


USERS_DATA: dict[str, UserStats] = {
    "user1": UserStats(name="Алексей", game="Dota 2", level=42, score=15320, playtime_hours=210),
    "user2": UserStats(name="Мария", game="Valorant", level=30, score=9870, playtime_hours=95),
    "user3": UserStats(name="Игорь", game="CS2", level=55, score=21000, playtime_hours=340),
}


def error(status, message):
    return status, ErrorResponse(error=message)


def explain_validation_error(exc):
    first = exc.errors()[0]          
    error_type = first["type"]       
    if error_type == "json_invalid":
        return "Невалидный JSON"
    if error_type == "missing":
        return "В теле должно быть поле score"
    if first["loc"] == ("score",):   
        return "Поле score должно быть числом"
    return "Тело запроса должно быть JSON-объектом с полем score"

class Handler(BaseHTTPRequestHandler):
    timeout = 5

    def do_GET(self):
        self.handle_request("GET")

    def do_POST(self):
        self.handle_request("POST")

    def do_PUT(self):
        self.handle_request("PUT")

    def do_DELETE(self):
        self.handle_request("DELETE")

    def do_PATCH(self):
        self.handle_request("PATCH")

    def log_message(self, format, *args):
        pass

    def handle_request(self, method):
        try:
            status, data = self.route(method)
        except TimeoutError:
            log.warning(f"[{method}] {self.path} -> клиент не прислал данные вовремя (таймаут)")
            return
        except Exception as exc:
            log.error(f"[{method}] {self.path} -> внутренняя ошибка: {exc}")
            status, data = error(500, "Внутренняя ошибка сервера")

        if status is None:
            return

        log.info(f"[{method}] {self.path} -> {status}")
        self.send_json(status, data)

    def route(self, method):
        parts = self.path.strip("/").split("/")

        if parts == ["users"]:
            if method != "GET":
                return error(405, "Метод не поддерживается")
            return 200, {user_id: user.model_dump() for user_id, user in USERS_DATA.items()}

        if len(parts) == 2 and parts[0] == "users":
            if method != "GET":
                return error(405, "Метод не поддерживается")
            user_id = parts[1]
            if user_id not in USERS_DATA:
                return error(404, "Пользователь не найден")
            return 200, USERS_DATA[user_id]

        if len(parts) == 3 and parts[0] == "users" and parts[2] == "score":
            if method != "POST":
                return error(405, "Метод не поддерживается")
            user_id = parts[1]
            if user_id not in USERS_DATA:
                return error(404, "Пользователь не найден")
            return self.add_score(user_id)

        return error(404, "Маршрут не найден")

    def add_score(self, user_id):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return error(400, "Некорректный заголовок Content-Length")

        if length <= 0:
            return error(400, "Пустое тело запроса")

        raw = self.rfile.read(length)
        if len(raw) < length:
            log.warning(f"[POST] {self.path} -> клиент оборвал соединение: получено {len(raw)} байт из {length}")
            return None, None

        try:
            body = ScoreRequest.model_validate_json(raw)
        except ValidationError as exc:
            return error(400, explain_validation_error(exc))

        user = USERS_DATA[user_id]
        
        try:
            user.score = user.score + body.score
        except ValidationError:
            return error(400, "Счёт пользователя не может стать отрицательным")

        return 200, user

    def send_json(self, status, data):
        if isinstance(data, BaseModel):
            text = data.model_dump_json()             
        else:
            text = json.dumps(data, ensure_ascii=False)  
        body = text.encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            log.warning("Не удалось отправить ответ: клиент уже отключился")


log.info("=" * 60)
log.info(f"Запуск сервера: {datetime.now().isoformat(timespec='seconds')}")
log.info(f"Адрес: http://{HOST}:{PORT}")
log.info("=" * 60)

server = HTTPServer((HOST, PORT), Handler)
try:
    server.serve_forever()
except KeyboardInterrupt:
    log.info("Получен Ctrl+C, остановка сервера...")
finally:
    server.server_close()
    log.info("Сервер остановлен")
