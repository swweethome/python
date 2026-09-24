import json
import logging
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

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

USERS_DATA = {
    "user1": {"name": "Алексей", "game": "Dota 2", "level": 42, "score": 15320, "playtime_hours": 210},
    "user2": {"name": "Мария", "game": "Valorant", "level": 30, "score": 9870, "playtime_hours": 95},
    "user3": {"name": "Игорь", "game": "CS2", "level": 55, "score": 21000, "playtime_hours": 340},
}


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
        except Exception as error:
            log.error(f"[{method}] {self.path} -> внутренняя ошибка: {error}")
            status, data = 500, {"error": "Внутренняя ошибка сервера"}

        if status is None:
            return

        log.info(f"[{method}] {self.path} -> {status}")
        self.send_json(status, data)

    def route(self, method):
        parts = self.path.strip("/").split("/")

        if parts == ["users"]:
            if method != "GET":
                return 405, {"error": "Метод не поддерживается"}
            return 200, USERS_DATA

        if len(parts) == 2 and parts[0] == "users":
            if method != "GET":
                return 405, {"error": "Метод не поддерживается"}
            user_id = parts[1]
            if user_id not in USERS_DATA:
                return 404, {"error": "Пользователь не найден"}
            return 200, USERS_DATA[user_id]

        if len(parts) == 3 and parts[0] == "users" and parts[2] == "score":
            if method != "POST":
                return 405, {"error": "Метод не поддерживается"}
            user_id = parts[1]
            if user_id not in USERS_DATA:
                return 404, {"error": "Пользователь не найден"}
            return self.add_score(user_id)

        return 404, {"error": "Маршрут не найден"}

    def add_score(self, user_id):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return 400, {"error": "Некорректный заголовок Content-Length"}

        if length <= 0:
            return 400, {"error": "Пустое тело запроса"}

        raw = self.rfile.read(length)
        if len(raw) < length:
            log.warning(f"[POST] {self.path} -> клиент оборвал соединение: получено {len(raw)} байт из {length}")
            return None, None

        try:
            body = json.loads(raw)
        except ValueError:
            return 400, {"error": "Невалидный JSON"}

        if type(body) is not dict or "score" not in body:
            return 400, {"error": "В теле должно быть поле score"}

        score = body["score"]
        if type(score) not in (int, float):
            return 400, {"error": "Поле score должно быть числом"}

        USERS_DATA[user_id]["score"] = USERS_DATA[user_id]["score"] + score
        return 200, USERS_DATA[user_id]

    def send_json(self, status, data):
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
