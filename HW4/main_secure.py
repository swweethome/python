import os
import time
import json
import hmac
import hashlib
import secrets
import logging
import threading
import socket
from decimal import Decimal, InvalidOperation
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ValidationError, condecimal

HOST = os.environ.get("BANK_HOST", "127.0.0.1")
PORT = int(os.environ.get("BANK_PORT", "9999"))
DB_FILE = os.environ.get("BANK_DB", "bank_db.json")

PBKDF2_ITERATIONS = 200_000
SALT_BYTES = 16

MAX_LOGIN_FAILS = 5 
LOCKOUT_SECONDS = 60
CONN_IDLE_TIMEOUT = 30     
MAX_CONNECTIONS = 100      
MAX_LINE_BYTES = 8192      

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("bank")

_bank_lock = threading.Lock()

_used_request_ids: set[str] = set()

_login_fails: dict[str, list] = {}
_fails_lock = threading.Lock()

_conn_semaphore = threading.Semaphore(MAX_CONNECTIONS)

def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    if salt is None:
        salt = secrets.token_bytes(SALT_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt_hex, hash_hex = stored.split("$", 2)
        if scheme != "pbkdf2":
            return False
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False

class User(BaseModel):
    id: int
    login: str
    password_hash: str
    role: Literal["admin", "user"] = "user"
    balance: Decimal = Decimal("0")


class Transaction(BaseModel):
    id: int
    ts: datetime
    from_id: int
    to_id: int
    amount: Decimal
    comment: str = ""


class LoginRequest(BaseModel):
    login: str
    password: str


class TransferRequest(BaseModel):
    to_id: int
    amount: condecimal(gt=Decimal("0"))
    comment: str = ""


db = {
    "users": [
        User(id=1, login="admin", role="admin",
             password_hash=hash_password("admin123"),
             balance=Decimal("1000000")),
        User(id=2, login="alice", role="user",
             password_hash=hash_password("qwerty"),
             balance=Decimal("5000")),
        User(id=3, login="bob", role="user",
             password_hash=hash_password("12345"),
             balance=Decimal("100")),
    ],
    "transactions": [],
    "next_tx_id": 1,
}


def save_db():
    data = {
        "users": [u.model_dump(mode="json") for u in db["users"]],
        "transactions": [t.model_dump(mode="json") for t in db["transactions"]],
        "next_tx_id": db["next_tx_id"],
    }
    tmp = DB_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, DB_FILE)
    try:
        os.chmod(DB_FILE, 0o600)
    except OSError:
        pass


def load_db():
    global db
    if not os.path.exists(DB_FILE):
        return
    try:
        with open(DB_FILE, "r", encoding="utf-8") as f:
            raw = json.load(f)
        db["users"] = [User(**u) for u in raw["users"]]
        db["transactions"] = [Transaction(**t) for t in raw["transactions"]]
        db["next_tx_id"] = raw.get("next_tx_id", 1)
        log.info("DB loaded: %d users, %d transactions",
                 len(db["users"]), len(db["transactions"]))
    except Exception as e:
        log.error("Failed to load DB: %s", e)


def find_user_by_id(uid: int) -> Optional[User]:
    for u in db["users"]:
        if u.id == uid:
            return u
    return None


def find_user_by_login(login: str) -> Optional[User]:
    for u in db["users"]:
        if u.login == login:
            return u
    return None


def record_tx(from_id, to_id, amount, comment) -> Transaction:
    tx = Transaction(id=db["next_tx_id"], ts=datetime.now(),
                     from_id=from_id, to_id=to_id, amount=amount, comment=comment)
    db["transactions"].append(tx)
    db["next_tx_id"] += 1
    return tx


def do_transfer(sender: User, req: TransferRequest, request_id: Optional[str]) -> str:
    with _bank_lock:
        if request_id is not None:
            if request_id in _used_request_ids:
                log.warning("REPLAY rejected: user=%s req_id=%s", sender.login, request_id)
                return "ERR|Duplicate request (replay rejected)"
            _used_request_ids.add(request_id)

        receiver = find_user_by_id(req.to_id)
        if not receiver:
            return "ERR|Recipient not found"

        if receiver.id == sender.id:
            log.warning("SELF-TRANSFER rejected: user=%s", sender.login)
            return "ERR|Self-transfer is not allowed"

        if sender.balance < req.amount:
            return "ERR|Insufficient funds"

        sender.balance -= req.amount
        receiver.balance += req.amount
        tx = record_tx(sender.id, req.to_id, req.amount, req.comment)
        save_db()
        log.info("TRANSFER ok: %s -> id=%s amount=%s tx=%s",
                 sender.login, req.to_id, req.amount, tx.id)
        return f"OK|Transfer completed|tx={tx.id}|balance={sender.balance}"


def get_history_for(user: User) -> str:
    rows = [t for t in db["transactions"]
            if t.from_id == user.id or t.to_id == user.id]
    return "OK|" + json.dumps([t.model_dump(mode="json") for t in rows],
                              ensure_ascii=False)

def is_locked(login: str) -> bool:
    with _fails_lock:
        rec = _login_fails.get(login)
        if not rec:
            return False
        _, locked_until = rec
        if locked_until and datetime.now().timestamp() < locked_until:
            return True
        if locked_until and datetime.now().timestamp() >= locked_until:
            _login_fails.pop(login, None)
        return False


def register_fail(login: str):
    with _fails_lock:
        fails, _ = _login_fails.get(login, [0, 0])
        fails += 1
        locked = datetime.now().timestamp() + LOCKOUT_SECONDS if fails >= MAX_LOGIN_FAILS else 0
        _login_fails[login] = [fails, locked]
        if locked:
            log.warning("LOCKOUT: login=%s after %d fails", login, fails)


def register_success(login: str):
    with _fails_lock:
        _login_fails.pop(login, None)


HELP = (
    "Commands:\n"
    "  LOGIN <login> <password>               — log in\n"
    "  BALANCE                                — current balance\n"
    "  TRANSFER <to_id> <amount> [req_id] [c] — transfer (req_id против replay)\n"
    "  HISTORY                                — YOUR transaction history\n"
    "  ADMIN LIST_USERS                       — admin only, fixed command\n"
    "  QUIT                                   — exit\n"
)


def recv_line(conn: socket.socket) -> bytes:

    buf = b""
    deadline = time.monotonic() + CONN_IDLE_TIMEOUT
    while not buf.endswith(b"\n"):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("line read deadline exceeded")
        conn.settimeout(remaining)
        chunk = conn.recv(4096)
        if not chunk:
            break 
        buf += chunk
        if len(buf) > MAX_LINE_BYTES:
            raise ValueError("line too long")
    return buf


def handle_client(conn: socket.socket, addr):
    current_user: Optional[User] = None
    conn.settimeout(CONN_IDLE_TIMEOUT)
    ip = addr[0]
    log.info("Connection from %s", ip)
    try:
        conn.sendall(b"BANK SERVER READY\n")
        conn.sendall(b"LOGIN <login> <password>\n")

        while True:
            try:
                raw = recv_line(conn)
            except ValueError:
                conn.sendall(b"ERR|Line too long\n")
                log.warning("Oversized line from %s", ip)
                continue
            except (TimeoutError, socket.timeout):
                conn.sendall(b"ERR|Read timeout\n")
                log.info("Read timeout (possible Slowloris): %s", ip)
                break
            if not raw:
                break
            line = raw.decode(errors="ignore").strip()
            if not line:
                continue

            parts = line.split(" ", 1)
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""
            reply = "ERR|Unknown command (HELP for reference)"

            if cmd == "HELP":
                reply = "OK|\n" + HELP

            elif cmd == "LOGIN":
                try:
                    login_str, pwd_str = arg.split(" ", 1)
                    req = LoginRequest(login=login_str, password=pwd_str)
                except ValueError:
                    reply = "ERR|Format: LOGIN <login> <password>"
                except ValidationError as e:
                    reply = f"ERR|{e.errors()[0]['msg']}"
                else:
                    if is_locked(req.login): 
                        reply = "FAIL|Account temporarily locked. Try later."
                        log.warning("LOGIN blocked (locked): login=%s ip=%s",
                                    req.login, ip)
                    else:
                        user = find_user_by_login(req.login)
                        if user and verify_password(req.password, user.password_hash):
                            current_user = user
                            register_success(req.login)
                            reply = f"OK|{current_user.login}|role={current_user.role}"
                            log.info("LOGIN ok: login=%s ip=%s", req.login, ip)
                        else:
                            register_fail(req.login)
                            reply = "FAIL|Invalid login or password"
                            log.warning("LOGIN fail: login=%s ip=%s", req.login, ip)

            elif cmd == "BALANCE":
                reply = f"OK|{current_user.balance}" if current_user else "ERR|Login required"

            elif cmd == "TRANSFER":
                if not current_user:
                    reply = "ERR|Login required"
                else:
                    try:
                        chunks = arg.split(" ", 3)
                        req = TransferRequest(
                            to_id=chunks[0],
                            amount=chunks[1],
                            comment=chunks[3] if len(chunks) > 3 else "",
                        )
                        request_id = chunks[2] if len(chunks) > 2 else None
                    except (IndexError, ValidationError, InvalidOperation) as e:

                        msg = str(e).replace("\n", " ").replace("\r", " ")
                        reply = f"ERR|{msg[:120]}"
                    else:
                        reply = do_transfer(current_user, req, request_id)

            elif cmd == "HISTORY":
                reply = get_history_for(current_user) if current_user else "ERR|Login required"

            elif cmd == "ADMIN":
                if not current_user or current_user.role != "admin":
                    reply = "ERR|Access denied"
                    log.warning("ADMIN denied: user=%s ip=%s",
                                current_user.login if current_user else "-", ip)
                elif arg.strip().upper() == "LIST_USERS":
                    out = [{"id": u.id, "login": u.login, "role": u.role}
                           for u in db["users"]] 
                    reply = "OK|" + json.dumps(out, ensure_ascii=False)
                    log.info("ADMIN LIST_USERS by %s", current_user.login)
                else:
                    reply = "ERR|Unknown admin command (allowed: LIST_USERS)"

            elif cmd == "QUIT":
                conn.sendall(b"BYE\n")
                break

            conn.sendall((reply + "\n").encode())

    except Exception as e:
        log.error("Handler error %s: %s", ip, e)
    finally:
        conn.close()
        log.info("Disconnected: %s", ip)


def run_server():
    load_db()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(MAX_CONNECTIONS)
    log.info("Secure banking server listening on %s:%s", HOST, PORT)

    try:
        while True:
            conn, addr = srv.accept()
            if not _conn_semaphore.acquire(blocking=False):
                conn.sendall(b"ERR|Server busy\n")
                conn.close()
                log.warning("Connection refused (limit): %s", addr[0])
                continue

            def _wrap(c, a):
                try:
                    handle_client(c, a)
                finally:
                    _conn_semaphore.release()

            threading.Thread(target=_wrap, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        log.info("Stopped by user")
    finally:
        srv.close()


if __name__ == "__main__":
    run_server()