#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_security.py — автоматические проверки безопасности сервера main_secure.py.

Каждый тест поднимает свежий сервер на тестовом порту с временной базой и
проверяет, что конкретная атака из ДЗ-3 НЕ проходит, а легитимные операции
работают. Запуск:

    python -m unittest -v test_security.py
"""

import os
import sys
import time
import socket
import tempfile
import threading
import subprocess
import unittest

HOST = "127.0.0.1"
PORT = 9998  # отдельный порт, чтобы не мешать «боевому» 9999


class Conn:
    """Простой клиент: читает 2 строки приветствия, затем по строке на команду."""

    def __init__(self, host=HOST, port=PORT, timeout=5):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect((host, port))
        self.buf = b""
        self._readline()  # BANK SERVER READY
        self._readline()  # LOGIN <login> <password>

    def _readline(self):
        while b"\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            self.buf += chunk
        line, _, self.buf = self.buf.partition(b"\n")
        return line.decode(errors="ignore").strip()

    def cmd(self, line):
        self.sock.sendall(line.encode() + b"\n")
        return self._readline()

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


class SecureServerTest(unittest.TestCase):
    """Базовый класс: поднимает свежий сервер перед каждым тестом."""

    def setUp(self):
        self.dbfile = tempfile.NamedTemporaryFile(
            suffix=".json", delete=False).name
        os.unlink(self.dbfile)  # пусть сервер создаст с нуля
        env = dict(os.environ, BANK_HOST=HOST, BANK_PORT=str(PORT),
                   BANK_DB=self.dbfile)
        self.proc = subprocess.Popen(
            [sys.executable, "main_secure.py"], env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._wait_port()

    def tearDown(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()
        if os.path.exists(self.dbfile):
            os.unlink(self.dbfile)

    def _wait_port(self, timeout=10):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                s = socket.create_connection((HOST, PORT), timeout=0.5)
                s.close()
                return
            except OSError:
                time.sleep(0.1)
        self.fail("Сервер не поднялся на тестовом порту")

    # ---------- Легитимная работа ----------
    def test_01_legit_login_and_balance(self):
        c = Conn()
        self.assertTrue(c.cmd("LOGIN alice qwerty").startswith("OK|"))
        self.assertEqual(c.cmd("BALANCE"), "OK|5000")
        c.close()

    def test_02_legit_transfer(self):
        c = Conn()
        c.cmd("LOGIN alice qwerty")
        self.assertTrue(c.cmd("TRANSFER 3 100 req-a обед").startswith("OK|"))
        self.assertEqual(c.cmd("BALANCE"), "OK|4900")
        c.close()

    # ---------- Атаки из ДЗ-3 ----------
    def test_03_sql_injection_login_fails(self):
        c = Conn()
        reply = c.cmd("LOGIN ' OR '1'='1 x")
        self.assertTrue(reply.startswith("FAIL"))
        self.assertEqual(c.cmd("BALANCE"), "ERR|Login required")
        c.close()

    def test_04_admin_sql_denied(self):
        c = Conn()
        c.cmd("LOGIN alice qwerty")  # обычный пользователь
        self.assertTrue(c.cmd("ADMIN SELECT * FROM users").startswith("ERR"))
        c.close()

    def test_05_negative_transfer_rejected(self):
        c = Conn()
        c.cmd("LOGIN bob 12345")
        self.assertTrue(c.cmd("TRANSFER 2 -1000 hack").startswith("ERR"))
        self.assertEqual(c.cmd("BALANCE"), "OK|100")  # баланс не изменился
        c.close()

    def test_06_zero_transfer_rejected(self):
        c = Conn()
        c.cmd("LOGIN bob 12345")
        self.assertTrue(c.cmd("TRANSFER 2 0 zero").startswith("ERR"))
        c.close()

    def test_07_self_transfer_rejected(self):
        c = Conn()
        c.cmd("LOGIN alice qwerty")
        self.assertIn("Self-transfer", c.cmd("TRANSFER 2 100 r1 self"))
        c.close()

    def test_08_idor_history_only_own(self):
        # alice переводит bob -> у alice появляется своя транзакция.
        c = Conn()
        c.cmd("LOGIN alice qwerty")
        c.cmd("TRANSFER 3 100 h1 x")
        own = c.cmd("HISTORY")           # своя история — непустая
        idor = c.cmd("HISTORY 1")        # попытка посмотреть чужую (admin, id=1)
        self.assertEqual(own, idor)      # uid игнорируется — показывается только своя
        self.assertNotIn('"from_id": 1', idor)  # нет чужих операций админа
        c.close()

    def test_09_replay_rejected(self):
        c = Conn()
        c.cmd("LOGIN alice qwerty")
        first = c.cmd("TRANSFER 3 100 SAME-ID pay")
        second = c.cmd("TRANSFER 3 100 SAME-ID pay")
        self.assertTrue(first.startswith("OK|"))
        self.assertIn("replay", second.lower())
        c.close()

    def test_10_bruteforce_lockout(self):
        # 5 неудачных попыток -> аккаунт блокируется.
        for _ in range(5):
            c = Conn(); c.cmd("LOGIN alice wrongpass"); c.close()
        c = Conn()
        reply = c.cmd("LOGIN alice qwerty")  # верный пароль, но уже блокировка
        self.assertIn("locked", reply.lower())
        c.close()

    def test_11_oversized_line_rejected(self):
        c = Conn()
        c.cmd("LOGIN alice qwerty")
        reply = c.cmd("TRANSFER 3 100 " + "A" * 9000)  # длиннее MAX_LINE_BYTES
        self.assertTrue(reply.startswith("ERR"))
        c.close()

    def test_12_race_no_overspend(self):
        # 20 потоков пытаются перевести больше, чем есть на балансе.
        results = []

        def worker(n):
            try:
                c = Conn()
                c.cmd("LOGIN alice qwerty")
                for i in range(10):
                    results.append(c.cmd(f"TRANSFER 3 400 race-{n}-{i} r"))
                c.close()
            except Exception as e:
                results.append(f"ERR|{e}")

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        ok = sum(1 for r in results if r.startswith("OK|"))
        # alice=5000, перевод 400 -> не больше 12 успешных
        self.assertLessEqual(ok, 12, "Перерасход: прошло больше переводов, чем есть денег")

        # Деньги сохранены и баланс не ушёл в минус.
        a = Conn(); a.cmd("LOGIN alice qwerty"); alice_bal = int(a.cmd("BALANCE").split("|")[1]); a.close()
        b = Conn(); b.cmd("LOGIN bob 12345"); bob_bal = int(b.cmd("BALANCE").split("|")[1]); b.close()
        self.assertGreaterEqual(alice_bal, 0)
        self.assertEqual(alice_bal + bob_bal, 5000 + 100)  # сумма сохранена


if __name__ == "__main__":
    unittest.main(verbosity=2)
