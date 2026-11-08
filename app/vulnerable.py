"""MODO VULNERÁVEL. Cada rota abaixo tem uma falha de propósito, marcada com [VULN].

Não copie nada daqui para um projeto real. A versão corrigida de cada rota está em fixed.py.
"""
import hashlib
import sqlite3
from pathlib import Path

from flask import Blueprint, Response, abort, current_app, redirect, render_template, request, session, url_for

bp = Blueprint("vuln", __name__, url_prefix="/vuln")
MODE = "vuln"
SESSION_KEY = "user_vuln"


def db():
    return current_app.extensions["dbs"][MODE]


def current_user():
    user_id = session.get(SESSION_KEY)
    if not user_id:
        return None
    return db().execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,)).fetchone()


def page(template, **ctx):
    return render_template(template, mode=MODE, vulnerable=True, user=current_user(), **ctx)


@bp.route("/")
def index():
    return page("lab.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password_hash = hashlib.md5(request.form.get("password", "").encode()).hexdigest()  # [VULN 5] MD5 sem sal
        # [VULN 1] SQL montado por concatenação: o usuário controla a consulta
        sql = f"SELECT id FROM users WHERE username = '{username}' AND password_hash = '{password_hash}'"
        try:
            row = db().execute(sql).fetchone()
        except sqlite3.Error as exc:
            error = f"Erro de banco: {exc} | SQL: {sql}"  # [VULN] vaza o erro e a consulta
            return page("login.html", error=error), 500
        if row:
            session[SESSION_KEY] = row["id"]
            return redirect(url_for("vuln.index"))
        error = "Usuário ou senha incorretos."
        return page("login.html", error=error), 401
    return page("login.html", error=None)


@bp.post("/logout")
def logout():
    session.pop(SESSION_KEY, None)
    return redirect(url_for("vuln.index"))


@bp.route("/search")
def search():
    q = request.args.get("q", "")
    results, error = [], None
    if q:
        sql = f"SELECT name, description, price_cents FROM products WHERE name LIKE '%{q}%'"  # [VULN 1]
        try:
            results = db().execute(sql).fetchall()
        except sqlite3.Error as exc:
            error = f"Erro de banco: {exc}"
    return page("search.html", q=q, results=results, error=error)


@bp.route("/guestbook", methods=["GET", "POST"])
def guestbook():
    if request.method == "POST":
        author = request.form.get("author", "anônimo")[:40]
        body = request.form.get("body", "")[:500]
        db().execute("INSERT INTO comments (author, body) VALUES (?, ?)", (author, body))
        db().commit()
        return redirect(url_for("vuln.guestbook"))
    comments = db().execute("SELECT author, body FROM comments ORDER BY id DESC").fetchall()
    return page("guestbook.html", comments=comments)  # [VULN 2] o template imprime body com |safe


@bp.route("/invoices/<int:invoice_id>")
def invoice(invoice_id: int):
    user = current_user()
    if user is None:
        return redirect(url_for("vuln.login"))
    row = db().execute(
        "SELECT i.id, i.description, i.amount_cents, u.username AS owner FROM invoices i JOIN users u ON u.id = i.owner_id WHERE i.id = ?",
        (invoice_id,),
    ).fetchone()
    if row is None:
        abort(404)
    # [VULN 3] confere que está logado, mas não que a nota é DESTE usuário
    return page("invoice.html", invoice=row)


@bp.route("/files")
def files():
    name = request.args.get("name", "bem-vindo.txt")
    base = Path(current_app.config["FILES_DIR"])
    path = base / name  # [VULN 4] nada impede "../" para sair da pasta pública
    try:
        return Response(path.read_text(encoding="utf-8"), mimetype="text/plain; charset=utf-8")
    except (OSError, UnicodeDecodeError):
        abort(404)
