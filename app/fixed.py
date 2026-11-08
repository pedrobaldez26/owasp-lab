"""MODO CORRIGIDO. Mesmas rotas de vulnerable.py, cada falha resolvida.

Os comentários [FIX n] apontam a correção de cada laboratório.
"""
import sqlite3
from pathlib import Path

from flask import Blueprint, Response, abort, current_app, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

bp = Blueprint("fixed", __name__, url_prefix="/fixed")
MODE = "fixed"
SESSION_KEY = "user_fixed"
PUBLIC_EXTENSIONS = {".txt"}


def db():
    return current_app.extensions["dbs"][MODE]


def current_user():
    user_id = session.get(SESSION_KEY)
    if not user_id:
        return None
    return db().execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,)).fetchone()


def page(template, **ctx):
    return render_template(template, mode=MODE, vulnerable=False, user=current_user(), **ctx)


@bp.route("/")
def index():
    return page("lab.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # [FIX 1] consulta parametrizada: o valor nunca vira SQL
        row = db().execute("SELECT id, password_hash FROM users WHERE username = ?", (username,)).fetchone()
        # [FIX 5] hash com sal e custo (scrypt/PBKDF2) conferido por função própria
        if row and check_password_hash(row["password_hash"], password):
            session.clear()  # sessão nova após login
            session[SESSION_KEY] = row["id"]
            return redirect(url_for("fixed.index"))
        # mensagem genérica, sem detalhe de banco
        return page("login.html", error="Usuário ou senha incorretos."), 401
    return page("login.html", error=None)


@bp.post("/logout")
def logout():
    session.pop(SESSION_KEY, None)
    return redirect(url_for("fixed.index"))


@bp.route("/search")
def search():
    q = request.args.get("q", "")
    results, error = [], None
    if q:
        pattern = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        try:
            # [FIX 1] parametrizada; % e _ digitados viram texto
            results = db().execute(
                "SELECT name, description, price_cents FROM products WHERE name LIKE ? ESCAPE '\\'", (pattern,)
            ).fetchall()
        except sqlite3.Error:
            current_app.logger.exception("falha na busca")
            error = "Não foi possível buscar agora."
    return page("search.html", q=q, results=results, error=error)


@bp.route("/guestbook", methods=["GET", "POST"])
def guestbook():
    if request.method == "POST":
        author = request.form.get("author", "anônimo")[:40]
        body = request.form.get("body", "")[:500]
        db().execute("INSERT INTO comments (author, body) VALUES (?, ?)", (author, body))
        db().commit()
        return redirect(url_for("fixed.guestbook"))
    comments = db().execute("SELECT author, body FROM comments ORDER BY id DESC").fetchall()
    # [FIX 2] o template imprime body com escape automático do Jinja
    return page("guestbook.html", comments=comments)


@bp.route("/invoices/<int:invoice_id>")
def invoice(invoice_id: int):
    user = current_user()
    if user is None:
        return redirect(url_for("fixed.login"))
    # [FIX 3] a própria consulta exige que a nota seja do usuário logado.
    # Responde 404 (e não 403) para não confirmar que a nota existe.
    row = db().execute(
        "SELECT i.id, i.description, i.amount_cents, u.username AS owner FROM invoices i JOIN users u ON u.id = i.owner_id "
        "WHERE i.id = ? AND i.owner_id = ?",
        (invoice_id, user["id"]),
    ).fetchone()
    if row is None:
        abort(404)
    return page("invoice.html", invoice=row)


@bp.route("/files")
def files():
    name = request.args.get("name", "bem-vindo.txt")
    base = Path(current_app.config["FILES_DIR"]).resolve()
    # [FIX 4] resolve o caminho final e confere que continua dentro da pasta pública e com extensão permitida
    target = (base / name).resolve()
    if base not in target.parents or target.suffix not in PUBLIC_EXTENSIONS or not target.is_file():
        abort(404)
    return Response(target.read_text(encoding="utf-8"), mimetype="text/plain; charset=utf-8")
