from pathlib import Path

from flask import Flask, abort, request

from . import fixed, vulnerable
from .seed import build_db

LOCAL_HOSTS = {"localhost", "127.0.0.1", "[::1]"}


def create_app(config=None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY="laboratorio-local-nao-use-em-lugar-nenhum",
        FILES_DIR=str(Path(__file__).with_name("files")),
    )
    if config:
        app.config.update(config)

    app.extensions["dbs"] = {
        "vuln": build_db("vuln"),
        "fixed": build_db("fixed", app.config.get("PASSWORD_HASH_METHOD")),
    }

    @app.before_request
    def only_localhost():
        """Esta aplicação é vulnerável de propósito: só responde a requisições para localhost.
        Barra acesso por IP de rede ou por nome DNS apontando para a máquina."""
        host = request.host.rsplit(":", 1)[0] if not request.host.startswith("[") else request.host.split("]")[0] + "]"
        if host not in LOCAL_HOSTS:
            abort(403, "Este laboratório só aceita acesso via localhost.")

    app.register_blueprint(vulnerable.bp)
    app.register_blueprint(fixed.bp)

    @app.route("/")
    def home():
        from flask import render_template

        return render_template("home.html")

    return app
