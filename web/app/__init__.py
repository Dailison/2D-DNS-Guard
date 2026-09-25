"""Fábrica do console web do 2D DNS Guard (dns-guard.2dtecnologia.com).

O console não tem banco próprio: dados de análise, empresas, operadores e metadados
de liberados vêm da API do analisador (VM 10.100.10.4); bloqueios, liberados e logs
vêm direto do Technitium.
"""

import logging

from flask import Flask, jsonify

from app.config import Config

logging.basicConfig(level=logging.INFO)


def create_app(config_object=Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_object)
    # Atrás do Traefik: respeita https/host originais em url_for(_external=True).
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

    @app.context_processor
    def _hub():
        return {"portal_kit_url": app.config.get("PORTAL_KIT_URL", "")}

    from app.analise import analise_bp
    from app.auth import auth_bp
    from app.dns import admin_bp
    from app.operadores import operadores_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(analise_bp)
    app.register_blueprint(operadores_bp)

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    return app
