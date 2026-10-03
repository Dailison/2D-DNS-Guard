"""Serviço liberado só para um IP/faixa (console: "IPs que liberam"). PostgreSQL real (pgserver)."""

import pytest

pgserver = pytest.importorskip("pgserver")

TOKEN = "t-ips"
H = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture(scope="module")
def api(tmp_path_factory):
    import os

    from dnsanalyzer import config, db
    from dnsanalyzer.migrate import migrate

    srv = pgserver.get_server(str(tmp_path_factory.mktemp("pg")), cleanup_mode="stop")
    uri = srv.get_uri()
    antes = {k: os.environ.get(k) for k in ("DATABASE_URL", "API_TOKEN", "DNSANALYZER_ENV")}
    os.environ.update(DATABASE_URL=uri, API_TOKEN=TOKEN, DNSANALYZER_ENV="/nao-existe")
    config._settings = None
    db.close()
    migrate(uri)
    with db.conn() as c:
        c.execute("INSERT INTO tenants (slug, name) VALUES ('emp-a', 'Empresa A')")
        c.execute("INSERT INTO liberado_meta (ip, usuario) VALUES ('10.9.9.9/32', 'isento')")
        c.execute("INSERT INTO liberado_log (ip, acao, por) VALUES ('10.9.9.9/32', 'liberar', 'op@2d')")
    from fastapi.testclient import TestClient

    from dnsanalyzer.api import app
    yield TestClient(app)
    db.close()
    for k, v in antes.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    config._settings = None
    srv.cleanup()


def test_liberar_editar_e_revogar(api):
    tid = next(t["id"] for t in api.get("/tenants", headers=H).json() if t["name"] == "Empresa A")
    r = api.put("/console/ip-servicos", headers=H, json={"ip": "10.1.2.3", "slug": "youtube", "tenant_id": tid, "filial": "Matriz",
                                                         "usuario": "João", "autorizado_por": "Maria", "by": "op@2d"})
    assert r.json() == {"ok": True, "ip": "10.1.2.3/32", "slug": "youtube", "novo": True}
    api.put("/console/ip-servicos", headers=H, json={"ip": "10.1.2.0/24", "slug": "spotify", "autorizado_por": "Ana", "by": "op@2d"})
    todos = api.get("/console/ip-servicos", headers=H).json()
    assert [(x["ip"], x["slug"]) for x in todos] == [("10.1.2.0/24", "spotify"), ("10.1.2.3/32", "youtube")]
    so = api.get("/console/ip-servicos", headers=H, params={"slug": "youtube"}).json()
    assert len(so) == 1 and so[0]["tenant_name"] == "Empresa A" and so[0]["usuario"] == "João" and so[0]["created_by"] == "op@2d"

    # editar: sem "autorizado por" mantém o que havia
    r = api.put("/console/ip-servicos", headers=H, json={"ip": "10.1.2.3/32", "slug": "youtube", "tenant_id": tid, "usuario": "José",
                                                         "by": "outro@2d"})
    assert r.json()["novo"] is False
    so = api.get("/console/ip-servicos", headers=H, params={"slug": "youtube"}).json()[0]
    assert so["usuario"] == "José" and so["autorizado_por"] == "Maria" and so["updated_by"] == "outro@2d" and so["filial"] is None

    assert api.delete("/console/ip-servicos", headers=H, params={"ip": "10.1.2.3", "slug": "youtube", "by": "op@2d"}).json()["removed"] == 1
    assert api.delete("/console/ip-servicos", headers=H, params={"ip": "10.1.2.3", "slug": "youtube"}).json()["removed"] == 0
    assert api.get("/console/ip-servicos", headers=H, params={"slug": "youtube"}).json() == []


def test_historico_separado_do_dos_ips_liberados(api):
    log = api.get("/console/liberados-log", headers=H, params={"servico": "youtube"}).json()
    assert [(h["acao"], h["ip"], h["por"], h["autorizado_por"]) for h in log] == [
        ("revogar", "10.1.2.3/32", "op@2d", "Maria"), ("editar", "10.1.2.3/32", "outro@2d", "Maria"),
        ("liberar", "10.1.2.3/32", "op@2d", "Maria")]
    assert log[-1]["detalhe"] == {"servico": "youtube", "filial": "Matriz", "usuario": "João"} and log[-1]["tenant_name"] == "Empresa A"
    isencoes = api.get("/console/liberados-log", headers=H).json()
    assert [(h["ip"], h["acao"]) for h in isencoes] == [("10.9.9.9/32", "liberar")], "o histórico dos IPs liberados não mistura"


def test_recusas(api):
    assert api.put("/console/ip-servicos", headers=H, json={"ip": "abc", "slug": "youtube"}).status_code == 400
    assert api.put("/console/ip-servicos", headers=H, json={"ip": "10.1.2.3", "slug": "nao-existe"}).status_code == 404
    assert api.put("/console/ip-servicos", headers=H, json={"ip": "10.1.2.3", "slug": "youtube", "tenant_id": 99999}).status_code == 404


def test_apagar_o_servico_leva_os_ips_dele(api):
    assert [x["slug"] for x in api.get("/console/ip-servicos", headers=H).json()] == ["spotify"]
    api.delete("/liberacao/spotify", headers=H)
    assert api.get("/console/ip-servicos", headers=H).json() == []
