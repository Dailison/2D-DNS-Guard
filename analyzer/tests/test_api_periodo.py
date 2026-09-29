from datetime import datetime, timedelta, timezone

from dnsanalyzer import api


def test_periodo_em_dias():
    since, ativo = api._periodo(7, None)
    assert ativo is None
    assert abs((datetime.now(timezone.utc) - since) - timedelta(days=7)) < timedelta(seconds=5)


def test_ultima_hora_pega_as_horas_cheias_que_cobrem_a_janela():
    """(29/09) query_agg é por hora cheia: a janela de 1 h começa no bucket da hora anterior e filtra por last_seen."""
    since, ativo = api._periodo(7, 1)
    agora = datetime.now(timezone.utc)
    assert abs((agora - ativo) - timedelta(hours=1)) < timedelta(seconds=5)
    assert since == ativo.replace(minute=0, second=0, microsecond=0) and since <= ativo


def test_horas_limitadas_a_24():
    since, ativo = api._periodo(1, 500)
    assert abs((datetime.now(timezone.utc) - ativo) - timedelta(hours=24)) < timedelta(seconds=5)
