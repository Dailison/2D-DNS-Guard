from dnsanalyzer.ti import parse_line, signature


def test_hosts_format():
    assert parse_line("hosts", "127.0.0.1\tEvil.Example.com") == "evil.example.com"
    assert parse_line("hosts", "0.0.0.0 localhost") is None
    assert parse_line("hosts", "# comentário") is None


def test_adblock_format():
    assert parse_line("adblock", "||bad-domain.xyz^") == "bad-domain.xyz"
    assert parse_line("adblock", "||*.wild.com^") is None          # curinga: ignora
    assert parse_line("adblock", "||x.com^$denyallow=y.com") is None  # regra condicional
    assert parse_line("adblock", "! Title: lista") is None


def test_plain_format():
    assert parse_line("plain", "phish-login-secure.top") == "phish-login-secure.top"
    assert parse_line("plain", "") is None


def test_platform_entries_are_dropped():
    # listar a plataforma não torna todos os clientes dela maliciosos
    assert parse_line("plain", "s3.us-east-1.amazonaws.com") is None
    assert parse_line("adblock", "||github.io^") is None
    assert parse_line("plain", "com.br") is None


def test_tld_list():
    assert parse_line("tld_adblock", "||*.zip^") == "zip"
    assert parse_line("tld_adblock", "||*.africa^$denyallow=nation.africa") == "africa"
    assert parse_line("tld_adblock", "||example.com^") is None


def test_signature():
    assert signature([{"source": "b"}, {"source": "a"}, {"source": "a"}]) == "a,b"
    assert signature([]) == ""
