from dnsanalyzer.features import analyze_name, dga_score, is_public_suffix, shannon_entropy

INTERNAL = ["local", "in-addr.arpa", "resolver.arpa"]


def test_registrable_simple():
    i = analyze_name("www.Facebook.com.", INTERNAL)
    assert i.kind == "public"
    assert i.registrable == "facebook.com"
    assert i.candidates == ["www.facebook.com", "facebook.com"]
    assert not i.private_suffix


def test_registrable_country_suffix():
    i = analyze_name("nfe.fazenda.gov.br", INTERNAL)
    assert i.registrable == "fazenda.gov.br"
    assert i.tld == "br"


def test_private_suffix_platform_is_unit():
    # site em plataforma compartilhada é a unidade — não a plataforma inteira
    i = analyze_name("evil.github.io", INTERNAL)
    assert i.registrable == "evil.github.io"
    assert i.icann_registrable == "github.io"
    assert i.private_suffix
    # candidatos nunca sobem até a plataforma
    assert "github.io" not in i.candidates


def test_s3_bucket_is_unit():
    i = analyze_name("prologapp.s3.us-east-1.amazonaws.com", INTERNAL)
    assert i.registrable == "prologapp.s3.us-east-1.amazonaws.com"
    assert "s3.us-east-1.amazonaws.com" not in i.candidates


def test_is_public_suffix():
    assert is_public_suffix("s3.us-east-1.amazonaws.com")
    assert is_public_suffix("github.io")
    assert is_public_suffix("com.br")
    assert not is_public_suffix("gravatar.com")


def test_internal_and_reverse_and_ip():
    assert analyze_name("dc01.2d.local", INTERNAL).kind == "internal"
    assert analyze_name("dc01.2d.local", INTERNAL).registrable == "2d.local"
    assert analyze_name("wpad", INTERNAL).kind == "internal"
    assert analyze_name("10.10.100.10.in-addr.arpa", INTERNAL).kind == "reverse"
    assert analyze_name("8.8.8.8", INTERNAL).kind == "ip"
    assert analyze_name("_dns.resolver.arpa", INTERNAL).kind == "internal"


def test_invalid_name():
    assert analyze_name("bad name.com", INTERNAL).kind == "invalid"


def test_entropy_and_dga():
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcd") == 2.0
    assert dga_score("google") == 0.0            # curto
    assert dga_score("microsoft") < 0.3
    assert dga_score("xjq7k2vbz9wpl3mqr8t") > 0.6
    assert dga_score("atualizacaosistema") < 0.45


def test_nome_sem_dominio_de_topo_conhecido_e_interno():
    """22/10: "2084-ms-7.2-7e48.447d59ce-…", "cloud.didi" e "192.168.11.11_1" viravam domínio público (o último rótulo)
    e iam p/ a IA, as listas e a investigação."""
    from dnsanalyzer.features import analyze_name
    for n, reg in (("2084-ms-7.2-7e48.447d59ce-c346-11f1-9d87-58020527b510", "447d59ce-c346-11f1-9d87-58020527b510"),
                   ("cloud.didi", "didi"), ("region.target_domain", "target_domain"), ("447d59ce-c346-11f1-9d87-58020527b510", None)):
        i = analyze_name(n)
        assert i.kind == "internal", (n, i)
        if reg:
            assert i.registrable == reg
    assert analyze_name("www.exemplo.com.br").kind == "public" and analyze_name("api.capcutapi.com").registrable == "capcutapi.com"
