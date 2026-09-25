import ipaddress
from datetime import datetime, timezone

from dnsanalyzer.collector import aggregate
from dnsanalyzer.technitium import parse_ts

S = datetime(2026, 9, 24, 10, 0, tzinfo=timezone.utc)
E = datetime(2026, 9, 24, 11, 30, tzinfo=timezone.utc)


def e(ts, ip="10.70.20.9", q="www.facebook.com", rt="Recursive", rc="NoError"):
    return {"timestamp": ts, "clientIpAddress": ip, "qname": q, "responseType": rt, "rcode": rc}


def test_parse_ts_7_digits():
    t = parse_ts("2026-09-23T02:24:48.9617347Z")
    assert t.tzinfo is not None and t.microsecond == 961734


def test_window_is_half_open():
    ents = [e("2026-09-24T10:00:00Z"), e("2026-09-24T11:30:00Z"), e("2026-09-24T09:59:59Z")]
    ag = aggregate(ents, S, E)
    assert sum(a.queries for a in ag.values()) == 1   # só o do início (inclusivo)


def test_hour_buckets_and_counters():
    ents = [
        e("2026-09-24T10:05:00.1Z"), e("2026-09-24T10:55:00Z", rt="Blocked"),
        e("2026-09-24T11:10:00Z", rc="NxDomain"), e("2026-09-24T11:12:00Z", ip="10.70.20.10"),
    ]
    ag = aggregate(ents, S, E)
    k10 = ("10.70.20.9", "www.facebook.com", datetime(2026, 9, 24, 10, tzinfo=timezone.utc))
    k11 = ("10.70.20.9", "www.facebook.com", datetime(2026, 9, 24, 11, tzinfo=timezone.utc))
    assert ag[k10].queries == 2 and ag[k10].blocked == 1
    assert ag[k11].queries == 1 and ag[k11].nxdomain == 1
    assert len(ag) == 3


def test_excluded_clients():
    ents = [e("2026-09-24T10:05:00Z", ip="10.100.10.4"), e("2026-09-24T10:06:00Z")]
    ag = aggregate(ents, S, E, [ipaddress.ip_network("10.100.10.4/32")])
    assert sum(a.queries for a in ag.values()) == 1


def test_normalizes_qname():
    ag = aggregate([e("2026-09-24T10:05:00Z", q="WWW.Facebook.COM.")], S, E)
    assert list(ag)[0][1] == "www.facebook.com"


def test_control_chars_in_qname_are_escaped():
    # NUL no nome travava a coleta (PostgreSQL recusa 0x00 em texto)
    ag = aggregate([e("2026-09-24T10:05:00Z", q="bad\x00name.com")], S, E)
    assert list(ag)[0][1] == "bad\\x00name.com"
