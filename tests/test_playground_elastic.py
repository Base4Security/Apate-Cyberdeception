import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
from urllib.error import URLError

import pytest

from apate.playground.elastic import DEFAULT_ELASTIC_URL, ELASTIC_INDEX, fetch_recent_hits
from apate.playground.exceptions import PlaygroundCommandError


def _fake_response(body: dict) -> MagicMock:
    response = MagicMock()
    response.read.return_value = json.dumps(body).encode("utf-8")
    response.__enter__.return_value = response
    response.__exit__.return_value = False
    return response


def test_fetch_recent_hits_queries_default_index_with_timestamp_filter():
    since = datetime(2026, 8, 6, 10, 0, tzinfo=timezone.utc)
    body = {"hits": {"hits": [{"_source": {"event_type": "ssh_connection"}}]}}

    with patch("apate.playground.elastic.urllib.request.urlopen", return_value=_fake_response(body)) as mock_urlopen:
        hits = fetch_recent_hits(since=since)

    assert hits == [{"_source": {"event_type": "ssh_connection"}}]
    request = mock_urlopen.call_args[0][0]
    assert request.full_url == f"{DEFAULT_ELASTIC_URL}/{ELASTIC_INDEX}/_search"
    sent_query = json.loads(request.data)
    # @timestamp, no timestamp: confirmado contra un indice real que el
    # campo "timestamp" esta ausente en la inmensa mayoria de los
    # documentos (logs de MySQL, ~99.8% del volumen), asi que un filtro
    # de rango sobre ese campo los excluia en silencio -- @timestamp lo
    # agrega Filebeat en la ingesta, presente siempre (ver docstring de
    # elastic.py).
    assert sent_query["query"]["range"]["@timestamp"]["gte"] == since.isoformat()
    assert sent_query["sort"] == [{"@timestamp": "asc"}]


def test_fetch_recent_hits_uses_custom_elastic_url_and_index():
    since = datetime(2026, 8, 6, tzinfo=timezone.utc)
    body = {"hits": {"hits": []}}

    with patch("apate.playground.elastic.urllib.request.urlopen", return_value=_fake_response(body)) as mock_urlopen:
        fetch_recent_hits(elastic_url="http://es.example:9200", index="otro-indice-*", since=since)

    request = mock_urlopen.call_args[0][0]
    assert request.full_url == "http://es.example:9200/otro-indice-*/_search"


def test_fetch_recent_hits_returns_empty_list_when_no_hits():
    since = datetime(2026, 8, 6, tzinfo=timezone.utc)
    body = {"hits": {"hits": []}}

    with patch("apate.playground.elastic.urllib.request.urlopen", return_value=_fake_response(body)):
        hits = fetch_recent_hits(since=since)

    assert hits == []


def test_fetch_recent_hits_wraps_connection_error():
    since = datetime(2026, 8, 6, tzinfo=timezone.utc)

    with patch("apate.playground.elastic.urllib.request.urlopen", side_effect=URLError("conexion rechazada")):
        with pytest.raises(PlaygroundCommandError):
            fetch_recent_hits(since=since)


def test_fetch_recent_hits_default_timestamp_field_is_at_timestamp():
    """Sin pasar `timestamp_field`, el comportamiento del Playground no
    cambia -- generalizado en apate.telemetry.external_bridge (ver
    docstring de fetch_recent_hits())."""

    since = datetime(2026, 8, 6, tzinfo=timezone.utc)
    body = {"hits": {"hits": []}}

    with patch("apate.playground.elastic.urllib.request.urlopen", return_value=_fake_response(body)) as mock_urlopen:
        fetch_recent_hits(since=since)

    sent_query = json.loads(mock_urlopen.call_args[0][0].data)
    assert sent_query["query"]["range"]["@timestamp"]["gte"] == since.isoformat()
    assert sent_query["sort"] == [{"@timestamp": "asc"}]


def test_fetch_recent_hits_uses_custom_timestamp_field():
    """Una fuente externa (T-Pot u otra) no tiene por que llamar a su
    campo de timestamp igual que el Playground -- ver
    apate.telemetry.external_bridge."""

    since = datetime(2026, 8, 6, tzinfo=timezone.utc)
    body = {"hits": {"hits": []}}

    with patch("apate.playground.elastic.urllib.request.urlopen", return_value=_fake_response(body)) as mock_urlopen:
        fetch_recent_hits(since=since, timestamp_field="event.created")

    sent_query = json.loads(mock_urlopen.call_args[0][0].data)
    assert sent_query["query"]["range"] == {"event.created": {"gte": since.isoformat()}}
    assert sent_query["sort"] == [{"event.created": "asc"}]
    assert "@timestamp" not in sent_query["query"]["range"]
