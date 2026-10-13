"""La Fase 8 retira por completo el namespace HTTP histórico /tools."""

import pytest


@pytest.mark.parametrize(
    ("method", "route"),
    [
        ("get", "/tools/dolost/activity"),
        ("get", "/tools/dolost/docker"),
        ("post", "/tools/dolost/docker"),
        ("get", "/tools/buda/settings"),
        ("post", "/tools/buda/settings"),
        ("post", "/tools/buda/settings/reset"),
        ("get", "/tools/buda/statistics"),
        ("get", "/tools/buda/activities"),
        ("post", "/tools/buda/activities"),
        ("post", "/tools/buda/activities/generate"),
        ("get", "/tools/buda/activities/42/edit"),
        ("post", "/tools/buda/activities/42/edit"),
        ("post", "/tools/buda/activities/42/delete"),
        ("get", "/tools/buda/user_profiles"),
        ("post", "/tools/buda/user_profiles"),
        ("get", "/tools/buda/user_profiles/42/edit"),
        ("post", "/tools/buda/user_profiles/42/edit"),
        ("post", "/tools/buda/user_profiles/42/delete"),
        ("get", "/tools/buda/context"),
        ("post", "/tools/buda/context/upload"),
        ("post", "/tools/buda/context/delete"),
    ],
)
def test_retired_tools_routes_return_404_without_redirect(client, method, route):
    response = getattr(client, method)(route, data={"confirmation": "REINICIAR DATOS"})

    assert response.status_code == 404
    assert "Location" not in response.headers
