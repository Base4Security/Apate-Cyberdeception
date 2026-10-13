from __future__ import annotations

from datetime import datetime, timezone

import pytest

from apate.deployment import (
    ActiveDirectoryHoneyuserConnector,
    ActiveDirectoryLogonEvent,
    ActiveDirectoryUser,
    DeploymentAction,
    DeploymentService,
    DeploymentStatus,
    DeploymentTarget,
    DeploymentValidationError,
    HoneyuserEventMonitor,
    JSONFileDeploymentRepository,
    JSONFileHoneyuserCheckpointRepository,
    MappingCredentialStore,
)
from apate.plugins import EventBus, EventType
from apate.telemetry import JSONFileTelemetryRepository, TelemetryCollector


ADMIN_REF = "secret://ad/admin"


class FakeActiveDirectoryTransport:
    def __init__(self) -> None:
        self.users: dict[str, ActiveDirectoryUser] = {}
        self.events: list[ActiveDirectoryLogonEvent] = []
        self.validations = 0
        self.passwords: list[str] = []

    def validate(self, target, credential, ou_dn):
        assert credential["username"] == "DOMAIN\\svc-apate"
        assert ou_dn == "OU=Deception,DC=example,DC=test"
        self.validations += 1

    def find_user(self, target, credential, sam_account_name):
        return self.users.get(sam_account_name.casefold())

    def create_or_update_user(self, target, credential, parameters, password):
        self.passwords.append(password)
        existing = self.find_user(target, credential, parameters["sam_account_name"])
        sid = existing.sid if existing else "S-1-5-21-100-200-300-1101"
        user = ActiveDirectoryUser(
            sid=sid,
            distinguished_name=f"CN={parameters['display_name']},{parameters['ou_dn']}",
            sam_account_name=parameters["sam_account_name"],
            user_principal_name=parameters["user_principal_name"],
            description=parameters["management_marker"],
            enabled=True,
        )
        self.users[user.sam_account_name.casefold()] = user
        return user

    def get_user(self, target, credential, identity):
        for user in self.users.values():
            if identity.casefold() in {user.sid.casefold(), user.sam_account_name.casefold()}:
                return user
        return None

    def set_password_and_enable(self, target, credential, identity, password):
        self.passwords.append(password)
        user = self.get_user(target, credential, identity)
        assert user is not None
        updated = ActiveDirectoryUser(**{**user.__dict__, "enabled": True})
        self.users[user.sam_account_name.casefold()] = updated
        return updated

    def disable_user(self, target, credential, identity):
        user = self.get_user(target, credential, identity)
        assert user is not None
        updated = ActiveDirectoryUser(**{**user.__dict__, "enabled": False})
        self.users[user.sam_account_name.casefold()] = updated
        return updated

    def logon_events(self, target, credential, *, sam_account_name, sid, after_record_id):
        return [event for event in self.events if event.record_id > after_record_id]


def _target(**config_overrides):
    config = {
        "ou_allowlist": ["OU=Deception,DC=example,DC=test"],
        "allowed_upn_suffixes": ["example.test"],
    }
    config.update(config_overrides)
    return DeploymentTarget(
        name="AD de laboratorio",
        connector_kind="active-directory-honeyuser",
        address="dc.example.test",
        credential_ref=ADMIN_REF,
        config=config,
    )


def _configuration(**overrides):
    values = {
        "sam_account_name": "laura.fernandez",
        "display_name": "Laura Fernández",
        "given_name": "Laura",
        "surname": "Fernández",
        "ou_dn": "OU=Deception,DC=example,DC=test",
        "upn_suffix": "example.test",
    }
    values.update(overrides)
    return values


def _stack(tmp_path):
    store = MappingCredentialStore(
        {ADMIN_REF: {"username": "DOMAIN\\svc-apate", "password": "AdminSecret!1"}}
    )
    transport = FakeActiveDirectoryTransport()
    passwords = iter(["GeneratedSecret!1Aa", "RotatedSecret!2Bb"])
    connector = ActiveDirectoryHoneyuserConnector(
        credential_store=store,
        transport=transport,
        password_factory=lambda: next(passwords),
    )
    repository = JSONFileDeploymentRepository(tmp_path / "deployments")
    service = DeploymentService(repository=repository, connectors={connector.kind: connector})
    return service, connector, transport, store, repository


@pytest.mark.parametrize(
    "override,expected",
    [
        ({"sam_account_name": "bad user"}, "sAMAccountName"),
        ({"display_name": ""}, "display_name"),
        ({"ou_dn": "OU=Users,DC=example,DC=test"}, "allowlist"),
        ({"upn_suffix": "evil.test"}, "UPN"),
    ],
)
def test_validation_rejects_values_outside_the_explicit_scope(tmp_path, override, expected):
    service, _connector, _transport, _store, _repository = _stack(tmp_path)
    with pytest.raises(DeploymentValidationError, match=expected):
        service.prepare(
            operation_id="op-1", plugin_id="honeyuser-1", target=_target(), configuration=_configuration(**override)
        )


@pytest.mark.parametrize("ttl", [59, 86401, "invalid"])
def test_validation_rejects_unsafe_plan_expiration(tmp_path, ttl):
    service, _connector, transport, _store, _repository = _stack(tmp_path)
    with pytest.raises(DeploymentValidationError, match="plan_ttl_seconds"):
        service.prepare(
            operation_id="op-1",
            plugin_id="honeyuser-1",
            target=_target(plan_ttl_seconds=ttl),
            configuration=_configuration(),
        )
    assert transport.validations == 0


def test_plan_then_deploy_persists_sid_and_keeps_password_out_of_the_plan(tmp_path):
    service, _connector, transport, store, _repository = _stack(tmp_path)
    plan = service.prepare(
        operation_id="op-1", plugin_id="honeyuser-1", target=_target(), configuration=_configuration()
    )

    assert plan.changes[0].action is DeploymentAction.CREATE
    assert transport.validations == 1
    assert (plan.valid_until - plan.created_at).total_seconds() == 900
    assert "password" not in str(plan.to_dict()).lower()
    assert plan.parameters["honeyuser_credential_ref"].startswith("secret://deployment/")

    record = service.execute(plan.id)

    assert record.status is DeploymentStatus.ACTIVE
    assert record.external_resource_ids[0].startswith("sid:S-1-5-")
    honey_credential = store.get(plan.parameters["honeyuser_credential_ref"])
    assert honey_credential["password"] == "GeneratedSecret!1Aa"
    assert "GeneratedSecret!1Aa" not in str(plan.to_dict())
    assert "GeneratedSecret!1Aa" not in str(record.to_dict())


def test_existing_unmanaged_account_is_never_adopted(tmp_path):
    service, _connector, transport, _store, _repository = _stack(tmp_path)
    transport.users["laura.fernandez"] = ActiveDirectoryUser(
        "S-1-5-21-100", "CN=Laura,OU=Users,DC=example,DC=test", "laura.fernandez",
        "laura.fernandez@example.test", "Cuenta real", True,
    )

    with pytest.raises(DeploymentValidationError, match="no pertenece"):
        service.prepare(
            operation_id="op-1", plugin_id="honeyuser-1", target=_target(), configuration=_configuration()
        )


def test_full_lifecycle_reconciles_rotates_and_disables_instead_of_deleting(tmp_path):
    service, _connector, transport, store, repository = _stack(tmp_path)
    plan = service.prepare(
        operation_id="op-1", plugin_id="honeyuser-1", target=_target(), configuration=_configuration()
    )
    deployed = service.execute(plan.id)

    assert service.refresh(deployed.id).status is DeploymentStatus.ACTIVE
    assert service.rotate(deployed.id).status is DeploymentStatus.ACTIVE
    assert store.get(plan.parameters["honeyuser_credential_ref"])["password"] == "RotatedSecret!2Bb"
    retired = service.retire(deployed.id)

    assert retired.status is DeploymentStatus.RETIRED
    assert transport.users["laura.fernandez"].enabled is False
    assert repository.get_record(deployed.id).status is DeploymentStatus.RETIRED
    assert service.refresh(deployed.id).status is DeploymentStatus.RETIRED


def test_refresh_detects_if_the_account_was_moved_outside_the_authorized_ou(tmp_path):
    service, _connector, transport, _store, _repository = _stack(tmp_path)
    plan = service.prepare(
        operation_id="op-1", plugin_id="honeyuser-1", target=_target(), configuration=_configuration()
    )
    record = service.execute(plan.id)
    current = transport.users["laura.fernandez"]
    transport.users["laura.fernandez"] = ActiveDirectoryUser(
        **{**current.__dict__, "distinguished_name": "CN=Laura,OU=Real,DC=example,DC=test"}
    )

    refreshed = service.refresh(record.id)

    assert refreshed.status is DeploymentStatus.DEGRADED
    assert "OU" in refreshed.detail


def test_monitor_publishes_4624_and_4625_once_and_telemetry_promotes_source_ip(tmp_path):
    service, connector, transport, _store, repository = _stack(tmp_path)
    plan = service.prepare(
        operation_id="op-1", plugin_id="honeyuser-1", target=_target(), configuration=_configuration()
    )
    record = service.execute(plan.id)
    transport.events = [
        ActiveDirectoryLogonEvent(
            10, 4624, datetime(2026, 9, 13, 12, tzinfo=timezone.utc), "laura.fernandez",
            "S-1-5-21-100-200-300-1101", "203.0.113.8", "WS-44", "3", "0x0",
        ),
        ActiveDirectoryLogonEvent(
            11, 4625, datetime(2026, 9, 13, 12, 1, tzinfo=timezone.utc), "laura.fernandez",
            "S-1-5-21-100-200-300-1101", "203.0.113.9", "WS-45", "3", "0xc000006a",
        ),
    ]
    bus = EventBus()
    collector = TelemetryCollector(
        repository=JSONFileTelemetryRepository(tmp_path / "telemetry"), bus=bus
    )
    checkpoints = JSONFileHoneyuserCheckpointRepository(tmp_path / "checkpoints")
    monitor = HoneyuserEventMonitor(connector=connector, checkpoint_repository=checkpoints)

    first = monitor.poll(record, repository.get_plan(plan.id), bus)
    second = monitor.poll(record, repository.get_plan(plan.id), bus)

    assert [event.payload["event_id"] for event in first] == [4624, 4625]
    assert first[0].payload["kind"] == "honeyuser_authentication_success"
    assert first[0].payload["ttp_id"] == "T1078"
    assert first[1].payload["kind"] == "honeyuser_authentication_failure"
    assert "ttp_id" not in first[1].payload
    assert second == []
    assert checkpoints.get(record.id) == 11
    telemetry = collector.list_events("op-1")
    assert [item.event_type for item in telemetry] == [EventType.INTERACTION, EventType.INTERACTION]
    assert telemetry[0].iocs[0].value == "203.0.113.8"


def test_monitor_classifies_kerberos_and_ntlm_success_and_failure(tmp_path):
    service, connector, transport, _store, repository = _stack(tmp_path)
    plan = service.prepare(
        operation_id="op-1", plugin_id="honeyuser-1", target=_target(), configuration=_configuration()
    )
    record = service.execute(plan.id)
    now = datetime(2026, 9, 13, 13, tzinfo=timezone.utc)
    transport.events = [
        ActiveDirectoryLogonEvent(20, 4768, now, "laura.fernandez", "S-1-5-21-100", status="0x0"),
        ActiveDirectoryLogonEvent(21, 4771, now, "laura.fernandez", "S-1-5-21-100", status="0x18"),
        ActiveDirectoryLogonEvent(22, 4776, now, "laura.fernandez", "S-1-5-21-100", status="0xc000006a"),
    ]
    monitor = HoneyuserEventMonitor(
        connector=connector,
        checkpoint_repository=JSONFileHoneyuserCheckpointRepository(tmp_path / "checkpoints"),
    )

    events = monitor.poll(record, repository.get_plan(plan.id), EventBus())

    assert [event.payload["kind"] for event in events] == [
        "honeyuser_authentication_success",
        "honeyuser_authentication_failure",
        "honeyuser_authentication_failure",
    ]
    assert events[0].payload["ttp_id"] == "T1078"


def test_monitor_recovers_when_security_log_record_ids_restart(tmp_path):
    service, connector, transport, _store, repository = _stack(tmp_path)
    plan = service.prepare(
        operation_id="op-1", plugin_id="honeyuser-1", target=_target(), configuration=_configuration()
    )
    record = service.execute(plan.id)
    checkpoints = JSONFileHoneyuserCheckpointRepository(tmp_path / "checkpoints")
    checkpoints.save(record.id, 900)
    event = ActiveDirectoryLogonEvent(
        3,
        4624,
        datetime(2026, 9, 13, 13, tzinfo=timezone.utc),
        "laura.fernandez",
        "S-1-5-21-100-200-300-1101",
        "203.0.113.8",
    )

    # Simula el transporte real, que detecta que el último ID del canal es
    # menor al checkpoint y vuelve a consultar desde cero.
    transport.logon_events = lambda *args, **kwargs: [event]
    events = HoneyuserEventMonitor(
        connector=connector,
        checkpoint_repository=checkpoints,
    ).poll(record, repository.get_plan(plan.id), EventBus())

    assert [item.payload["event_record_id"] for item in events] == [3]
    assert checkpoints.get(record.id) == 3
    assert checkpoints.get_state(record.id) == (3, 1)


def test_log_reset_keeps_source_event_ids_distinct_across_monitor_restart(tmp_path):
    service, connector, transport, _store, repository = _stack(tmp_path)
    plan = service.prepare(operation_id="op-1", plugin_id="honeyuser-1",
                           target=_target(), configuration=_configuration())
    record = service.execute(plan.id)
    path = tmp_path / "checkpoints"
    first_event = ActiveDirectoryLogonEvent(5, 4624, datetime(2026, 9, 13, tzinfo=timezone.utc),
                                           "laura.fernandez", "S-1-5-21-100-200-300-1101")
    transport.events = [first_event]
    first = HoneyuserEventMonitor(connector=connector,
                                 checkpoint_repository=JSONFileHoneyuserCheckpointRepository(path)).poll(
                                     record, repository.get_plan(plan.id), EventBus())
    reset_event = ActiveDirectoryLogonEvent(3, 4624, datetime(2026, 9, 14, tzinfo=timezone.utc),
                                           "laura.fernandez", "S-1-5-21-100-200-300-1101")
    transport.logon_events = lambda *args, **kwargs: [reset_event]
    second_monitor = HoneyuserEventMonitor(connector=connector,
                                          checkpoint_repository=JSONFileHoneyuserCheckpointRepository(path))
    second = second_monitor.poll(record, repository.get_plan(plan.id), EventBus())
    assert first[0].id != second[0].id
    assert second_monitor.poll(record, repository.get_plan(plan.id), EventBus()) == []
    assert JSONFileHoneyuserCheckpointRepository(path).get_state(record.id) == (3, 1)
