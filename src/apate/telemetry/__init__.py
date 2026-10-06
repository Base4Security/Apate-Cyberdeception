"""Telemetria y correlacion (M4) - ver documento de diseno, seccion 4.3."""

from .classifications import (
    JSONFileTlpClassificationRepository,
    TlpClassification,
    TlpClassificationRepository,
    TlpLevel,
    ioc_subject_key,
)
from .collector import TelemetryCollector
from .exceptions import ExternalTelemetryError
from .external_bridge import ExternalTelemetryBridge
from .incidents import Incident, IncidentRepository, JSONFileIncidentRepository
from .models import IoC, TelemetryRecord
from .repository import JSONFileTelemetryRepository, TelemetryRepository
from .sqlite_repository import SQLiteTelemetryRepository
from .virustotal import (
    JSONFileVirusTotalEnrichmentRepository,
    PrivateIoCError,
    SUPPORTED_IOC_TYPES,
    VirusTotalConfigRepository,
    VirusTotalEnrichment,
    VirusTotalEnrichmentRepository,
    query_virustotal,
)

__all__ = [
    "ExternalTelemetryBridge",
    "ExternalTelemetryError",
    "Incident",
    "IncidentRepository",
    "IoC",
    "JSONFileIncidentRepository",
    "JSONFileTelemetryRepository",
    "JSONFileTlpClassificationRepository",
    "JSONFileVirusTotalEnrichmentRepository",
    "PrivateIoCError",
    "SQLiteTelemetryRepository",
    "TelemetryCollector",
    "TelemetryRecord",
    "TelemetryRepository",
    "TlpClassification",
    "TlpClassificationRepository",
    "TlpLevel",
    "SUPPORTED_IOC_TYPES",
    "VirusTotalConfigRepository",
    "VirusTotalEnrichment",
    "VirusTotalEnrichmentRepository",
    "ioc_subject_key",
    "query_virustotal",
]
