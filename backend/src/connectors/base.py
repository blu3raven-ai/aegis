"""Type aliases, result dataclasses, and abstract bases for the connectors kernel."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar, Literal

ConnectorKind = Literal["sender", "ingester", "runner", "wizard"]
ConnectorStatus = Literal["stable", "beta", "preview", "deprecated"]
ConnectorCategory = Literal["ci", "notification", "runner", "intel"]


@dataclass
class TestResult:
    """Outcome of `BaseConnector.test()` — minimal liveness check result."""
    # Tell pytest not to try collecting this as a test class. ClassVar so
    # the dataclass machinery treats it as a class attribute, not a field.
    __test__: ClassVar[bool] = False

    ok: bool
    message: str | None = None


@dataclass
class SendResult:
    """Outcome of a single `BaseSender.send()` call.

    Senders must catch exceptions and return SendResult(success=False, ...)
    rather than raising — failures are recorded by the dispatcher and may
    be retried via the kernel's `with_retry` helper.
    """
    __test__: ClassVar[bool] = False  # pytest collection silencer (starts with 'S' but kept defensive)
    success: bool
    response_code: int | None = None
    error: str | None = None


class BaseConnector(ABC):
    """Common metadata + lifecycle shared by every connector kind.

    Class-level attributes are read by the catalog without instantiation.
    Subclasses must set every metadata attribute and implement `test`.
    """

    id: ClassVar[str]
    name: ClassVar[str]
    kind: ClassVar[ConnectorKind]
    category: ClassVar[ConnectorCategory]
    description: ClassVar[str]
    version: ClassVar[str]
    status: ClassVar[ConnectorStatus]
    icon_slug: ClassVar[str]
    href: ClassVar[str | None] = None

    @abstractmethod
    def test(self) -> TestResult:
        """Verify the connector is reachable / its config decodes."""


class BaseSender(BaseConnector):
    """Outbound: deliver a notification to a destination.

    Senders are stateless — config is supplied per-call by the dispatcher
    from the destination record. Senders must catch all exceptions and
    return a SendResult; raising propagates up and aborts the dispatch
    loop, which the dispatcher cannot recover from cleanly.
    """
    kind: ClassVar[ConnectorKind] = "sender"

    @abstractmethod
    def send(self, payload: dict, config: dict) -> SendResult:
        """Deliver `payload` to the destination described by `config`."""


class BaseIngester(BaseConnector):
    """Inbound: receive a webhook, verify it, normalize it.

    `verify_signature` lets each ingester pick the right primitive
    (`verify_hmac_sha256` or `verify_token_eq`) — the handler stays
    algorithm-agnostic. Concrete implementations resolve the shared
    secret DB-first (per-provider `webhook_endpoints` rows) and fall
    back to the legacy env-var for bootstrap deployments — see
    `src.connectors.webhooks.secret_resolver`.
    """
    kind: ClassVar[ConnectorKind] = "ingester"

    @abstractmethod
    def signature_header(self) -> str:
        """Name of the HTTP header carrying the signature/token."""

    @abstractmethod
    def verify_signature(self, body: bytes, header: str) -> bool:
        """Return True iff the body is authentic given the header value."""

    @abstractmethod
    def normalize(self, body: bytes) -> object:
        """Parse the raw body into a domain event object."""


class BaseRunner(BaseConnector):
    """Catalog-only base for the federated-runner subsystem.

    `BaseRunner` deliberately omits send/ingest verbs. The runner protocol
    (workers, queue, heartbeat) stays in backend/src/runner/ unchanged;
    this class exists so the runner shows up in the catalog uniformly.
    """
    kind: ClassVar[ConnectorKind] = "runner"


class BaseWizard(BaseConnector):
    """Catalog-only base for setup wizards (e.g. CI YAML generators).

    Like BaseRunner, wizards have no runtime lifecycle verbs in the kernel —
    they exist so the integrations marketplace can surface user-setup
    integrations that don't fit sender / ingester / runner semantics.
    """
    kind: ClassVar[ConnectorKind] = "wizard"
