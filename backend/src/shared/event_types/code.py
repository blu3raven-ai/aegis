"""Code-change event types (push, image push, PR, file save, manual rescan)."""
from __future__ import annotations

from typing import Literal

from src.shared.event_types.base import Event


class CodePushEvent(Event):
    event_type: Literal["code.push"] = "code.push"


class ImagePushEvent(Event):
    event_type: Literal["code.image_push"] = "code.image_push"


class PrOpenedEvent(Event):
    event_type: Literal["code.pr_opened"] = "code.pr_opened"


class PrUpdatedEvent(Event):
    event_type: Literal["code.pr_updated"] = "code.pr_updated"


class FileSaveEvent(Event):
    event_type: Literal["code.file_save"] = "code.file_save"


class ManualRescanEvent(Event):
    event_type: Literal["code.manual_rescan"] = "code.manual_rescan"
