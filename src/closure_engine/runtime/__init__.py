"""Shipped ACE operating runtime: persistent role identities, enrollment, brokered HTTP
deployment, independent observation, custody, deterministic close and verified recovery."""

from .clock import SystemClock
from .deployment import Deployment, enroll, enroll_target
from .identities import ROLES, init_identity, load_identity
from .service import Runtime, artifact_bytes
from .target import ReferenceTarget, ReferenceTargetServer, TargetClient

__all__ = [
    "ROLES",
    "Deployment",
    "ReferenceTarget",
    "ReferenceTargetServer",
    "Runtime",
    "SystemClock",
    "TargetClient",
    "artifact_bytes",
    "enroll",
    "enroll_target",
    "init_identity",
    "load_identity",
]
