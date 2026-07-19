from apisec.checks.base import Check, Finding, Severity
from apisec.checks.bola import BolaCheck
from apisec.checks.broken_auth import BrokenAuthCheck
from apisec.checks.excessive_data_exposure import ExcessiveDataExposureCheck
from apisec.checks.mass_assignment import MassAssignmentCheck
from apisec.checks.missing_auth import MissingAuthCheck

ALL_CHECKS: list[Check] = [
    BrokenAuthCheck(),
    MissingAuthCheck(),
    BolaCheck(),
    ExcessiveDataExposureCheck(),
    MassAssignmentCheck(),
]

__all__ = ["ALL_CHECKS", "Check", "Finding", "Severity"]
