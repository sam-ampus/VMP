"""Closed vocabularies for the canonical schema."""

from enum import StrEnum


class LocusType(StrEnum):
    HOST = "host"
    PACKAGE = "package"
    ENDPOINT = "endpoint"


class ScanType(StrEnum):
    AUTHENTICATED_NETWORK = "authenticated_network"
    UNAUTHENTICATED_NETWORK = "unauthenticated_network"
    SCA = "sca"
    CONTAINER_IMAGE = "container_image"
    DAST = "dast"
    DAST_AGENTIC = "dast_agentic"
    SAST = "sast"
    UNKNOWN = "unknown"


class Protocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"


class HttpMethod(StrEnum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class ParameterLocation(StrEnum):
    QUERY = "query"
    BODY = "body"
    PATH = "path"
    HEADER = "header"
    COOKIE = "cookie"


class FixStatus(StrEnum):
    """Trivy's vocabulary, which is the most complete of the package scanners."""

    FIXED = "fixed"
    AFFECTED = "affected"
    WILL_NOT_FIX = "will_not_fix"
    FIX_DEFERRED = "fix_deferred"
    END_OF_LIFE = "end_of_life"
    NOT_AFFECTED = "not_affected"
    UNDER_INVESTIGATION = "under_investigation"
    UNKNOWN = "unknown"


class NormalisedSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    """How far a finding was validated. Mirror's four tiers, plus the scanner default."""

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POTENTIAL = "potential"
    UNTESTED = "untested"
    UNVALIDATED = "unvalidated"


class ConfidenceSource(StrEnum):
    TOOL_ASSERTED = "tool_asserted"
    DEFAULT_FOR_TOOL_CLASS = "default_for_tool_class"
    ANALYST = "analyst"


class EvidenceCompleteness(StrEnum):
    FULL = "full"
    PARTIAL = "partial"
    NONE = "none"


class CvssVersion(StrEnum):
    V2_0 = "2.0"
    V3_0 = "3.0"
    V3_1 = "3.1"
    V4_0 = "4.0"


class CvssSelectionRule(StrEnum):
    """Which precedence tier chose the CVSS value (locked decision 1).

    OS packages: distro first. Otherwise: NVD, then the issuing CNA, then the tool.
    """

    DISTRO = "distro"
    NVD = "nvd"
    CNA = "cna"
    TOOL = "tool"


class CvssSourceKind(StrEnum):
    """Who scored a CVE, for locked decision 1's precedence: NVD, then the issuing CNA."""

    NVD = "nvd"
    CNA = "cna"
    OTHER = "other"  # e.g. CISA ADP


class ClosureReason(StrEnum):
    FIXED = "fixed"
    FALSE_POSITIVE = "false_positive"
    RISK_ACCEPTED = "risk_accepted"


class VulnerabilityStatus(StrEnum):
    OPEN = "open"
    CLOSED = "closed"


class AssetCriticality(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Environment(StrEnum):
    PRODUCTION = "production"
    NON_PRODUCTION = "non_production"


class ScoreBand(StrEnum):
    LOW = "low"
    MODERATE = "moderate"
    ELEVATED = "elevated"
    VERY_HIGH = "very_high"


class FactorDirection(StrEnum):
    UP = "up"
    DOWN = "down"


class FactorSource(StrEnum):
    """Where a factor's value came from. 'agent' values are evidence, never the score."""

    TOOL = "tool"
    INTEL = "intel"
    INVENTORY = "inventory"
    AGENT = "agent"
    RULE = "rule"


class FPMechanism(StrEnum):
    """False-positive logic is selected by locus type, never shared across shapes."""

    VERSION_RANGE = "version_range"  # host
    DETERMINISTIC_VERSION = "deterministic_version"  # package
    CONFIDENCE_REACHABILITY = "confidence_reachability"  # endpoint


class FPBand(StrEnum):
    CONFIRMED_APPLICABLE = "confirmed_applicable"
    CONFIRMED_NOT_APPLICABLE = "confirmed_not_applicable"
    LOW_LIKELIHOOD = "low_likelihood"
    NEEDS_REVIEW = "needs_review"
    LIKELY_FALSE_POSITIVE = "likely_false_positive"


class FixType(StrEnum):
    VERSION_BUMP = "version_bump"
    PATCH = "patch"
    CONFIG_CHANGE = "config_change"
    CODE_CHANGE = "code_change"
    SECRET_ROTATION = "secret_rotation"
    REBUILD = "rebuild"
    HOST_UPGRADE = "host_upgrade"
    DECOMMISSION = "decommission"


class SharedBasisKind(StrEnum):
    """What a remediation action's findings have in common. Code checks this claim."""

    HOST = "host"
    IMAGE = "image"
    ROUTE = "route"
    APPLICATION = "application"
    PACKAGE = "package"
