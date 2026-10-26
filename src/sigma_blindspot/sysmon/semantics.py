from collections.abc import Callable
from enum import Enum, StrEnum


class Status(StrEnum):
    DOCUMENTED = "documented"
    ASSUMED = "assumed"
    VERIFIED = "verified"


class Semantic(Enum):
    INCLUDE = Status.DOCUMENTED, "`include` logs only the events that match"
    EXCLUDE = Status.DOCUMENTED, "`exclude` logs every event except those that match"
    EXCLUDE_WINS = Status.DOCUMENTED, "An `exclude` match overrides an `include` match"
    EMPTY_FILTER = (
        Status.DOCUMENTED,
        "An empty `include` logs nothing, an empty `exclude` everything",
    )
    GROUP_RELATION = (
        Status.DOCUMENTED,
        "RuleGroup `groupRelation` sets AND or OR between filter items",
    )
    LEGACY_RELATION = (
        Status.DOCUMENTED,
        "Without RuleGroup, the same field combines with OR and different fields with AND",
    )
    CASE_INSENSITIVE = Status.DOCUMENTED, "Every condition is case-insensitive"
    DEFAULT_CONDITION = Status.DOCUMENTED, "The default condition is `is`"
    LIST_SEPARATOR = Status.DOCUMENTED, "`;` separates the values of the `any` and `all` conditions"
    IMAGE_CONDITION = Status.DOCUMENTED, "`image` matches the full path or the bare image name"
    UNFILTERABLE = Status.DOCUMENTED, "Event IDs 4, 16 and 255 cannot be filtered"
    DISABLED_BY_DEFAULT = (
        Status.DOCUMENTED,
        "Without a filter, NetworkConnect (3) and ImageLoad (7) are not logged",
    )
    LOGGED_BY_DEFAULT = (
        Status.VERIFIED,
        "Without a filter, ProcessCreate (1) and ProcessTerminate (5) are logged "
        "(probe P1, Sysmon 15.22)",
    )
    NOT_LOGGED_BY_DEFAULT = (
        Status.VERIFIED,
        "Without a filter, FileCreateTime (2), ProcessAccess (10), FileCreate (11), "
        "RegistryEvent (12, 13, 14), FileCreateStreamHash (15), PipeEvent (17, 18), "
        "DnsQuery (22), FileDelete (23) and FileExecutableDetected (29) are not logged "
        "(probes P1 and P1 control, Sysmon 15.22)",
    )
    CONDITION_NAME_CASE = (
        Status.ASSUMED,
        "Condition names ignore ASCII case: `Contains` is `contains`",
    )
    LEXICAL_COMPARISON = (
        Status.ASSUMED,
        "`less than` and `more than` compare lower-cased values lexically",
    )
    LITERAL_WHITESPACE = (
        Status.ASSUMED,
        "Leading and trailing whitespace in values is compared literally",
    )
    SEVERAL_FILTERS = (
        Status.ASSUMED,
        "Several filters with the same tag and `onmatch` combine with OR",
    )
    LEGACY_RULE = Status.ASSUMED, "A `<Rule>` inside a filter without RuleGroup combines with AND"
    RULE_RELATION = (
        Status.ASSUMED,
        "A `<Rule>` is one filter item combining its conditions with its own `groupRelation`",
    )
    ABSENT_FIELD = Status.ASSUMED, "A condition on a field the event does not carry never matches"
    EMPTY_LIST_ITEM = Status.ASSUMED, "Empty items in a `;` list are ignored"
    CASE_FOLDING = Status.ASSUMED, "Case-insensitivity follows the Unicode lower-case mapping"
    NAMED_FIELDS = (
        Status.ASSUMED,
        "Events carry every field that the config or a rule names for their type",
    )

    def __init__(self, status: Status, behaviour: str) -> None:
        self.status = status
        self.behaviour = behaviour


def assumes[F: Callable[..., object]](*semantics: Semantic) -> Callable[[F], F]:
    def mark(function: F) -> F:
        return function

    return mark
