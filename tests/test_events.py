from sigma_blindspot.sysmon.events import (
    EVENT_IDS,
    EVENT_IDS_BY_TAG,
    SIGMA_CATEGORY_TO_EVENT_IDS,
    TAG_BY_EVENT_ID,
    UNFILTERABLE_EVENT_IDS,
    Default,
    EventTag,
    default_without_filter,
)


def test_event_ids_are_the_documented_ones() -> None:
    assert EVENT_IDS == frozenset(range(1, 30)) | {255}


def test_every_filterable_event_id_has_exactly_one_tag() -> None:
    listed = [event_id for event_ids in EVENT_IDS_BY_TAG.values() for event_id in event_ids]
    assert sorted(listed) == sorted(EVENT_IDS - UNFILTERABLE_EVENT_IDS)
    assert set(EVENT_IDS_BY_TAG) == set(EventTag)


def test_tag_lookup_inverts_the_tag_table() -> None:
    assert all(
        TAG_BY_EVENT_ID[event_id] is tag
        for tag, event_ids in EVENT_IDS_BY_TAG.items()
        for event_id in event_ids
    )
    assert UNFILTERABLE_EVENT_IDS.isdisjoint(TAG_BY_EVENT_ID)


def test_sigma_categories_map_to_known_event_ids() -> None:
    assert all(
        event_ids and set(event_ids) <= EVENT_IDS
        for event_ids in SIGMA_CATEGORY_TO_EVENT_IDS.values()
    )
    assert SIGMA_CATEGORY_TO_EVENT_IDS["process_creation"] == (1,)
    assert SIGMA_CATEGORY_TO_EVENT_IDS["registry_event"] == (12, 13, 14)


def test_only_documented_or_probed_defaults_are_decided() -> None:
    defaults = {tag: default_without_filter(tag) for tag in EventTag}
    decided = {tag: default for tag, default in defaults.items() if default is not Default.UNKNOWN}
    logged = {EventTag.PROCESS_CREATE, EventTag.PROCESS_TERMINATE}
    unknown = {
        EventTag.DRIVER_LOAD,
        EventTag.CREATE_REMOTE_THREAD,
        EventTag.RAW_ACCESS_READ,
        EventTag.WMI_EVENT,
        EventTag.CLIPBOARD_CHANGE,
        EventTag.PROCESS_TAMPERING,
        EventTag.FILE_DELETE_DETECTED,
        EventTag.FILE_BLOCK_EXECUTABLE,
        EventTag.FILE_BLOCK_SHREDDING,
    }
    assert decided == {
        tag: Default.LOGGED if tag in logged else Default.NOT_LOGGED
        for tag in EventTag
        if tag not in unknown
    }
