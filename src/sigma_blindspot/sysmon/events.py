from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Final

from sigma_blindspot.sysmon.semantics import Semantic, assumes


class EventTag(StrEnum):
    PROCESS_CREATE = "ProcessCreate"
    FILE_CREATE_TIME = "FileCreateTime"
    NETWORK_CONNECT = "NetworkConnect"
    PROCESS_TERMINATE = "ProcessTerminate"
    DRIVER_LOAD = "DriverLoad"
    IMAGE_LOAD = "ImageLoad"
    CREATE_REMOTE_THREAD = "CreateRemoteThread"
    RAW_ACCESS_READ = "RawAccessRead"
    PROCESS_ACCESS = "ProcessAccess"
    FILE_CREATE = "FileCreate"
    REGISTRY_EVENT = "RegistryEvent"
    FILE_CREATE_STREAM_HASH = "FileCreateStreamHash"
    PIPE_EVENT = "PipeEvent"
    WMI_EVENT = "WmiEvent"
    DNS_QUERY = "DnsQuery"
    FILE_DELETE = "FileDelete"
    CLIPBOARD_CHANGE = "ClipboardChange"
    PROCESS_TAMPERING = "ProcessTampering"
    FILE_DELETE_DETECTED = "FileDeleteDetected"
    FILE_BLOCK_EXECUTABLE = "FileBlockExecutable"
    FILE_BLOCK_SHREDDING = "FileBlockShredding"
    FILE_EXECUTABLE_DETECTED = "FileExecutableDetected"


EVENT_IDS_BY_TAG: Final[Mapping[EventTag, tuple[int, ...]]] = MappingProxyType(
    {
        EventTag.PROCESS_CREATE: (1,),
        EventTag.FILE_CREATE_TIME: (2,),
        EventTag.NETWORK_CONNECT: (3,),
        EventTag.PROCESS_TERMINATE: (5,),
        EventTag.DRIVER_LOAD: (6,),
        EventTag.IMAGE_LOAD: (7,),
        EventTag.CREATE_REMOTE_THREAD: (8,),
        EventTag.RAW_ACCESS_READ: (9,),
        EventTag.PROCESS_ACCESS: (10,),
        EventTag.FILE_CREATE: (11,),
        EventTag.REGISTRY_EVENT: (12, 13, 14),
        EventTag.FILE_CREATE_STREAM_HASH: (15,),
        EventTag.PIPE_EVENT: (17, 18),
        EventTag.WMI_EVENT: (19, 20, 21),
        EventTag.DNS_QUERY: (22,),
        EventTag.FILE_DELETE: (23,),
        EventTag.CLIPBOARD_CHANGE: (24,),
        EventTag.PROCESS_TAMPERING: (25,),
        EventTag.FILE_DELETE_DETECTED: (26,),
        EventTag.FILE_BLOCK_EXECUTABLE: (27,),
        EventTag.FILE_BLOCK_SHREDDING: (28,),
        EventTag.FILE_EXECUTABLE_DETECTED: (29,),
    }
)

TAG_BY_EVENT_ID: Final[Mapping[int, EventTag]] = MappingProxyType(
    {event_id: tag for tag, event_ids in EVENT_IDS_BY_TAG.items() for event_id in event_ids}
)

UNFILTERABLE_EVENT_IDS: Final = frozenset({4, 16, 255})

EVENT_IDS: Final = frozenset(TAG_BY_EVENT_ID) | UNFILTERABLE_EVENT_IDS

SIGMA_CATEGORY_TO_EVENT_IDS: Final[Mapping[str, tuple[int, ...]]] = MappingProxyType(
    {
        "process_creation": (1,),
        "file_change": (2,),
        "network_connection": (3,),
        "sysmon_status": (4, 16),
        "process_termination": (5,),
        "driver_load": (6,),
        "image_load": (7,),
        "create_remote_thread": (8,),
        "raw_access_thread": (9,),
        "process_access": (10,),
        "file_event": (11,),
        "registry_add": (12,),
        "registry_delete": (12,),
        "registry_set": (13,),
        "registry_rename": (14,),
        "registry_event": (12, 13, 14),
        "create_stream_hash": (15,),
        "pipe_created": (17, 18),
        "wmi_event": (19, 20, 21),
        "dns_query": (22,),
        "file_delete": (23,),
        "clipboard_capture": (24,),
        "process_tampering": (25,),
        "file_delete_detected": (26,),
        "file_block_executable": (27,),
        "file_block_shredding": (28,),
        "file_executable_detected": (29,),
        "sysmon_error": (255,),
    }
)

_DISABLED_WITHOUT_FILTER: Final = frozenset({EventTag.NETWORK_CONNECT, EventTag.IMAGE_LOAD})


@assumes(Semantic.UNLISTED_EVENT_TYPES)
def logged_without_filter(tag: EventTag) -> bool:
    return tag not in _DISABLED_WITHOUT_FILTER
