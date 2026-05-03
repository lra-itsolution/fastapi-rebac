from enum import Enum


class Action(str, Enum):
    CREATE = "CREATE"
    READ = "READ"
    UPDATE = "UPDATE"
    DELETE = "DELETE"


class AuditStatus(str, Enum):
    SUCCESS = "SUCCESS"
    DENIED = "DENIED"
    ERROR = "ERROR"

class SuspiciousSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class SuspiciousStatus(str, Enum):
    NEW = "NEW"
    REVIEWED = "REVIEWED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    CONFIRMED = "CONFIRMED"

