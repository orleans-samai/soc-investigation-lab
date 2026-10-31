from app.detection.base import Rule
from app.detection.rules.accounts import AccountCreated, PrivilegedGroupAddition, SudoAbuse
from app.detection.rules.authentication import (
    LateralMovement,
    PasswordSpraying,
    PrivilegedOffHoursLogon,
    RootSshLogin,
    SshBruteForce,
    SuccessAfterFailures,
    WindowsBruteForce,
)
from app.detection.rules.endpoint import AuditLogCleared, ScheduledTaskCreated, ServiceInstalled, SuspiciousPowerShell


def builtin_rules() -> list[Rule]:
    rules: list[Rule] = [
        SshBruteForce(),
        WindowsBruteForce(),
        PasswordSpraying(),
        SuccessAfterFailures(),
        PrivilegedOffHoursLogon(),
        RootSshLogin(),
        AccountCreated(),
        PrivilegedGroupAddition(),
        SuspiciousPowerShell(),
        AuditLogCleared(),
        ScheduledTaskCreated(),
        ServiceInstalled(),
        LateralMovement(),
        SudoAbuse(),
    ]
    return sorted(rules, key=lambda r: r.id)
