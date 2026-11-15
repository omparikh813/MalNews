class MalNewsError(Exception):
    exit_code = 1


class ConfigError(MalNewsError):
    exit_code = 2


class RateLimitStop(MalNewsError):
    exit_code = 3


class BudgetExceeded(MalNewsError):
    exit_code = 4


class AllSourcesFailed(MalNewsError):
    exit_code = 5


class AIAuthError(MalNewsError):
    exit_code = 6
