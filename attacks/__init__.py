"""Attack catalogue -- one module per attack vector.

``ATTACK_REGISTRY`` lists every available attack class so the orchestrator
can discover and run them without hard-coding script paths.
"""

from .heartbeat_flood import HeartbeatFloodAttack
from .ping_flood import PingFloodAttack
from .param_request_flood import ParamRequestFloodAttack
from .mitm_identity_spoof import MitmIdentitySpoofAttack
from .replay_pattern_attack import ReplayPatternAttack
from .command_injection_burst import CommandInjectionBurstAttack

ATTACK_REGISTRY = [
    HeartbeatFloodAttack,
    PingFloodAttack,
    ParamRequestFloodAttack,
    MitmIdentitySpoofAttack,
    ReplayPatternAttack,
    CommandInjectionBurstAttack,
]
