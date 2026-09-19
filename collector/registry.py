"""Maps the `mechanism` field of a check definition to the class that runs it.

All nine mechanisms appear here, including the six not yet implemented.
Registering them regardless means an unknown mechanism name is always a
typo in a check definition, never "that one isn't built yet" -- those
raise a clear NotImplementedError instead of going missing.
"""

from mechanisms.cloud_api_config_read import CloudAPIConfigRead
from mechanisms.inventory_reconciliation import InventoryReconciliation
from mechanisms.log_query import LogQuery
from mechanisms.not_yet_built import (
    DeclaredVersusLiveComparison,
    DeliberateTest,
    EffectiveAccessAnalysis,
    PipelineConfigRead,
    RecordStore,
    RegisterRead,
)

MECHANISMS = {
    # Implemented.
    "cloud_api_config_read": CloudAPIConfigRead(),
    "inventory_reconciliation": InventoryReconciliation(),
    "log_query": LogQuery(),
    # Registered, not yet implemented -- each waits on infrastructure
    # that does not exist yet. See mechanisms/not_yet_built.py.
    "declared_versus_live_comparison": DeclaredVersusLiveComparison(),
    "register_read": RegisterRead(),
    "pipeline_config_read": PipelineConfigRead(),
    "deliberate_test": DeliberateTest(),
    "record_store": RecordStore(),
    "effective_access_analysis": EffectiveAccessAnalysis(),
}
