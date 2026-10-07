"""Maps the `mechanism` field of a check definition to the class that runs it.

All nine mechanisms appear here, including those not yet implemented.
Registering them regardless means an unknown mechanism name is always a
typo in a check definition, never "that one isn't built yet" -- those
raise a clear NotImplementedError instead of going missing.
"""

from mechanisms.cloud_api_config_read import CloudAPIConfigRead
from mechanisms.declared_versus_live_comparison import DeclaredVersusLiveComparison
from mechanisms.inventory_reconciliation import InventoryReconciliation
from mechanisms.log_query import LogQuery
from mechanisms.deliberate_test import DeliberateTest
from mechanisms.not_yet_built import EffectiveAccessAnalysis
from mechanisms.record_store import RecordStore
from mechanisms.pipeline_config_read import PipelineConfigRead
from mechanisms.register_read import RegisterRead

MECHANISMS = {
    # Implemented.
    "cloud_api_config_read": CloudAPIConfigRead(),
    "declared_versus_live_comparison": DeclaredVersusLiveComparison(),
    "inventory_reconciliation": InventoryReconciliation(),
    "log_query": LogQuery(),
    "pipeline_config_read": PipelineConfigRead(),
    "register_read": RegisterRead(),  # since 2026-10-03
    "deliberate_test": DeliberateTest(),  # since 2026-10-05
    "record_store": RecordStore(),  # since 2026-10-06
    # Registered, not yet implemented -- each waits on infrastructure
    # that does not exist yet. See mechanisms/not_yet_built.py.
    "effective_access_analysis": EffectiveAccessAnalysis(),
}
