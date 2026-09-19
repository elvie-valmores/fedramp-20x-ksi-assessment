"""Maps a check definition's `mechanism` field to the class that
executes it. All nine mechanisms are registered even though seven are
still stubs -- an unrecognized mechanism name in a check definition
should be a typo, never "we haven't built that yet."
"""

from mechanisms.cloud_api_config_read import CloudAPIConfigRead
from mechanisms.inventory_reconciliation import InventoryReconciliation
from mechanisms.not_yet_built import (
    DeclaredVersusLiveComparison,
    DeliberateTest,
    EffectiveAccessAnalysis,
    LogQuery,
    PipelineConfigRead,
    RecordStore,
    RegisterRead,
)

MECHANISMS = {
    "cloud_api_config_read": CloudAPIConfigRead(),
    "inventory_reconciliation": InventoryReconciliation(),
    "log_query": LogQuery(),
    "declared_versus_live_comparison": DeclaredVersusLiveComparison(),
    "register_read": RegisterRead(),
    "pipeline_config_read": PipelineConfigRead(),
    "deliberate_test": DeliberateTest(),
    "record_store": RecordStore(),
    "effective_access_analysis": EffectiveAccessAnalysis(),
}
