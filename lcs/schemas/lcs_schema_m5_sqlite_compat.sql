-- Milestone 5: Cross-Platform SQLite Compatibility Trigger Patch
-- Drops and recreates trg_gc_reservation_validate_update with static string literals
-- to ensure full backward and forward compatibility across SQLite versions < 3.44 and >= 3.44.

DROP TRIGGER IF EXISTS trg_gc_reservation_validate_update;

CREATE TRIGGER trg_gc_reservation_validate_update
BEFORE UPDATE ON cas_gc_deletion_reservations
FOR EACH ROW
BEGIN
    -- Token validation: reservation_token cannot be mutated during update
    SELECT CASE
        WHEN NEW.reservation_token != OLD.reservation_token
        THEN RAISE(ABORT, 'GC_TRANSITION_ERROR: Cannot alter reservation_token during state transition')
    END;
    
    -- State machine transitions validation
    SELECT CASE
        -- Terminal states cannot be altered
        WHEN OLD.reservation_state = 'PHYSICALLY_DELETED'
        THEN RAISE(ABORT, 'GC_TRANSITION_ERROR: Cannot alter terminal reservation state PHYSICALLY_DELETED')
        WHEN OLD.reservation_state = 'REVERTED'
        THEN RAISE(ABORT, 'GC_TRANSITION_ERROR: Cannot alter terminal reservation state REVERTED')
        
        -- Transitions from RESERVED:
        -- Must be COMMITTED_FOR_UNLINK or REVERTED (cannot jump to PHYSICALLY_DELETED)
        WHEN OLD.reservation_state = 'RESERVED' AND NEW.reservation_state = 'PHYSICALLY_DELETED'
        THEN RAISE(ABORT, 'GC_TRANSITION_ERROR: Illegal state transition from RESERVED to PHYSICALLY_DELETED; cannot bypass COMMITTED_FOR_UNLINK')
        WHEN OLD.reservation_state = 'RESERVED' AND NEW.reservation_state NOT IN ('RESERVED', 'COMMITTED_FOR_UNLINK', 'REVERTED')
        THEN RAISE(ABORT, 'GC_TRANSITION_ERROR: Illegal state transition from RESERVED; cannot bypass COMMITTED_FOR_UNLINK')
        
        -- Transitions from COMMITTED_FOR_UNLINK:
        -- Must be PHYSICALLY_DELETED, or REVERTED strictly with an authenticated cancellation receipt
        WHEN OLD.reservation_state = 'COMMITTED_FOR_UNLINK' AND NEW.reservation_state NOT IN ('COMMITTED_FOR_UNLINK', 'PHYSICALLY_DELETED', 'REVERTED')
        THEN RAISE(ABORT, 'GC_TRANSITION_ERROR: Illegal state transition from COMMITTED_FOR_UNLINK')

        -- Transition from COMMITTED_FOR_UNLINK to REVERTED strictly requires verified physical existence cancellation receipt
        WHEN OLD.reservation_state = 'COMMITTED_FOR_UNLINK' AND NEW.reservation_state = 'REVERTED' AND NOT EXISTS (
            SELECT 1 FROM cas_gc_cancellation_receipts c
            WHERE c.blob_digest = NEW.blob_digest
              AND c.reservation_token = NEW.reservation_token
              AND length(c.receipt_signature) >= 16
        )
        THEN RAISE(ABORT, 'GC_TRANSITION_ERROR: Cannot revert COMMITTED_FOR_UNLINK reservation without verified physical existence cancellation receipt')

        -- Transition to PHYSICALLY_DELETED strictly requires verified physical deletion receipt
        WHEN NEW.reservation_state = 'PHYSICALLY_DELETED' AND NOT EXISTS (
            SELECT 1 FROM cas_physical_deletion_receipts r
            WHERE r.blob_digest = NEW.blob_digest
              AND r.reservation_token = NEW.reservation_token
              AND r.sync_method IN ('F_FULLFSYNC', 'FSYNC')
              AND length(r.receipt_signature) >= 16
        )
        THEN RAISE(ABORT, 'GC_TRANSITION_ERROR: Cannot transition to PHYSICALLY_DELETED without verified physical deletion receipt linking blob_digest and reservation_token')
    END;
END;
