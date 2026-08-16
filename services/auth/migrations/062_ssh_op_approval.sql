-- +goose Up

ALTER TABLE session_op_approvals DROP CONSTRAINT IF EXISTS session_op_approvals_channel_check;
ALTER TABLE session_op_approvals
    ADD CONSTRAINT session_op_approvals_channel_check
    CHECK (channel IN ('http', 'k8s', 'ssh'));

-- +goose Down

ALTER TABLE session_op_approvals DROP CONSTRAINT IF EXISTS session_op_approvals_channel_check;
ALTER TABLE session_op_approvals
    ADD CONSTRAINT session_op_approvals_channel_check
    CHECK (channel IN ('http', 'k8s'));
