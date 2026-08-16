-- +goose Up

-- Nested PAM groups: member of a child is WHO on the parent's ACL (child implies parent).

ALTER TABLE groups
    ADD COLUMN IF NOT EXISTS parent_id UUID REFERENCES groups(id) ON DELETE SET NULL;

ALTER TABLE groups
    DROP CONSTRAINT IF EXISTS groups_parent_not_self;
ALTER TABLE groups
    ADD CONSTRAINT groups_parent_not_self CHECK (parent_id IS NULL OR parent_id <> id);

CREATE INDEX IF NOT EXISTS idx_groups_parent ON groups (parent_id);

-- +goose Down

DROP INDEX IF EXISTS idx_groups_parent;
ALTER TABLE groups DROP CONSTRAINT IF EXISTS groups_parent_not_self;
ALTER TABLE groups DROP COLUMN IF EXISTS parent_id;
