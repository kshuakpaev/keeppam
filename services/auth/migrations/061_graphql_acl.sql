-- +goose Up

-- GraphQL field ACL uses existing app_object_packs: OBJECT glob-matches
-- top-level GraphQL fields when the body is a GraphQL request.

INSERT INTO app_object_packs (id, name, description, unmatched, rules) VALUES
('01900000-0000-7000-8000-000000000075', 'graphql-objects',
 'GraphQL: introspection и delete*/remove* — deny; остальные поля POST /graphql* — allow. Несовпавшее — deny.',
 'deny',
 ARRAY[
   'POST /graphql* __schema deny',
   'POST /graphql* __type deny',
   'POST /graphql* delete* deny',
   'POST /graphql* remove* deny',
   'POST /graphql* * allow'
 ])
ON CONFLICT (id) DO NOTHING;

-- +goose Down

DELETE FROM app_object_packs WHERE id='01900000-0000-7000-8000-000000000075';
