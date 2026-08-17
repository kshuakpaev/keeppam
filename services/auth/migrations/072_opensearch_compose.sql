-- +goose Up

UPDATE siem_settings
SET opensearch_url = 'http://opensearch:9200',
    format = 'ecs'
WHERE id = 1 AND COALESCE(opensearch_url, '') = '';

-- +goose Down

UPDATE siem_settings
SET opensearch_url = ''
WHERE id = 1 AND opensearch_url = 'http://opensearch:9200';
