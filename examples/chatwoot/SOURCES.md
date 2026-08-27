# Provenance for the Chatwoot golden fixture

The schema names, column types, and JSON keys in this directory are taken from
[Chatwoot](https://github.com/chatwoot/chatwoot) (MIT). The fixture is a
reduced copy: enough tables to debug a support inbox, not a dump of production.

Pinned against Chatwoot `develop` as fetched 2026-08-27.

| Fixture | Upstream |
|---|---|
| Table list, `json` vs `jsonb` | [`db/schema.rb`](https://github.com/chatwoot/chatwoot/blob/develop/db/schema.rb) |
| `contacts.additional_attributes->>'company_name'` / `city` / `country` | [`app/models/contact.rb`](https://github.com/chatwoot/chatwoot/blob/develop/app/models/contact.rb) (`order_on_company_name`, `order_on_city`, `order_on_country_name`) |
| `additional_attributes['city']` / `['country']` | [`app/services/contacts/sync_attributes.rb`](https://github.com/chatwoot/chatwoot/blob/develop/app/services/contacts/sync_attributes.rb) |
| `(additional_attributes->'campaign_id') IS NULL` | [`app/models/message.rb`](https://github.com/chatwoot/chatwoot/blob/develop/app/models/message.rb) (`valid_first_reply?`); GIN on that extract is in `schema.rb` |
| `content_attributes` typed as `json` | `schema.rb` (`t.json "content_attributes"`); accessors `submitted_email`, `email`, `items`, `in_reply_to` on the Message model |
| Native `json` / `jsonb` values observed double-encoded by `store ..., coder: JSON` | [Chatwoot issue #14660](https://github.com/chatwoot/chatwoot/issues/14660), a self-hosted production report; the `store` declarations remain in [`app/models/message.rb`](https://github.com/chatwoot/chatwoot/blob/develop/app/models/message.rb) |
| Widget `browser` / `referer` / `initiated_at` | Chatwoot widget session payload (`additional_attributes` on Contact and Conversation) |
| `accounts.internal_attributes` / `settings` | Account model + `schema.rb` |
| `automation_rules.conditions` / `actions` | Automation rule JSON (attribute_key / values / action_name); `action_params` may be `send_message` prose |
| `LOWER(custom_attributes ->> key)::type` filters | [`app/services/filters/custom_attribute_filter_helper.rb`](https://github.com/chatwoot/chatwoot/blob/develop/app/services/filters/custom_attribute_filter_helper.rb) |
| `COUNT(*) FILTER` conversation dashboard counts | [`app/services/filter_service.rb`](https://github.com/chatwoot/chatwoot/blob/develop/app/services/filter_service.rb) |
| Custom-attribute metadata and enum meanings | [`app/models/custom_attribute_definition.rb`](https://github.com/chatwoot/chatwoot/blob/develop/app/models/custom_attribute_definition.rb) |
| Tag/tagging `EXISTS` label filter | [`app/services/filter_service.rb`](https://github.com/chatwoot/chatwoot/blob/develop/app/services/filter_service.rb) (`tag_filter_query`) and `db/schema.rb` |
| Message `today` and `chat` scopes | [`app/models/message.rb`](https://github.com/chatwoot/chatwoot/blob/develop/app/models/message.rb) |

Rails typically emits unqualified `"contacts"` because the app lives in
`public`. This fixture uses schema `chatwoot` so the catalog can be
schema-qualified without colliding with other examples on the same cluster.
`queries.sql` includes both the unqualified Chatwoot shape (refused) and the
schema-qualified operator rewrite (served).
