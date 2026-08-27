-- Golden query corpus for the Chatwoot fixture.
--
-- Each case is a header of `-- @key: value` lines followed by one SQL
-- statement. `probe.py` is the pin: EXPECT is what pgmask should do today,
-- not a wishlist. Over-refusal is a finding we keep; a canary in a served
-- result is a disclosure.

-- @id: health-literal
-- @expect: served
-- @contains: 1
SELECT 1;

-- @id: health-count-contacts
-- @expect: served
-- @contains: 2
SELECT count(*) FROM chatwoot.contacts;

-- Chatwoot's Arel emits unqualified "contacts" assuming search_path includes
-- the app schema (usually public). In this fixture the tables live in
-- `chatwoot`, so Postgres raises undefined_table. pgmask withholds the
-- backend error text (SQL can choose it).
-- @id: chatwoot-unqualified-from
-- @expect: error
-- @contains: withheld
-- @source: https://github.com/chatwoot/chatwoot/blob/develop/app/models/contact.rb
SELECT "contacts"."additional_attributes"->>'company_name'
FROM "contacts"
WHERE "contacts"."account_id" = 1
ORDER BY 1;

-- Same SQL with search_path=chatwoot (what Rails would have on public).
-- Postgres finds the table; pgmask still refuses extract attribution without
-- a schema-qualified relation. Documented friction, not a gap to close by
-- guessing search_path.
-- @id: search-path-unqualified-extract
-- @expect: refused
-- @search_path: chatwoot
-- @source: https://github.com/chatwoot/chatwoot/blob/develop/app/models/contact.rb
SELECT "contacts"."additional_attributes"->>'company_name'
FROM "contacts"
WHERE "contacts"."account_id" = 1
ORDER BY 1;

-- The operator rewrite: schema-qualify what Chatwoot generated.
-- @id: contact-order-on-company-name
-- @expect: refused
-- @source: https://github.com/chatwoot/chatwoot/blob/develop/app/models/contact.rb
SELECT chatwoot.contacts.additional_attributes->>'company_name' AS company_name
FROM chatwoot.contacts
WHERE chatwoot.contacts.account_id = 1
ORDER BY chatwoot.contacts.additional_attributes->>'company_name';

-- Hostile posture knows the JSON document is masked but does not use pointer
-- release policy to bless ORDER BY expressions. Projecting the public value
-- without sorting is the conservative debugging rewrite.
-- @id: contact-company-name-unsorted
-- @expect: served
-- @contains: Canary Logistics
-- @refute: alice.cw-canary
SELECT chatwoot.contacts.additional_attributes->>'company_name' AS company_name
FROM chatwoot.contacts
WHERE chatwoot.contacts.account_id = 1;

-- @id: contact-order-on-city
-- @expect: served
-- @contains: Austin
-- @source: https://github.com/chatwoot/chatwoot/blob/develop/app/models/contact.rb
SELECT chatwoot.contacts.additional_attributes->>'city' AS city
FROM chatwoot.contacts
WHERE chatwoot.contacts.id = 1001;

-- Contacts::SyncAttributes copies additional_attributes['city'] into location.
-- JSONB subscript of an exact object key is attributed.
-- @id: sync-attributes-city-subscript
-- @expect: served
-- @contains: Austin
-- @source: https://github.com/chatwoot/chatwoot/blob/develop/app/services/contacts/sync_attributes.rb
SELECT chatwoot.contacts.additional_attributes['city'] AS city
FROM chatwoot.contacts
WHERE chatwoot.contacts.id = 1001;

-- @id: sync-attributes-country-subscript
-- @expect: served
-- @contains: US
-- @source: https://github.com/chatwoot/chatwoot/blob/develop/app/services/contacts/sync_attributes.rb
SELECT chatwoot.contacts.additional_attributes['country'] AS country
FROM chatwoot.contacts
WHERE chatwoot.contacts.id = 1001;

-- IP is classified: prefix only.
-- @id: contact-created-at-ip
-- @expect: served
-- @contains: 203.0.113.0
-- @refute: 203.0.113.77
SELECT chatwoot.contacts.additional_attributes->>'created_at_ip'
FROM chatwoot.contacts
WHERE chatwoot.contacts.id = 1001;

-- Referer holds a checkout token. Redact, do not pass.
-- @id: contact-referer
-- @expect: served
-- @refute: CANARYREF
SELECT chatwoot.contacts.additional_attributes->>'referer'
FROM chatwoot.contacts
WHERE chatwoot.contacts.id = 1001;

-- Nested public widget metadata, Chatwoot JS SDK shape.
-- @id: contact-browser-os
-- @expect: served
-- @contains: macOS
SELECT chatwoot.contacts.additional_attributes->'browser'->>'os'
FROM chatwoot.contacts
WHERE chatwoot.contacts.id = 1001;

-- Whole additional_attributes cell: shape plus pointer policy.
-- @id: contact-additional-blob
-- @expect: served
-- @contains: Austin
-- @contains: Canary Logistics
-- @refute: 203.0.113.77
-- @refute: CANARYREF
-- @refute: alice_canary
SELECT additional_attributes
FROM chatwoot.contacts
WHERE id = 1001;

-- Custom-attribute commerce key vs SSN.
-- @id: contact-order-id
-- @expect: served
-- @refute: ORD-9911
SELECT custom_attributes->>'order_id'
FROM chatwoot.contacts
WHERE id = 1001;

-- @id: contact-ssn
-- @expect: served
-- @refute: 078-05-4391
SELECT custom_attributes->>'ssn'
FROM chatwoot.contacts
WHERE id = 1001;

-- Message.valid_first_reply? uses (additional_attributes->'campaign_id') IS NULL
-- plus a GIN on that extract in real Chatwoot. The extract itself is attributed;
-- wrapping it in IS NULL is an expression and is refused (no provenance).
-- @id: first-reply-campaign-id-null
-- @expect: refused
-- @source: https://github.com/chatwoot/chatwoot/blob/develop/app/models/message.rb
SELECT (additional_attributes->'campaign_id') IS NULL AS no_campaign
FROM chatwoot.messages
WHERE id = 9001;

-- The operator rewrite: project the extract, do not compute on it.
-- @id: first-reply-campaign-id-extract
-- @expect: served
-- @source: https://github.com/chatwoot/chatwoot/blob/develop/app/models/message.rb
SELECT additional_attributes->'campaign_id' AS campaign_id
FROM chatwoot.messages
WHERE id = 9001;

-- Pre-chat form stores submitted_email on content_attributes (json, not jsonb).
-- @id: message-submitted-email
-- @expect: served
-- @refute: alice.cw-canary@inbox.test
SELECT content_attributes->>'submitted_email'
FROM chatwoot.messages
WHERE id = 9003;

-- Incoming email channel payload.
-- @id: message-email-from
-- @expect: served
-- @refute: alice.cw-canary@inbox.test
SELECT content_attributes->'email'->'from'
FROM chatwoot.messages
WHERE id = 9004;

-- @id: message-email-subject
-- @expect: served
-- @refute: missing parcel
SELECT content_attributes->'email'->>'subject'
FROM chatwoot.messages
WHERE id = 9004;

-- Whole OID-114 json document: keys/array shape survive, submitted values do
-- not. This is the pre-chat form shape used by Message store accessors.
-- @id: message-content-attributes-blob
-- @expect: served
-- @contains: "name":"email"
-- @refute: alice.cw-canary@inbox.test
SELECT content_attributes
FROM chatwoot.messages
WHERE id = 9003;

-- Transcript text may contain names and addresses a recogniser cannot find.
-- Metadata stays useful; the prose is wholly redacted.
-- @id: message-content-redact
-- @expect: served
-- @refute: 555-867-5309
-- @refute: alice.cw-canary
SELECT content FROM chatwoot.messages WHERE id = 9001;

-- SELECT * is the first thing an on-call engineer types. Every NOT NULL
-- column is classified so the type-aware fallback cannot invent a NULL.
-- @id: select-star-contact
-- @expect: served
-- @contains: Austin
-- @refute: alice.cw-canary@inbox.test
-- @refute: +15558675309
SELECT * FROM chatwoot.contacts WHERE id = 1001;

-- View OID must have its own catalog rows (pgmask D-2).
-- @id: contact-directory-view
-- @expect: served
-- @contains: Acme Support
-- @refute: alice.cw-canary@inbox.test
SELECT account_name, email, additional_attributes->>'city'
FROM chatwoot.contact_directory
WHERE id = 1001;

-- Billing canary in account internal_attributes.
-- @id: account-stripe-customer
-- @expect: served
-- @refute: CANARYSTRIPE
SELECT internal_attributes->>'stripe_customer_id'
FROM chatwoot.accounts
WHERE id = 1;

-- @id: conversation-mail-subject
-- @expect: served
-- @refute: Alice Canary
SELECT additional_attributes->>'mail_subject'
FROM chatwoot.conversations
WHERE id = 5001;

-- @id: webhook-url
-- @expect: served
-- @refute: CANARYHOOK
SELECT url FROM chatwoot.webhooks WHERE id = 3;

-- Automation condition values name a customer company — redact the values,
-- keep the operator-visible keys.
-- @id: automation-conditions
-- @expect: served
-- @contains: company_name
-- @refute: Canary Logistics
SELECT conditions FROM chatwoot.automation_rules WHERE id = 70;

-- jsonb_pretty is the usual "let me read this blob" debug tool. Construction
-- / pretty-print has no provenance.
-- @id: debug-jsonb-pretty
-- @expect: refused
SELECT jsonb_pretty(additional_attributes)
FROM chatwoot.contacts
WHERE id = 1001;

-- jsonb_each is how people explode keys while debugging.
-- @id: debug-jsonb-each
-- @expect: refused
SELECT key, value
FROM chatwoot.contacts,
     jsonb_each(additional_attributes)
WHERE id = 1001;

-- Named extract through a subquery alias. Refused by design: provenance does
-- not follow a renamed output.
-- @id: extract-through-subquery-alias
-- @expect: refused
SELECT company FROM (
  SELECT additional_attributes->>'company_name' AS company
  FROM chatwoot.contacts
  WHERE id = 1001
) q;

-- Set operations drop provenance.
-- @id: union-cities
-- @expect: refused
SELECT additional_attributes->>'city' FROM chatwoot.contacts
UNION ALL
SELECT additional_attributes->>'city' FROM chatwoot.contacts;

-- Row-to-json laundering.
-- @id: to-jsonb-contact
-- @expect: refused
SELECT to_jsonb(c) FROM chatwoot.contacts c WHERE c.id = 1001;

-- Mixed operator + subscript, the shape an engineer writes after reading both
-- the Rails hash access and the SQL ->> scopes.
-- @id: mixed-browser-subscript
-- @expect: served
-- @contains: Chrome
SELECT (additional_attributes->'browser')['browser_name']
FROM chatwoot.contacts
WHERE id = 1001;

-- GROUP BY a released extract — the query an analyst writes for "contacts by city".
-- @id: group-by-city-extract
-- @expect: served
-- @contains: Austin
SELECT additional_attributes->>'city' AS city, count(*)
FROM chatwoot.contacts
GROUP BY 1
ORDER BY 1;

-- ---------------------------------------------------------------------------
-- Incident-debugging questions: enough operational metadata to debug queues,
-- delivery failures, routing and automations without opening transcript/PII.
-- ---------------------------------------------------------------------------

-- "Are messages failing, and which content type is affected?"
-- @id: message-delivery-status-counts
-- @expect: served
-- @contains: 3|0|1
-- @source: https://github.com/chatwoot/chatwoot/blob/develop/app/models/message.rb
SELECT status, content_type, count(*)
FROM chatwoot.messages
GROUP BY status, content_type
ORDER BY status, content_type;

-- "Which failed row should I trace in jobs/logs?" No message body is needed.
-- @id: failed-message-metadata
-- @expect: served
-- @contains: 9005|5001|3|0|User
SELECT id, conversation_id, status, content_type, sender_type, created_at
FROM chatwoot.messages
WHERE status = 3
ORDER BY created_at;

-- "Is one inbox failing?" Join only released operational columns.
-- @id: delivery-counts-by-inbox
-- @expect: refused
SELECT i.name, m.status, count(*)
FROM chatwoot.messages m
JOIN chatwoot.inboxes i ON i.id = m.inbox_id
GROUP BY i.name, m.status
ORDER BY i.name, m.status;

-- `name` is masked on other relations, and hostile posture deliberately
-- over-refuses by identifier spelling before result OIDs are available.
-- Group by the released inbox id and read its name in a separate projection.
-- @id: delivery-counts-by-inbox-id
-- @expect: served
-- @contains: 100|3|1
SELECT m.inbox_id, m.status, count(*)
FROM chatwoot.messages m
GROUP BY m.inbox_id, m.status
ORDER BY m.inbox_id, m.status;

-- @id: inbox-name-by-id
-- @expect: served
-- @contains: 100|Website Widget
SELECT id, name
FROM chatwoot.inboxes
WHERE id = 100;

-- "How many conversations are in each workflow status?"
-- @id: conversation-status-counts
-- @expect: served
-- @contains: 0|1
SELECT status, count(*)
FROM chatwoot.conversations
GROUP BY status
ORDER BY status;

-- "Show the timeline envelope, not transcript contents."
-- @id: conversation-message-envelope
-- @expect: served
-- @contains: 42|9001|0|0
-- @contains: 42|9005|3|0
SELECT c.display_id, m.id, m.status, m.content_type, m.message_type, m.created_at
FROM chatwoot.conversations c
JOIN chatwoot.messages m ON m.conversation_id = c.id
WHERE c.id = 5001
ORDER BY m.created_at;

-- "What action should this automation take?" Array wildcard policy is entered
-- through a proven integer array step.
-- @id: automation-action-name
-- @expect: served
-- @contains: add_label
SELECT actions->0->>'action_name'
FROM chatwoot.automation_rules
WHERE id = 70;

-- Condition values can name people or customer records. The diagnostic shape
-- (attribute/operator) is visible; the configured value is not.
-- @id: automation-condition-shape
-- @expect: served
-- @contains: company_name|equal_to
-- @refute: Canary Logistics
SELECT conditions->0->>'attribute_key', conditions->0->>'filter_operator'
FROM chatwoot.automation_rules
WHERE id = 70;

-- PostgreSQL JSONB subscripts decide whether 0 means an array index from the
-- runtime parent. A configured `*` edge therefore cannot be proven statically.
-- Integer -> is the safe diagnostic form above.
-- @id: automation-condition-subscript
-- @expect: refused
SELECT conditions[0]['attribute_key']
FROM chatwoot.automation_rules
WHERE id = 70;

-- The two masked projections use one semantic domain, so an engineer can
-- correlate a contact reached through a base table and a view without seeing
-- the source email.
-- @id: email-pseudonym-consistency
-- @expect: served
-- @refute: alice.cw-canary@inbox.test
SELECT c.email, d.email
FROM chatwoot.contacts c
JOIN chatwoot.contact_directory d ON d.id = c.id
WHERE c.id = 1001;

-- ---------------------------------------------------------------------------
-- A real Chatwoot storage bug: `store ..., coder: JSON` can double-encode a
-- native json/jsonb column as a JSON string scalar (chatwoot#14660).
-- ---------------------------------------------------------------------------

-- The whole cell must not reveal the encoded object. Type-placeholders emit
-- an empty string scalar, which is enough to notice the wrong shape.
-- @id: legacy-double-encoded-content-cell
-- @expect: served
-- @refute: legacy.cw-canary@inbox.test
-- @source: https://github.com/chatwoot/chatwoot/issues/14660
SELECT content_attributes
FROM chatwoot.messages
WHERE id = 9005;

-- PostgreSQL extraction from the string scalar silently yields SQL NULL,
-- matching the production bug report.
-- @id: legacy-double-encoded-extract
-- @expect: served
-- @refute: legacy.cw-canary@inbox.test
-- @source: https://github.com/chatwoot/chatwoot/issues/14660
SELECT content_attributes->>'automation_rule_id'
FROM chatwoot.messages
WHERE id = 9005;

-- The same Rails coder pattern is used on external_source_ids (jsonb).
-- @id: legacy-double-encoded-external-source
-- @expect: served
-- @refute: slack-CANARYEXTERNAL
-- @source: https://github.com/chatwoot/chatwoot/issues/14660
SELECT external_source_ids
FROM chatwoot.messages
WHERE id = 9005;

-- ---------------------------------------------------------------------------
-- Hostile posture: projections are not the only disclosure route. These
-- controls prove that masked PII cannot be inferred with predicates, sorting
-- or grouping while released operational JSON remains filterable.
-- ---------------------------------------------------------------------------

-- @id: hostile-email-equality-oracle
-- @expect: refused
SELECT count(*)
FROM chatwoot.contacts
WHERE email = 'alice.cw-canary@inbox.test';

-- @id: hostile-phone-order-oracle
-- @expect: served
-- @contains: 1002
-- @contains: 1001
SELECT id
FROM chatwoot.contacts
ORDER BY phone_number;

-- @id: hostile-email-group-oracle
-- @expect: refused
SELECT email, count(*)
FROM chatwoot.contacts
GROUP BY email;

-- @id: hostile-json-ip-predicate
-- @expect: refused
SELECT id
FROM chatwoot.contacts
WHERE additional_attributes->>'created_at_ip' = '203.0.113.77';

-- A released operational key remains usable in the same posture.
-- @id: hostile-released-city-predicate
-- @expect: refused
SELECT id, additional_attributes->>'city'
FROM chatwoot.contacts
WHERE additional_attributes->>'city' = 'Austin';

-- Hostile posture does not reason from a JSON pointer's `none` policy while
-- scanning predicates. Chatwoot mirrors city into a released scalar column,
-- so this equivalent operator query remains available.
-- @id: hostile-city-scalar-workaround
-- @expect: served
-- @contains: 1001|Austin
-- @source: https://github.com/chatwoot/chatwoot/blob/develop/app/services/contacts/sync_attributes.rb
SELECT id, location
FROM chatwoot.contacts
WHERE location = 'Austin';

-- ---------------------------------------------------------------------------
-- More exact ActiveRecord shapes from Chatwoot models/services.
-- ---------------------------------------------------------------------------

-- CustomAttributeFilterHelper builds LOWER(json ->> key)::text predicates.
-- The custom value is masked and hostile posture refuses the membership
-- oracle, even though only an id is projected.
-- @id: chatwoot-custom-attribute-filter
-- @expect: refused
-- @source: https://github.com/chatwoot/chatwoot/blob/develop/app/services/filters/custom_attribute_filter_helper.rb
SELECT id
FROM chatwoot.contacts
WHERE LOWER(custom_attributes->>'order_id')::text IN ('ord-9911');

-- Conversations::FilterService computes these three dashboard counts in one
-- scan with COUNT(*) FILTER. Hostile posture disables reducing summaries; the
-- simpler per-status operational counts above remain available.
-- @id: chatwoot-conversation-dashboard-counts
-- @expect: refused
-- @source: https://github.com/chatwoot/chatwoot/blob/develop/app/services/filter_service.rb
SELECT
  count(*) FILTER (WHERE assignee_id = 10),
  count(*) FILTER (WHERE assignee_id IS NULL),
  count(*)
FROM chatwoot.conversations;

-- Message.today is a real model scope. created_at and row-envelope fields are
-- released operational metadata, so this remains useful under hostile posture.
-- @id: chatwoot-message-today-scope
-- @expect: served
-- @contains: 9005|3
-- @source: https://github.com/chatwoot/chatwoot/blob/develop/app/models/message.rb
SELECT id, status
FROM chatwoot.messages
WHERE date_trunc('day', created_at) = TIMESTAMP '2026-03-14 00:00:00'
ORDER BY id;

-- Message.chat excludes activity/private rows. It is pure released metadata.
-- @id: chatwoot-message-chat-scope
-- @expect: served
-- @contains: 9001|0|f
-- @source: https://github.com/chatwoot/chatwoot/blob/develop/app/models/message.rb
SELECT id, message_type, private
FROM chatwoot.messages
WHERE message_type <> 2 AND private = false
ORDER BY id;
