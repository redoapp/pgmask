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
-- @direct_expect: served
-- @direct_contains: Canary Logistics
-- @search_path: chatwoot
-- @source: https://github.com/chatwoot/chatwoot/blob/develop/app/models/contact.rb
SELECT "contacts"."additional_attributes"->>'company_name'
FROM "contacts"
WHERE "contacts"."account_id" = 1
ORDER BY 1;

-- The operator rewrite: schema-qualify what Chatwoot generated.
-- @id: contact-order-on-company-name
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: Canary Logistics
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

-- ContactIpLookupJob writes both created_at_ip and updated_at_ip.
-- @id: contact-updated-at-ip
-- @expect: served
-- @contains: 203.0.113.0
-- @refute: 203.0.113.88
-- @source: https://github.com/chatwoot/chatwoot/blob/develop/app/jobs/contact_ip_lookup_job.rb
SELECT chatwoot.contacts.additional_attributes->>'updated_at_ip'
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

-- Keep browser family/version for compatibility diagnosis, redact the device
-- fingerprint.
-- @id: contact-browser-device
-- @expect: served
-- @refute: MacIntel
SELECT chatwoot.contacts.additional_attributes->'browser'->>'device_name'
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
-- @direct_expect: served
-- @direct_contains: t
-- @source: https://github.com/chatwoot/chatwoot/blob/develop/app/models/message.rb
SELECT (additional_attributes->'campaign_id') IS NULL AS no_campaign
FROM chatwoot.messages
WHERE id = 9001;

-- The operator rewrite: project the extract, do not compute on it.
-- @id: first-reply-campaign-id-extract
-- @expect: served
-- @contains: [NULL]
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
-- @contains: "name":"***"
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

-- Message SELECT * is equally common during incident response. Transcript,
-- source ids and nested submitted values must all remain hidden.
-- @id: select-star-message
-- @expect: served
-- @refute: alice.cw-canary@inbox.test
-- @refute: cw-canary-msgid@inbox.test
SELECT * FROM chatwoot.messages WHERE id = 9003;

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

-- IMAP threading data is useful as a presence/shape diagnosis but the message
-- id itself is external customer data. Channel `source` is unmatched so a
-- later object-shaped value cannot inherit `none`.
-- @id: conversation-email-routing-json
-- @expect: served
-- @contains: false
-- @refute: thread-CANARY@inbox.test
-- @source: https://github.com/chatwoot/chatwoot/blob/develop/app/mailboxes/imap/imap_mailbox.rb
SELECT additional_attributes->>'source',
       additional_attributes->>'in_reply_to',
       additional_attributes->>'auto_reply'
FROM chatwoot.conversations
WHERE id = 5001;

-- @id: webhook-url
-- @expect: served
-- @refute: CANARYHOOK
SELECT url FROM chatwoot.webhooks WHERE id = 3;

-- Stable external identifiers remain correlatable without source bytes.
-- @id: contact-identifier-pseudonym
-- @expect: served
-- @refute: widget-alice-1
SELECT identifier FROM chatwoot.contacts WHERE id = 1001;

-- @id: conversation-identifiers-pseudonym
-- @expect: served
-- @refute: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
-- @refute: conv-CANARYIDENTIFIER
SELECT uuid, identifier FROM chatwoot.conversations WHERE id = 5001;

-- @id: contact-inbox-identifiers
-- @expect: served
-- @refute: widget-src-alice
-- @refute: tok_contact_pubsub_CANARY
SELECT source_id, pubsub_token
FROM chatwoot.contact_inboxes
WHERE id = 8001;

-- @id: user-custom-phone
-- @expect: served
-- @refute: +15558675309
SELECT custom_attributes->>'phone_number'
FROM chatwoot.users
WHERE id = 10;

-- @id: conversation-stripe-charge
-- @expect: served
-- @refute: ch_CANARYCHARGE
SELECT custom_attributes->>'stripe_charge'
FROM chatwoot.conversations
WHERE id = 5001;

-- User-authored automation names/descriptions can contain customer data.
-- @id: automation-free-text
-- @expect: served
-- @refute: When company is Canary Logistics, add billing label
SELECT name, description
FROM chatwoot.automation_rules
WHERE id = 70;

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
-- @direct_expect: served
-- @direct_contains: CANARYREF
SELECT jsonb_pretty(additional_attributes)
FROM chatwoot.contacts
WHERE id = 1001;

-- jsonb_each is how people explode keys while debugging.
-- @id: debug-jsonb-each
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: CANARYREF
SELECT key, value
FROM chatwoot.contacts,
     jsonb_each(additional_attributes)
WHERE id = 1001;

-- Named extract through a subquery alias. Refused by design: provenance does
-- not follow a renamed output.
-- @id: extract-through-subquery-alias
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: Canary Logistics
SELECT company FROM (
  SELECT additional_attributes->>'company_name' AS company
  FROM chatwoot.contacts
  WHERE id = 1001
) q;

-- Set operations drop provenance.
-- @id: union-cities
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: Austin
SELECT additional_attributes->>'city' FROM chatwoot.contacts
UNION ALL
SELECT additional_attributes->>'city' FROM chatwoot.contacts;

-- Row-to-json laundering.
-- @id: to-jsonb-contact
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: alice.cw-canary@inbox.test
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

-- The failed row's prose remains unavailable even though its envelope serves.
-- @id: failed-message-content-redact
-- @expect: served
-- @refute: Alice Canary
-- @refute: legacy.cw-canary@inbox.test
SELECT content, processed_message_content
FROM chatwoot.messages
WHERE id = 9005;

-- Sentiment is deliberately released operational metadata.
-- @id: message-sentiment
-- @expect: served
-- @contains: negative
-- @contains: 0.95
SELECT sentiment FROM chatwoot.messages WHERE id = 9005;

-- "Is one inbox failing?" Join only released operational columns.
-- @id: delivery-counts-by-inbox
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: Website Widget
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

-- One-screen triage: released company/city plus the non-PII message envelope.
-- No contact name, email, phone or transcript is selected.
-- @id: conversation-company-message-envelope
-- @expect: served
-- @contains: 42|Canary Logistics|Austin|9005|3
SELECT c.display_id,
       ct.additional_attributes->>'company_name',
       ct.additional_attributes->>'city',
       m.id,
       m.status
FROM chatwoot.conversations c
JOIN chatwoot.contacts ct ON ct.id = c.contact_id
JOIN chatwoot.messages m ON m.conversation_id = c.id
WHERE c.id = 5001
ORDER BY m.id;

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
-- @direct_expect: served
-- @direct_contains: company_name
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
-- @contains: [NULL]
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

-- Alternate literal JSON extract spellings used at the SQL console.
-- @id: contact-city-hash-path
-- @expect: served
-- @contains: Austin
SELECT additional_attributes #>> '{city}'
FROM chatwoot.contacts
WHERE id = 1001;

-- @id: contact-city-extract-function
-- @expect: served
-- @contains: Austin
SELECT jsonb_extract_path_text(additional_attributes, 'city')
FROM chatwoot.contacts
WHERE id = 1001;

-- OID 114 `json` function form.
-- @id: message-email-extract-function
-- @expect: served
-- @refute: alice.cw-canary@inbox.test
SELECT json_extract_path_text(content_attributes, 'submitted_email')
FROM chatwoot.messages
WHERE id = 9003;

-- A text extract of an object with child policies cannot be safely walked.
-- @id: contact-browser-parent-text
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: MacIntel
SELECT additional_attributes->>'browser'
FROM chatwoot.contacts
WHERE id = 1001;

-- Runtime/dynamic keys stay opaque.
-- @id: contact-dynamic-json-key
-- @expect: refused
-- @direct_expect: served
SELECT additional_attributes->>(id::text)
FROM chatwoot.contacts
WHERE id = 1001;

-- The reusable alias loses enough syntactic evidence for hostile posture to
-- refuse before the outer RowDescription can rescue it.
-- @id: contact-json-through-cte
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: 203.0.113.77
WITH c AS (
  SELECT additional_attributes
  FROM chatwoot.contacts
  WHERE id = 1001
)
SELECT additional_attributes FROM c;

-- ---------------------------------------------------------------------------
-- Hostile posture: projections are not the only disclosure route. These
-- controls prove that masked PII cannot be inferred with predicates, sorting
-- or grouping while released operational JSON remains filterable.
-- ---------------------------------------------------------------------------

-- @id: hostile-email-equality-oracle
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: 1
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
-- @direct_expect: served
-- @direct_contains: alice.cw-canary@inbox.test
SELECT email, count(*)
FROM chatwoot.contacts
GROUP BY email;

-- @id: hostile-json-ip-predicate
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: 1001
SELECT id
FROM chatwoot.contacts
WHERE additional_attributes->>'created_at_ip' = '203.0.113.77';

-- A released operational key remains usable in the same posture.
-- @id: hostile-released-city-predicate
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: 1001|Austin
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
-- @direct_expect: served
-- @direct_contains: 1001
-- @source: https://github.com/chatwoot/chatwoot/blob/develop/app/services/filters/custom_attribute_filter_helper.rb
SELECT id
FROM chatwoot.contacts
WHERE LOWER(custom_attributes->>'order_id')::text IN ('ord-9911');

-- Conversations::FilterService computes these three dashboard counts in one
-- scan with COUNT(*) FILTER. Every predicate column is explicitly released,
-- so the real dashboard query remains available under hostile posture.
-- @id: chatwoot-conversation-dashboard-counts
-- @expect: served
-- @contains: 1|0|1
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

-- FilterService looks up tenant-defined attribute metadata before it builds
-- the JSON predicate. Keys/types are operational; labels/descriptions/values
-- are user-authored and withheld.
-- @id: custom-attribute-definition
-- @expect: served
-- @contains: order_id|0|1
-- @source: https://github.com/chatwoot/chatwoot/blob/develop/app/models/custom_attribute_definition.rb
SELECT attribute_key, attribute_display_type, attribute_model
FROM chatwoot.custom_attribute_definitions
WHERE account_id = 1
ORDER BY id;

-- @id: custom-attribute-definition-values
-- @expect: served
-- @refute: tier-CANARYPRIVATE
SELECT attribute_display_name, attribute_description, attribute_values
FROM chatwoot.custom_attribute_definitions
WHERE id = 202;

-- Exact label-filter EXISTS shape assembled by FilterService. Labels and ids
-- are explicitly released, but `name` is masked on other relations and the
-- hostile preflight conservatively refuses by identifier spelling.
-- @id: chatwoot-label-filter
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: 5001|0
-- @source: https://github.com/chatwoot/chatwoot/blob/develop/app/services/filter_service.rb
SELECT c.id, c.status
FROM chatwoot.conversations c
WHERE EXISTS (
  SELECT *
  FROM chatwoot.taggings
  WHERE taggings.taggable_id = c.id
    AND taggings.taggable_type = 'Conversation'
    AND taggings.tag_id IN (
      SELECT tags.id
      FROM chatwoot.tags
      WHERE tags.name IN ('billing')
    )
)
ORDER BY c.id;

-- ---------------------------------------------------------------------------
-- Red-team sweep: try alternate projections, laundering, predicates, sorting,
-- joins and JSON syntax against canary-bearing columns.
-- ---------------------------------------------------------------------------

-- Pointers present in seed but easy to miss in a hand-written catalog.
-- @id: message-cc-emails
-- @expect: served
-- @refute: ops@acme.example
SELECT content_attributes->>'cc_emails'
FROM chatwoot.messages
WHERE id = 9004;

-- @id: user-select-star
-- @expect: served
-- @refute: Jordan Agent
-- @refute: jordan.agent@acme.example
-- @refute: tok_agent_pubsub
-- @refute: draft about Alice
SELECT * FROM chatwoot.users WHERE id = 10;

-- @id: user-editor-draft
-- @expect: served
-- @refute: draft about Alice
SELECT ui_settings->>'editor_message'
FROM chatwoot.users
WHERE id = 10;

-- @id: contact-social-profile
-- @expect: served
-- @refute: alice_canary
SELECT additional_attributes->'social_profiles'->>'twitter'
FROM chatwoot.contacts
WHERE id = 1001;

-- Serializing the protected parent to text would bypass child masks.
-- @id: contact-social-parent-text
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: alice_canary
SELECT additional_attributes->>'social_profiles'
FROM chatwoot.contacts
WHERE id = 1001;

-- Known inbox config remains useful after changing unknown leaves to
-- type-placeholders. CSAT copy is tenant prose and is redacted.
-- @id: inbox-csat-config
-- @expect: served
-- @contains: emoji|***
-- @refute: RT2CANARY-csat-email@leak.test
SELECT csat_config->>'display_type', csat_config->>'message'
FROM chatwoot.inboxes
WHERE id = 100;

-- Cast laundering attempts on scalar and double-encoded JSON.
-- @id: contact-email-text-cast
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: alice.cw-canary@inbox.test
SELECT email::text FROM chatwoot.contacts WHERE id = 1001;

-- @id: double-encoded-json-text-cast
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: legacy.cw-canary@inbox.test
SELECT content_attributes::text
FROM chatwoot.messages
WHERE id = 9005;

-- @id: whole-json-identity-cast
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: 203.0.113.77
SELECT additional_attributes::jsonb
FROM chatwoot.contacts
WHERE id = 1001;

-- JSONPath and runtime keys remain opaque.
-- @id: jsonpath-city
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: Austin
SELECT jsonb_path_query_first(additional_attributes, '$.city')
FROM chatwoot.contacts
WHERE id = 1001;

-- @id: case-json-key
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: CANARYREF
SELECT additional_attributes[
  CASE WHEN id = 1001 THEN 'referer' ELSE 'city' END
]
FROM chatwoot.contacts
WHERE id = 1001;

-- Text path "0" is ambiguous at the configured array wildcard.
-- @id: message-items-ambiguous-hash-path
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: alice.cw-canary@inbox.test
SELECT content_attributes #>> '{items,0,value}'
FROM chatwoot.messages
WHERE id = 9003;

-- Prove the integer operator rewrite reaches the same sensitive leaf and
-- applies the wildcard policy.
-- @id: message-items-integer-path
-- @expect: served
-- @refute: alice.cw-canary@inbox.test
SELECT content_attributes->'items'->0->>'value'
FROM chatwoot.messages
WHERE id = 9003;

-- Hostile predicate variants: joins, HAVING and subqueries must not turn
-- source equality into an oracle.
-- @id: hostile-masked-join
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: 1001|1001
SELECT c.id, d.id
FROM chatwoot.contacts c
JOIN chatwoot.contact_directory d ON d.email = c.email;

-- @id: hostile-masked-having
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: 1001
SELECT id
FROM chatwoot.contacts
GROUP BY id, email
HAVING email = 'alice.cw-canary@inbox.test';

-- @id: hostile-masked-correlated-subquery
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: 1001
SELECT c.id
FROM chatwoot.contacts c
WHERE EXISTS (
  SELECT 1
  FROM chatwoot.contact_directory d
  WHERE d.email = c.email
);

-- Simple ordering is a documented relative-order disclosure. Expressions in
-- ORDER BY are not credited and must refuse.
-- @id: hostile-order-by-membership
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: 1001
SELECT id
FROM chatwoot.contacts
ORDER BY email = 'alice.cw-canary@inbox.test';

-- @id: hostile-order-by-lower
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: 1001
SELECT id
FROM chatwoot.contacts
ORDER BY lower(email);

-- DISTINCT over deterministic pseudonyms exposes equality/frequency by
-- design, but never the source bytes.
-- @id: hostile-distinct-email
-- @expect: served
-- @refute: alice.cw-canary@inbox.test
SELECT DISTINCT email
FROM chatwoot.contacts
ORDER BY email;

-- Relative ordering is also observable for wholly redacted transcript text.
-- The ids reproduce backend cleartext order; no body bytes cross.
-- @id: hostile-order-by-content
-- @expect: served
-- @rows: 5
-- @contains: 9004
-- @contains: 9001
-- @contains: 9005
-- @contains: 9002
-- @contains: 9003
SELECT id
FROM chatwoot.messages
WHERE conversation_id = 5001
ORDER BY content;

-- Grouping deterministic JSON pseudonyms exposes equality/frequency.
-- @id: group-by-order-id-pseudonym
-- @expect: served
-- @rows: 2
-- @refute: ORD-9911
SELECT custom_attributes->>'order_id', count(*)
FROM chatwoot.contacts
GROUP BY 1
ORDER BY 1;

-- Redaction hides values but not distinct plaintext cardinality: four
-- non-NULL bodies become four identical `***` rows plus one SQL NULL.
-- @id: distinct-redacted-content
-- @expect: served
-- @rows: 5
-- @contains: ***
SELECT DISTINCT content
FROM chatwoot.messages
WHERE conversation_id = 5001;

-- JSON containment is a membership oracle, including when the target pointer
-- itself is released. Hostile posture refuses the masked document use.
-- @id: hostile-json-containment-referer
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: 1001
SELECT id
FROM chatwoot.contacts
WHERE additional_attributes @>
  '{"referer":"https://shop.acme.example/checkout?token=CANARYREF"}'::jsonb;

-- @id: hostile-json-containment-company
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: 1001
SELECT id
FROM chatwoot.contacts
WHERE additional_attributes @> '{"company_name":"Canary Logistics"}'::jsonb;

-- @id: hostile-json-containment-order
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: 1001
SELECT id
FROM chatwoot.contacts
WHERE custom_attributes @> '{"order_id":"ORD-9911"}'::jsonb;

-- Rename the source columns, then try to predicate on the alias instead of the
-- catalogued name. The hostile rename guard must not lose the masked source.
-- @id: hostile-column-list-rename
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: 1001
SELECT contact_id
FROM chatwoot.contacts AS renamed(
  contact_id, contact_name, contact_email, contact_phone, account,
  external_identifier, last_seen, custom_json, additional_json,
  kind, middle, family, place, country, is_blocked
)
WHERE contact_email = 'alice.cw-canary@inbox.test';

-- NATURAL JOIN implicitly introduces every same-named column, including
-- masked names/emails. Even a count cannot make that safe.
-- @id: hostile-natural-join
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: 0
SELECT count(*)
FROM chatwoot.contacts
NATURAL JOIN chatwoot.users;

-- LATERAL and scalar-subquery routes to the same membership oracle.
-- @id: hostile-lateral-membership
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: 1001
SELECT c.id
FROM chatwoot.contacts c,
LATERAL (
  SELECT 1 AS matched
  WHERE c.email = 'alice.cw-canary@inbox.test'
) probe;

-- @id: hostile-scalar-subquery-email
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: alice.cw-canary@inbox.test
SELECT (
  SELECT email FROM chatwoot.contacts WHERE id = 1001
);

-- Window order can expose the same rank as top-level ORDER BY but adds an
-- expression result with no safe provenance.
-- @id: hostile-window-order-email
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: 1001
SELECT id, row_number() OVER (ORDER BY email)
FROM chatwoot.contacts;

-- Transcript predicate and nullness probes.
-- @id: hostile-content-like
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: 9001
SELECT id
FROM chatwoot.messages
WHERE content LIKE '%ORD-9911%';

-- @id: hostile-email-is-not-null
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: 2
SELECT count(*)
FROM chatwoot.contacts
WHERE email IS NOT NULL;

-- Unicode-escaped identifiers must decode before hostile matching.
-- @id: hostile-unicode-email
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: 1
SELECT count(*)
FROM chatwoot.contacts
WHERE u&"email" = 'alice.cw-canary@inbox.test';

-- Constructor and SRF laundering.
-- @id: row-to-json-contact
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: alice.cw-canary@inbox.test
SELECT row_to_json(c)
FROM chatwoot.contacts c
WHERE id = 1001;

-- @id: jsonb-set-contact
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: CANARYREF
SELECT jsonb_set(additional_attributes, '{city}', '"Houston"')
FROM chatwoot.contacts
WHERE id = 1001;

-- @id: unnest-conversation-labels
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: billing
SELECT unnest(label_list)
FROM chatwoot.conversations
WHERE id = 5001;

-- Set-operation provenance cannot be recovered from matching pseudonym
-- domains.
-- @id: intersect-contact-emails
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: alice.cw-canary@inbox.test
SELECT email FROM chatwoot.contacts
INTERSECT
SELECT email FROM chatwoot.contact_directory;

-- COPY bypasses RowDescription and must be stopped before source rows stream.
-- @id: copy-contacts
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: alice.cw-canary@inbox.test
COPY chatwoot.contacts TO STDOUT;

-- Inner SELECT * retains OID/attnum provenance; outer projections still mask.
-- @id: subquery-select-star-email
-- @expect: served
-- @refute: alice.cw-canary@inbox.test
SELECT email
FROM (
  SELECT * FROM chatwoot.contacts WHERE id = 1001
) contact_row;

-- A `json` (OID 114) value cannot use PostgreSQL's JSONB bracket subscripts.
-- The backend message is withheld because SQL can choose error text.
-- @id: json-bracket-backend-error
-- @expect: error
-- @contains: withheld
-- @direct_expect: error
-- @direct_contains: cannot subscript type json
SELECT content_attributes['items'][0]['value']
FROM chatwoot.messages
WHERE id = 9003;

-- Additional expression/function families from the final red-team pass.
-- @id: hostile-content-length
-- @expect: refused
-- @direct_expect: served
SELECT length(content)
FROM chatwoot.messages
WHERE id = 9001;

-- @id: hostile-email-substring
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: alice.cw-ca
SELECT substring(email FROM 1 FOR 11)
FROM chatwoot.contacts
WHERE id = 1001;

-- An SRF cardinality driven by a masked comparison is a boolean oracle.
-- @id: hostile-generate-series
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: 1
SELECT generated
FROM chatwoot.contacts,
LATERAL generate_series(
  1,
  CASE
    WHEN email = 'alice.cw-canary@inbox.test' THEN 1
    ELSE 0
  END
) generated
WHERE id = 1001;

-- COLLATE and pagination variants retain the documented simple-sort leak.
-- @id: hostile-order-email-collate-desc
-- @expect: served
-- @rows: 2
-- @refute: alice.cw-canary@inbox.test
SELECT id
FROM chatwoot.contacts
ORDER BY email COLLATE "C" DESC NULLS LAST;

-- @id: hostile-order-email-fetch-first
-- @expect: served
-- @rows: 1
-- @contains: 1001
SELECT id
FROM chatwoot.contacts
ORDER BY email
FETCH FIRST 1 ROW ONLY;

-- @id: hostile-project-email-order
-- @expect: served
-- @rows: 2
-- @refute: alice.cw-canary@inbox.test
SELECT id, email
FROM chatwoot.contacts
ORDER BY email;

-- DISTINCT ON uses the source value to choose a representative row.
-- @id: hostile-distinct-on-email
-- @expect: refused
-- @direct_expect: served
SELECT DISTINCT ON (email) id
FROM chatwoot.contacts
ORDER BY email, id;

-- Aggregation/fingerprinting must not turn source bytes into an opaque scalar.
-- @id: hostile-array-agg-email
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: alice.cw-canary@inbox.test
SELECT array_agg(email) FROM chatwoot.contacts;

-- @id: hostile-string-agg-email
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: alice.cw-canary@inbox.test
SELECT string_agg(email, ',') FROM chatwoot.contacts;

-- @id: hostile-md5-email
-- @expect: refused
-- @direct_expect: served
SELECT md5(email) FROM chatwoot.contacts WHERE id = 1001;

-- @id: hostile-case-email
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: alice.cw-canary@inbox.test
SELECT CASE
  WHEN email = 'alice.cw-canary@inbox.test' THEN email
  ELSE 'no'
END
FROM chatwoot.contacts
WHERE id = 1001;

-- LIMIT can encode the result of a hidden membership query.
-- @id: hostile-limit-subquery
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: 1001
SELECT id
FROM chatwoot.contacts
ORDER BY id
LIMIT (
  SELECT count(*)
  FROM chatwoot.contacts
  WHERE email = 'alice.cw-canary@inbox.test'
);

-- Recursive machinery must not make a masked projection releasable.
-- @id: hostile-recursive-cte
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: alice.cw-canary@inbox.test
WITH RECURSIVE sequence(n) AS (
  SELECT 1
  UNION ALL
  SELECT n + 1 FROM sequence WHERE n < 2
)
SELECT email
FROM chatwoot.contacts, sequence
WHERE contacts.id = 1001;

-- Built-in array helpers still create opaque expression output.
-- @id: array-position-conversation-label
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: 1
SELECT array_position(label_list, 'billing')
FROM chatwoot.conversations
WHERE id = 5001;

-- Leaky system catalogs can carry query text containing source values.
-- @id: pg-stat-activity-query-text
-- @expect: refused
-- @direct_expect: served
SELECT query
FROM pg_catalog.pg_stat_activity
WHERE datname = current_database()
LIMIT 1;

-- A literal is client-supplied, but naming it like a masked column is an
-- intentional parser edge: either safe release or conservative refusal must
-- stay pinned.
-- @id: values-column-named-email
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: alice.cw-canary@inbox.test
SELECT *
FROM (VALUES ('alice.cw-canary@inbox.test')) literal(email);

-- Contrasting provenance path: inner SELECT * preserves enough OID/attnum
-- evidence for the outer JSON field to receive the original pointer plan.
-- @id: cte-select-star-json
-- @expect: served
-- @contains: Austin
-- @refute: CANARYREF
WITH contact_row AS (
  SELECT * FROM chatwoot.contacts WHERE id = 1001
)
SELECT additional_attributes FROM contact_row;

-- Labels are tenant-controlled and often customer-identifying. The array
-- is nulled (varchar[] cannot use redact); membership is a hostile oracle.
-- @id: label-list-any
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: 5001
SELECT id
FROM chatwoot.conversations
WHERE 'billing' = ANY (label_list);

-- Condition values are customer-controlled; direct integer array navigation
-- reaches the wildcard redact policy.
-- @id: automation-condition-value
-- @expect: served
-- @contains: ***
-- @refute: Canary Logistics
SELECT conditions->0->'values'->>0
FROM chatwoot.automation_rules
WHERE id = 70;

-- A masked JSON leaf in a WHERE expression stays an oracle and refuses.
-- @id: hostile-submitted-email-predicate
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: 9003
SELECT id
FROM chatwoot.messages
WHERE content_attributes->>'submitted_email' =
  'alice.cw-canary@inbox.test';

-- The same expression in the result list is also opaque.
-- @id: hostile-submitted-email-nullness
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: f
SELECT (content_attributes->>'submitted_email') IS NULL
FROM chatwoot.messages
WHERE id = 9003;

-- Cast the native-json pre-chat object, not only the double-encoded row.
-- @id: content-attributes-text-cast
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: alice.cw-canary@inbox.test
SELECT content_attributes::text
FROM chatwoot.messages
WHERE id = 9003;

-- JSONPath aimed directly at a sensitive pointer.
-- @id: jsonpath-referer
-- @expect: refused
-- @direct_expect: served
-- @direct_contains: CANARYREF
SELECT jsonb_path_query(additional_attributes, '$.referer')
FROM chatwoot.contacts
WHERE id = 1001;

-- Operator workaround after resolving "billing" to tag id 301.
-- @id: chatwoot-label-filter-by-id
-- @expect: served
-- @contains: 5001|0
SELECT c.id, c.status
FROM chatwoot.conversations c
WHERE EXISTS (
  SELECT *
  FROM chatwoot.taggings
  WHERE taggings.taggable_id = c.id
    AND taggings.taggable_type = 'Conversation'
    AND taggings.tag_id = 301
)
ORDER BY c.id;

-- Parent `none` on `/initiated_at` would inherit into note/email children.
-- Timestamp is released; nested canaries must not be. A text extract of an
-- unmatched leaf is JSON-null (SQL NULL); the parent object walk keeps `""`.
-- @id: initiated-at-timestamp
-- @expect: served
-- @contains: 2026-03-14T09:21:55.000Z
-- @refute: CANARYNEST
-- @refute: nested.cw-canary
SELECT additional_attributes->'initiated_at'->>'timestamp'
FROM chatwoot.contacts
WHERE id = 1001;

-- @id: initiated-at-nested-note
-- @expect: served
-- @rows: 1
-- @refute: initiated-CANARYNEST
SELECT additional_attributes->'initiated_at'->>'note'
FROM chatwoot.contacts
WHERE id = 1001;

-- @id: initiated-at-object
-- @expect: served
-- @contains: 2026-03-14T09:21:55.000Z
-- @contains: "note":""
-- @refute: initiated-CANARYNEST
-- @refute: nested.cw-canary@inbox.test
SELECT additional_attributes->'initiated_at'
FROM chatwoot.contacts
WHERE id = 1001;

-- @id: conversation-initiated-at-secret
-- @expect: served
-- @rows: 1
-- @refute: conv-initiated-CANARYNEST
SELECT additional_attributes->'initiated_at'->>'secret'
FROM chatwoot.conversations
WHERE id = 5001;

-- Unmatched widget key holding a source email (including JSON `\u` forms
-- after parse) keeps type without value.
-- @id: unmatched-escaped-email
-- @expect: served
-- @rows: 1
-- @refute: alice.cw-canary@inbox.test
SELECT additional_attributes->>'escaped'
FROM chatwoot.contacts
WHERE id = 1001;

-- send_message params are customer-facing prose; action_name stays visible.
-- @id: automation-send-message-name
-- @expect: served
-- @contains: send_message
SELECT actions->1->>'action_name'
FROM chatwoot.automation_rules
WHERE id = 70;

-- @id: automation-send-message-params
-- @expect: served
-- @contains: ***
-- @refute: alice.cw-canary@inbox.test
-- @refute: ORD-9911
SELECT actions->1->'action_params'->>0
FROM chatwoot.automation_rules
WHERE id = 70;

-- add_label params are also redacted: pointer policy cannot depend on
-- sibling action_name.
-- @id: automation-add-label-params
-- @expect: served
-- @contains: ***
SELECT actions->0->'action_params'->>0
FROM chatwoot.automation_rules
WHERE id = 70;

-- Custom-attribute regex/cue fields can embed sample PII.
-- @id: custom-attribute-regex-pattern
-- @expect: served
-- @contains: ***
-- @refute: alice.cw-canary@inbox.test
SELECT regex_pattern
FROM chatwoot.custom_attribute_definitions
WHERE id = 201;

-- @id: custom-attribute-regex-cue
-- @expect: served
-- @contains: ***
-- @refute: Alice Canary
-- @refute: 078-05-4391
SELECT regex_cue
FROM chatwoot.custom_attribute_definitions
WHERE id = 201;

-- Inbox and account routing addresses are emails, not ops literals.
-- @id: inbox-email-address
-- @expect: served
-- @refute: widget@acme.example
-- @refute: support@acme.example
SELECT email_address FROM chatwoot.inboxes ORDER BY id;

-- @id: account-support-email
-- @expect: served
-- @refute: help@acme.example
SELECT support_email FROM chatwoot.accounts WHERE id = 1;

-- Second contact's source email must not pass just because it is not Alice.
-- @id: bob-email-pseudonym
-- @expect: served
-- @refute: bob.ops@vendor.example
SELECT email FROM chatwoot.contacts WHERE id = 1002;

-- Second-pass catalog grants: tenant-controlled `none` leaves.
-- @id: account-domain-redact
-- @expect: served
-- @contains: ***
-- @refute: RT2CANARY-tenant.example
SELECT domain FROM chatwoot.accounts WHERE id = 1;

-- @id: items-name-redact
-- @expect: served
-- @contains: ***
-- @refute: RT2CANARY-item-name@leak.test
SELECT content_attributes->'items'->0->>'name'
FROM chatwoot.messages
WHERE id = 9001;

-- @id: in-reply-to-unmatched-object
-- @expect: served
-- @contains: "thread":""
-- @refute: INREPLY-NESTED-CANARY
SELECT content_attributes->'in_reply_to'
FROM chatwoot.messages
WHERE id = 9001;

-- @id: webhook-subscriptions-placeholder
-- @expect: served
-- @contains: ""
-- @refute: RT2CANARY-hook-event
SELECT subscriptions FROM chatwoot.webhooks WHERE id = 3;

-- @id: conversation-label-list-null
-- @expect: served
-- @contains: [NULL]
-- @refute: RT2CANARY-alice-label
SELECT label_list FROM chatwoot.conversations WHERE id = 5001;

-- @id: tag-name-redact
-- @expect: served
-- @contains: ***
-- @refute: RT2CANARY-customer-tag
SELECT name FROM chatwoot.tags WHERE id = 303;

-- @id: priority-reason-redact
-- @expect: served
-- @contains: ***
-- @refute: RT2CANARY-priority
SELECT custom_attributes->>'priority_reason'
FROM chatwoot.conversations
WHERE id = 5001;
