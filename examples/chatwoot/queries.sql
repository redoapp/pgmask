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
-- @expect: served
-- @contains: Canary Logistics
-- @refute: alice.cw-canary
-- @source: https://github.com/chatwoot/chatwoot/blob/develop/app/models/contact.rb
SELECT chatwoot.contacts.additional_attributes->>'company_name' AS company_name
FROM chatwoot.contacts
WHERE chatwoot.contacts.account_id = 1
ORDER BY chatwoot.contacts.additional_attributes->>'company_name';

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
-- @contains: ORD-9911
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
-- @contains: missing parcel
SELECT content_attributes->'email'->>'subject'
FROM chatwoot.messages
WHERE id = 9004;

-- Transcript. Scrub must catch the phone; the given name in prose may remain.
-- @id: message-content-scrub
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
