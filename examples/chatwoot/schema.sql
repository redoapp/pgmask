-- Golden fixture modelled on Chatwoot (MIT, chatwoot/chatwoot).
-- Schema names, column types, and JSON key names come from db/schema.rb
-- and the Ruby models cited in SOURCES.md. This is a *reduced* schema:
-- enough tables and JSON blobs to debug a support inbox, not a full dump.

CREATE SCHEMA IF NOT EXISTS chatwoot;

CREATE TABLE chatwoot.accounts (
    id integer PRIMARY KEY,
    name character varying NOT NULL,
    locale integer DEFAULT 0,
    domain character varying,
    support_email character varying,
    settings jsonb DEFAULT '{}'::jsonb,
    custom_attributes jsonb DEFAULT '{}'::jsonb,
    limits jsonb DEFAULT '{}'::jsonb,
    feature_flags bigint DEFAULT 0 NOT NULL,
    status integer DEFAULT 0,
    internal_attributes jsonb DEFAULT '{}'::jsonb
);

CREATE TABLE chatwoot.users (
    id integer PRIMARY KEY,
    name character varying NOT NULL,
    display_name character varying,
    email character varying NOT NULL,
    pubsub_token character varying,
    ui_settings jsonb DEFAULT '{}'::jsonb,
    custom_attributes jsonb DEFAULT '{}'::jsonb,
    type character varying
);

CREATE TABLE chatwoot.inboxes (
    id integer PRIMARY KEY,
    channel_id integer NOT NULL,
    account_id integer NOT NULL REFERENCES chatwoot.accounts (id),
    name character varying NOT NULL,
    email_address character varying,
    greeting_enabled boolean,
    greeting_message character varying,
    enable_email_collect boolean DEFAULT true,
    csat_survey_enabled boolean DEFAULT false,
    auto_assignment_config jsonb DEFAULT '{}'::jsonb,
    timezone character varying DEFAULT 'UTC',
    selected_feature_flags bigint DEFAULT 0 NOT NULL,
    lock_to_single_conversation boolean DEFAULT false,
    csat_config jsonb DEFAULT '{}'::jsonb
);

CREATE TABLE chatwoot.contacts (
    id bigint PRIMARY KEY,
    name character varying,
    email character varying,
    phone_number character varying,
    account_id integer NOT NULL REFERENCES chatwoot.accounts (id),
    identifier character varying,
    last_activity_at timestamp without time zone,
    custom_attributes jsonb DEFAULT '{}'::jsonb,
    additional_attributes jsonb DEFAULT '{}'::jsonb,
    contact_type integer DEFAULT 0,
    middle_name character varying,
    last_name character varying,
    location character varying,
    country_code character varying,
    blocked boolean DEFAULT false
);

CREATE TABLE chatwoot.conversations (
    id integer PRIMARY KEY,
    account_id integer NOT NULL REFERENCES chatwoot.accounts (id),
    inbox_id integer NOT NULL REFERENCES chatwoot.inboxes (id),
    status integer DEFAULT 0,
    assignee_id integer,
    contact_id bigint REFERENCES chatwoot.contacts (id),
    display_id integer NOT NULL,
    contact_last_seen_at timestamp without time zone,
    additional_attributes jsonb DEFAULT '{}'::jsonb,
    contact_inbox_id bigint,
    uuid uuid NOT NULL,
    identifier character varying,
    last_activity_at timestamp without time zone,
    team_id integer,
    campaign_id integer,
    snoozed_until timestamp without time zone,
    custom_attributes jsonb DEFAULT '{}'::jsonb,
    first_reply_created_at timestamp without time zone,
    priority integer,
    sla_policy_id integer,
    label_list character varying[] DEFAULT '{}'::character varying[]
);

CREATE TABLE chatwoot.contact_inboxes (
    id bigint PRIMARY KEY,
    contact_id bigint REFERENCES chatwoot.contacts (id),
    inbox_id integer REFERENCES chatwoot.inboxes (id),
    source_id character varying NOT NULL,
    hmac_verified boolean,
    pubsub_token character varying
);

CREATE TABLE chatwoot.messages (
    id integer PRIMARY KEY,
    content text,
    account_id integer NOT NULL REFERENCES chatwoot.accounts (id),
    inbox_id integer NOT NULL REFERENCES chatwoot.inboxes (id),
    conversation_id integer NOT NULL REFERENCES chatwoot.conversations (id),
    message_type integer NOT NULL,
    created_at timestamp without time zone NOT NULL DEFAULT now(),
    updated_at timestamp without time zone NOT NULL DEFAULT now(),
    private boolean DEFAULT false,
    status integer DEFAULT 0,
    source_id character varying,
    content_type integer DEFAULT 0 NOT NULL,
    -- Chatwoot stores this as json (OID 114), not jsonb. Keep that.
    content_attributes json DEFAULT '{}'::json,
    sender_type character varying,
    sender_id bigint,
    external_source_ids jsonb DEFAULT '{}'::jsonb,
    additional_attributes jsonb DEFAULT '{}'::jsonb,
    processed_message_content text,
    sentiment jsonb DEFAULT '{}'::jsonb
);

CREATE TABLE chatwoot.automation_rules (
    id bigint PRIMARY KEY,
    account_id integer NOT NULL REFERENCES chatwoot.accounts (id),
    name character varying NOT NULL,
    description character varying,
    event_name character varying NOT NULL,
    conditions jsonb DEFAULT '[]'::jsonb NOT NULL,
    actions jsonb DEFAULT '[]'::jsonb NOT NULL,
    active boolean DEFAULT true NOT NULL
);

CREATE TABLE chatwoot.webhooks (
    id integer PRIMARY KEY,
    account_id integer NOT NULL REFERENCES chatwoot.accounts (id),
    url character varying,
    webhook_type integer DEFAULT 0,
    subscriptions jsonb DEFAULT '[]'::jsonb
);

-- Operator-facing directory: a view with its own OID, so catalog rows must
-- name the view, not only the base table (pgmask D-2 / view-OID leak).
CREATE VIEW chatwoot.contact_directory AS
SELECT
    c.id,
    c.name,
    c.email,
    c.phone_number,
    c.additional_attributes,
    c.custom_attributes,
    a.name AS account_name
FROM chatwoot.contacts c
JOIN chatwoot.accounts a ON a.id = c.account_id;

-- ---------------------------------------------------------------------------
-- Seed: one tenant, two inboxes, two contacts, one conversation, messages.
-- Canary tokens that must never appear through pgmask are marked CANARY.
-- ---------------------------------------------------------------------------

INSERT INTO chatwoot.accounts (id, name, locale, domain, support_email, settings, custom_attributes, limits, feature_flags, status, internal_attributes)
VALUES (
    1,
    'Acme Support',
    0,
    'acme.example',
    'help@acme.example',
    jsonb_build_object(
        'auto_resolve_after', 120,
        'audio_transcriptions', true,
        'auto_resolve_ignore_waiting', false
    ),
    jsonb_build_object(
        'industry', 'ecommerce',
        'plan', 'pro'
    ),
    jsonb_build_object(
        'agents', 12,
        'inboxes', 4
    ),
    0,
    0,
    jsonb_build_object(
        'stripe_customer_id', 'cus_CANARYSTRIPE',
        'onboarding_step', 'invite_team'
    )
);

INSERT INTO chatwoot.users (id, name, display_name, email, pubsub_token, ui_settings, custom_attributes, type)
VALUES (
    10,
    'Jordan Agent',
    'Jordan',
    'jordan.agent@acme.example',
    'tok_agent_pubsub',
    jsonb_build_object(
        'rtl_view', false,
        'is_conv_actions_open', true,
        'editor_message', 'draft about Alice'
    ),
    jsonb_build_object(
        'phone_number', '+15558675309',
        'language', 'en'
    ),
    'SuperAdmin'
);

INSERT INTO chatwoot.inboxes (id, channel_id, account_id, name, email_address, greeting_enabled, greeting_message, csat_survey_enabled, auto_assignment_config, csat_config)
VALUES (
    100,
    1,
    1,
    'Website Widget',
    'widget@acme.example',
    true,
    'Hi, how can we help?',
    true,
    jsonb_build_object(
        'max_assignment_limit', 8
    ),
    jsonb_build_object(
        'display_type', 'emoji',
        'message', 'How was your chat?'
    )
),
(
    101,
    2,
    1,
    'Email Channel',
    'support@acme.example',
    false,
    NULL,
    false,
    '{}'::jsonb,
    '{}'::jsonb
);

INSERT INTO chatwoot.contacts (
    id, name, email, phone_number, account_id, identifier,
    last_activity_at, custom_attributes, additional_attributes,
    contact_type, last_name, location, country_code
) VALUES (
    1001,
    'Alice Canary',
    'alice.cw-canary@inbox.test',
    '+15558675309',
    1,
    'widget-alice-1',
    TIMESTAMP '2026-03-14 09:22:00',
    jsonb_build_object(
        'order_id', 'ORD-9911',
        'signed_up_at', '2026-01-02',
        'ssn', '078-05-4391',
        'internal_notes', 'VIP — billing dispute'
    ),
    jsonb_build_object(
        'company_name', 'Canary Logistics',
        'city', 'Austin',
        'country', 'US',
        'country_code', 'US',
        'created_at_ip', '203.0.113.77',
        'social_profiles', jsonb_build_object(
            'twitter', 'alice_canary',
            'linkedin', 'alice-canary'
        ),
        'browser', jsonb_build_object(
            'browser_name', 'Chrome',
            'browser_version', '124.0.0',
            'device_name', 'MacIntel',
            'os', 'macOS'
        ),
        'referer', 'https://shop.acme.example/checkout?token=CANARYREF',
        'initiated_at', jsonb_build_object(
            'timestamp', '2026-03-14T09:21:55.000Z'
        ),
        'conversation_language', 'en'
    ),
    0,
    'Canary',
    'Austin, TX',
    'US'
),
(
    1002,
    'Bob Public',
    'bob.ops@vendor.example',
    '+15550001111',
    1,
    'email-bob-2',
    TIMESTAMP '2026-03-13 16:00:00',
    jsonb_build_object(
        'order_id', 'ORD-1002',
        'signed_up_at', '2025-11-20'
    ),
    jsonb_build_object(
        'company_name', 'Vendor Co',
        'city', 'Denver',
        'country', 'US',
        'country_code', 'US',
        'created_at_ip', '198.51.100.9'
    ),
    0,
    'Public',
    'Denver, CO',
    'US'
);

INSERT INTO chatwoot.conversations (
    id, account_id, inbox_id, status, assignee_id, contact_id, display_id,
    additional_attributes, uuid, identifier, last_activity_at, custom_attributes,
    first_reply_created_at, label_list
) VALUES (
    5001,
    1,
    100,
    0,
    10,
    1001,
    42,
    jsonb_build_object(
        'browser', jsonb_build_object(
            'browser_name', 'Chrome',
            'browser_version', '124.0.0',
            'device_name', 'MacIntel'
        ),
        'referer', 'https://shop.acme.example/checkout?token=CANARYREF',
        'initiated_at', jsonb_build_object('timestamp', '2026-03-14T09:21:55.000Z'),
        'browser_language', 'en-US',
        'conversation_language', 'en',
        'type', 'widget',
        'mail_subject', 'Order ORD-9911 never arrived — Alice Canary'
    ),
    'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'::uuid,
    NULL,
    TIMESTAMP '2026-03-14 09:30:00',
    jsonb_build_object(
        'priority_reason', 'lost_package',
        'stripe_charge', 'ch_CANARYCHARGE'
    ),
    TIMESTAMP '2026-03-14 09:25:00',
    ARRAY['billing', 'shipping']::character varying[]
);

INSERT INTO chatwoot.contact_inboxes (id, contact_id, inbox_id, source_id, hmac_verified, pubsub_token)
VALUES (
    8001,
    1001,
    100,
    'widget-src-alice',
    true,
    'tok_contact_pubsub_CANARY'
);

INSERT INTO chatwoot.messages (
    id, content, account_id, inbox_id, conversation_id, message_type,
    created_at, private, status, content_type, content_attributes,
    sender_type, sender_id, additional_attributes, processed_message_content, sentiment
) VALUES
(
    9001,
    'Hi, my order ORD-9911 never arrived. Call me at 555-867-5309.',
    1, 100, 5001, 0,
    TIMESTAMP '2026-03-14 09:22:10',
    false, 0, 0,
    json_build_object(
        'in_reply_to', NULL,
        'items', json_build_array(
            json_build_object('title', 'Track package', 'value', 'track')
        )
    ),
    'Contact', 1001,
    jsonb_build_object('campaign_id', NULL),
    'Hi, my order ORD-9911 never arrived.',
    jsonb_build_object('label', 'negative', 'score', 0.82)
),
(
    9002,
    'Thanks Alice — looking this up now.',
    1, 100, 5001, 1,
    TIMESTAMP '2026-03-14 09:25:00',
    false, 0, 0,
    '{}'::json,
    'User', 10,
    jsonb_build_object(),
    'Thanks Alice — looking this up now.',
    jsonb_build_object('label', 'neutral', 'score', 0.1)
),
(
    9003,
    NULL,
    1, 100, 5001, 0,
    TIMESTAMP '2026-03-14 09:26:00',
    false, 0, 0,
    json_build_object(
        'submitted_email', 'alice.cw-canary@inbox.test',
        'items', json_build_array(
            json_build_object('name', 'email', 'value', 'alice.cw-canary@inbox.test')
        )
    ),
    'Contact', 1001,
    jsonb_build_object(),
    NULL,
    '{}'::jsonb
),
(
    9004,
    E'From: Alice Canary <alice.cw-canary@inbox.test>\nSubject: missing parcel',
    1, 101, 5001, 0,
    TIMESTAMP '2026-03-14 09:27:00',
    false, 0, 0,
    json_build_object(
        'email', json_build_object(
            'from', json_build_array('Alice Canary <alice.cw-canary@inbox.test>'),
            'subject', 'missing parcel',
            'message_id', '<cw-canary-msgid@inbox.test>'
        ),
        'cc_emails', 'ops@acme.example'
    ),
    'Contact', 1001,
    jsonb_build_object(),
    'missing parcel',
    '{}'::jsonb
);

INSERT INTO chatwoot.automation_rules (id, account_id, name, description, event_name, conditions, actions, active)
VALUES (
    70,
    1,
    'Label lost packages',
    'When company is Canary Logistics, add billing label',
    'conversation_created',
    jsonb_build_array(
        jsonb_build_object(
            'values', jsonb_build_array('Canary Logistics'),
            'attribute_key', 'company_name',
            'query_operator', NULL,
            'filter_operator', 'equal_to',
            'custom_attribute_type', ''
        )
    ),
    jsonb_build_array(
        jsonb_build_object(
            'action_name', 'add_label',
            'action_params', jsonb_build_array('billing')
        )
    ),
    true
);

INSERT INTO chatwoot.webhooks (id, account_id, url, webhook_type, subscriptions)
VALUES (
    3,
    1,
    'https://hooks.acme.example/chatwoot?secret=CANARYHOOK',
    0,
    '["conversation_status_changed", "message_created"]'::jsonb
);
