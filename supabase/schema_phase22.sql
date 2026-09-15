-- ============================================================
-- VARTEX — Phase 22 Schema — messaging simplified, on request
--
-- Removes the passphrase requirement entirely. Messages are now
-- stored as plain content, protected the same way every other
-- private row in this app is protected: Row Level Security that
-- only lets the sender and recipient ever select it. This is
-- exactly how ordinary consumer DMs (Instagram, Facebook
-- Messenger's standard chats, etc.) actually work — no
-- passphrase, works immediately on any device, because the
-- server itself is the thing doing the access control.
--
-- HONEST TRADE-OFF, stated once here and in the Privacy Center:
-- this is no longer zero-knowledge end-to-end encryption. Someone
-- with direct database access (a compromised service-role key, or
-- Vartex staff with admin database access) could technically read
-- message content. It IS still protected from every other user of
-- the app, and still travels over HTTPS in transit. That's a
-- different, weaker guarantee than Phase 21's passphrase-based
-- E2E — traded deliberately for "just works everywhere," per
-- explicit request.
--
-- Run AFTER phase 21 (this supersedes its passphrase-backup
-- table, which is left in place but unused going forward).
-- ============================================================

-- 1-to-1 messages: add plain content, stop requiring the old
-- encryption columns for new rows
alter table public.messages_metadata add column if not exists content text;
alter table public.messages_metadata alter column ciphertext drop not null;
alter table public.messages_metadata alter column iv drop not null;
alter table public.messages_metadata alter column key_for_recipient drop not null;
alter table public.messages_metadata alter column key_for_sender drop not null;

-- extend the Phase 17 integrity guard to also protect the new
-- content column (a recipient still shouldn't be able to rewrite
-- what a sender appears to have said)
create or replace function public.guard_message_integrity()
returns trigger language plpgsql as $$
begin
  new.sender_id := old.sender_id;
  new.recipient_id := old.recipient_id;
  new.content := old.content;
  new.ciphertext := old.ciphertext;
  new.iv := old.iv;
  new.key_for_recipient := old.key_for_recipient;
  new.key_for_sender := old.key_for_sender;
  new.created_at := old.created_at;
  return new;
end;
$$;

-- Group messages: same change
alter table public.group_messages add column if not exists content text;
alter table public.group_messages alter column ciphertext drop not null;
alter table public.group_messages alter column iv drop not null;

-- Group membership no longer needs a per-member wrapped key
alter table public.chat_group_members alter column wrapped_key drop not null;
