-- ============================================================
-- VARTEX — Phase 21 Schema
-- Cross-device access to encrypted messages.
--
-- THE PROBLEM (real product bug, not cosmetic): the private key
-- for reading your messages was generated fresh per browser/
-- device and only ever stored in that device's localStorage.
-- Log in from a second phone, a laptop, or just clear browser
-- data, and a NEW key gets made — meaning messages sent to your
-- OLD key become permanently unreadable there. Whoever is logged
-- in as an account should see that account's messages, full stop
-- — which device they're on isn't relevant.
--
-- THE FIX: the private key can now be backed up, encrypted with
-- a passphrase ONLY the user knows, to this table. The server
-- never sees the passphrase and never sees the plaintext key —
-- it only ever stores ciphertext it cannot open. On a new device,
-- the person enters that same passphrase once, the browser
-- decrypts the backup locally, and messaging works everywhere
-- from then on — genuinely the same account, same messages,
-- any device, while the "server can't read your messages" 
-- guarantee stays completely intact.
--
-- Run AFTER phase 20.
-- ============================================================

create table if not exists public.user_key_backups (
  user_id uuid primary key references public.profiles(id) on delete cascade,
  encrypted_private_key text not null,  -- the RSA private key JWK, AES-GCM encrypted
  key_wrap_iv text not null,
  key_wrap_salt text not null,          -- PBKDF2 salt used to derive the wrapping key from the passphrase
  updated_at timestamptz not null default now()
);

-- Deliberately its OWN table, not a column on profiles — profiles
-- has a public-read policy (needed for public profile pages), and
-- this blob should never be fetchable by anyone but its owner,
-- even though it's already encrypted.
alter table public.user_key_backups enable row level security;

drop policy if exists "owner reads own key backup" on public.user_key_backups;
create policy "owner reads own key backup"
  on public.user_key_backups for select
  using (auth.uid() = user_id);

drop policy if exists "owner creates own key backup" on public.user_key_backups;
create policy "owner creates own key backup"
  on public.user_key_backups for insert
  with check (auth.uid() = user_id);

drop policy if exists "owner updates own key backup" on public.user_key_backups;
create policy "owner updates own key backup"
  on public.user_key_backups for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);
