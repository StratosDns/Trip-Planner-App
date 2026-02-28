-- Role management migration (ALTER-based, safe for existing DBs)
begin;

-- participants can be owner/member/observer
alter table public.trip_members
  alter column role set default 'member';

-- enforce role domain values
alter table public.trip_members
  drop constraint if exists trip_members_role_check;

alter table public.trip_members
  add constraint trip_members_role_check
  check (role in ('owner','member','observer'));

-- invitations carry assigned role (member/observer only)
alter table public.pending_invites
  add column if not exists invite_role text not null default 'member';

alter table public.pending_invites
  drop constraint if exists pending_invites_invite_role_check;

alter table public.pending_invites
  add constraint pending_invites_invite_role_check
  check (invite_role in ('member','observer'));

-- notifications carry role to apply when accepted
alter table public.notifications
  add column if not exists invite_role text not null default 'member';

alter table public.notifications
  drop constraint if exists notifications_invite_role_check;

alter table public.notifications
  add constraint notifications_invite_role_check
  check (invite_role in ('member','observer'));

commit;
