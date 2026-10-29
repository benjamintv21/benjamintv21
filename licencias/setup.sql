-- =====================================================================
-- LICENCIAS: tabla (sin autenticación; el rol va en el final del enlace)
-- Ejecutar completo en Supabase > SQL Editor > New query > Run
-- Es seguro ejecutarlo aunque ya hubieras ejecutado la versión anterior.
-- =====================================================================

-- 0) Limpieza de la versión anterior (Auth + perfiles) -------------------
drop policy if exists licencias_select on public.licencias;
drop policy if exists licencias_insert on public.licencias;
drop policy if exists licencias_update on public.licencias;
drop policy if exists licencias_delete on public.licencias;
drop trigger  if exists licencias_guard on public.licencias;
drop function if exists public.licencias_guard();
drop trigger  if exists on_auth_user_created on auth.users;
drop function if exists public.crear_perfil();
drop table    if exists public.perfiles;
drop function if exists public.rol_actual();

-- 1) Tabla -------------------------------------------------------------
create table if not exists public.licencias (
  id         uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  modelo     text not null default 'Space' check (modelo in ('Space','Bike')),
  mac_placa  text not null default '',
  mac_mci    text not null default '',
  licencia   text not null default ''
);
alter table public.licencias drop column if exists created_by;

create or replace function public.licencias_touch()
returns trigger language plpgsql as $$
begin
  new.updated_at := now();
  return new;
end $$;

drop trigger if exists licencias_touch on public.licencias;
create trigger licencias_touch
  before update on public.licencias
  for each row execute function public.licencias_touch();

-- 2) Acceso con la clave pública (igual que la tabla instalaciones) ----------
alter table public.licencias enable row level security;

drop policy if exists licencias_publico on public.licencias;
create policy licencias_publico on public.licencias
  for all to anon, authenticated
  using (true) with check (true);

grant select, insert, update, delete on public.licencias to anon, authenticated;
