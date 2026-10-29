-- =====================================================================
-- LICENCIAS: tabla, roles (user / editor / admin) y seguridad (RLS)
-- Ejecutar completo en Supabase > SQL Editor > New query > Run
-- =====================================================================

-- 1) Perfiles: un rol por usuario de Supabase Auth ---------------------
create table if not exists public.perfiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  email   text,
  rol     text not null default 'user' check (rol in ('user','editor','admin')),
  created_at timestamptz not null default now()
);

-- Cada usuario nuevo recibe automáticamente el rol 'user'
create or replace function public.crear_perfil()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.perfiles (user_id, email) values (new.id, new.email)
  on conflict (user_id) do nothing;
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.crear_perfil();

-- Perfiles de usuarios que ya existieran
insert into public.perfiles (user_id, email)
select id, email from auth.users
on conflict (user_id) do nothing;

-- Rol del usuario que hace la petición (security definer evita recursión en RLS)
create or replace function public.rol_actual()
returns text language sql stable security definer set search_path = public as $$
  select rol from public.perfiles where user_id = auth.uid()
$$;

-- 2) Tabla de licencias -------------------------------------------------
create table if not exists public.licencias (
  id         uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  created_by uuid default auth.uid() references auth.users(id) on delete set null,
  modelo     text not null default 'Space' check (modelo in ('Space','Bike')),
  mac_placa  text not null default '',
  mac_mci    text not null default '',
  licencia   text not null default ''
);

-- 3) Regla de columnas: solo editor/admin pueden tocar 'licencia' ---------
create or replace function public.licencias_guard()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'INSERT' then
    if coalesce(new.licencia,'') <> '' and public.rol_actual() not in ('editor','admin') then
      raise exception 'Solo editor o admin pueden rellenar la licencia';
    end if;
  elsif new.licencia is distinct from old.licencia
        and public.rol_actual() not in ('editor','admin') then
    raise exception 'Solo editor o admin pueden rellenar la licencia';
  end if;
  new.updated_at := now();
  return new;
end $$;

drop trigger if exists licencias_guard on public.licencias;
create trigger licencias_guard
  before insert or update on public.licencias
  for each row execute function public.licencias_guard();

-- 4) Seguridad por filas (RLS) -----------------------------------------
alter table public.perfiles  enable row level security;
alter table public.licencias enable row level security;

-- perfiles: cada uno ve el suyo; el admin ve y cambia todos
drop policy if exists perfiles_select on public.perfiles;
create policy perfiles_select on public.perfiles for select to authenticated
  using (user_id = auth.uid() or public.rol_actual() = 'admin');

drop policy if exists perfiles_update_admin on public.perfiles;
create policy perfiles_update_admin on public.perfiles for update to authenticated
  using (public.rol_actual() = 'admin') with check (public.rol_actual() = 'admin');

-- licencias: user/editor/admin leen, crean y modifican; solo admin elimina
drop policy if exists licencias_select on public.licencias;
create policy licencias_select on public.licencias for select to authenticated
  using (public.rol_actual() in ('user','editor','admin'));

drop policy if exists licencias_insert on public.licencias;
create policy licencias_insert on public.licencias for insert to authenticated
  with check (public.rol_actual() in ('user','editor','admin'));

drop policy if exists licencias_update on public.licencias;
create policy licencias_update on public.licencias for update to authenticated
  using (public.rol_actual() in ('user','editor','admin'))
  with check (public.rol_actual() in ('user','editor','admin'));

drop policy if exists licencias_delete on public.licencias;
create policy licencias_delete on public.licencias for delete to authenticated
  using (public.rol_actual() = 'admin');

-- Sin sesión (anon) no hay acceso a nada
revoke all on public.perfiles  from anon;
revoke all on public.licencias from anon;

-- 5) Asignar roles (ejecutar después de crear los usuarios) ---------------
-- Crear usuarios en: Authentication > Users > Add user (email + contraseña,
-- marcando "Auto Confirm User"). Luego:
--
-- update public.perfiles set rol = 'admin'  where email = 'tu@correo.com';
-- update public.perfiles set rol = 'editor' where email = 'editor@correo.com';
-- (los demás se quedan como 'user')
