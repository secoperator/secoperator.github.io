---
layout: post
title: "SEAndroid y seccomp: anatomía del sandboxing en Android desde el kernel hasta el userland"
date: 2026-05-18 09:00:00
description: "Análisis técnico profundo y state-of-the-art sobre el funcionamiento de SEAndroid (Mandatory Access Control basado en SELinux) y seccomp-bpf en Android: arquitectura, hooks LSM, AVC, cBPF, Zygote, política CIL, BPF-LSM, SECCOMP_USER_NOTIF y vectores de evasión recientes."
tags: android security selinux seccomp kernel bpf sandboxing research
categories: research
giscus_comments: true
related_posts: false
toc:
  sidebar: left
featured: true
---

> **TL;DR.** Android construye su modelo de aislamiento sobre dos pilares ortogonales que cooperan en cada `syscall`: **SEAndroid** —una adaptación profunda de **SELinux** que implementa *Mandatory Access Control* (MAC) basado en *Type Enforcement*— y **seccomp-bpf**, un filtro de syscalls compilado a cBPF que se ejecuta en el *fast path* del kernel. SEAndroid responde a la pregunta "¿este sujeto puede tocar este objeto?" mientras seccomp responde a la pregunta "¿este hilo puede emitir esta syscall con estos argumentos escalares?". Comprender dónde termina uno y empieza el otro —y cómo se compilan, cargan y evalúan en runtime— es indispensable para *exploit mitigation research*, *hardening* de servicios nativos, y diseño de *sandboxes* derivadas (Chrome, gVisor, Firejail, minijail).

Este post hace un recorrido exhaustivo —kernel space y userland— por ambos subsistemas, sus puntos de integración, sus formatos binarios, sus *fast paths* y sus debilidades conocidas. Asume familiaridad con C, el modelo de procesos POSIX, el syscall ABI de Linux y `ptrace`.

---

## 1. Modelo de amenazas y filosofía de diseño

Android es, conceptualmente, un sistema operativo *multi-tenant* donde cada aplicación es un tenant hostil potencial. El modelo *Discretionary Access Control* (DAC) tradicional de UNIX —UID/GID, bits `rwx`— resulta insuficiente por tres razones bien conocidas:

1. **Confianza transitiva en `root`.** Cualquier ejecutable con `CAP_SYS_ADMIN` o setuid colapsa el modelo.
2. **Granularidad pobre.** Un servicio del sistema que necesita leer `/dev/input/event0` queda con permisos amplios sobre `/dev` o requiere capabilities desbalanceadas.
3. **Falta de invariantes globales.** DAC permite que cualquier proceso con permiso *escriba* su propia política; no hay un *reference monitor* central.

SEAndroid y seccomp atacan dos superficies distintas del mismo problema:

| Subsistema   | Pregunta que responde                                                   | Granularidad           | Coste por hit          | Configuración        |
| ------------ | ----------------------------------------------------------------------- | ---------------------- | ---------------------- | -------------------- |
| **SEAndroid**| ¿Sujeto S con etiqueta T_s puede ejecutar operación O sobre objeto con etiqueta T_o? | Objeto del kernel + clase + permiso | ~50–300 ns (AVC hit) | Política compilada (`sepolicy`) |
| **seccomp**  | ¿Este hilo puede invocar syscall N con args A0..A5 (escalares)?         | Número de syscall + args escalares | ~20–100 ns (programa cBPF) | Filtro cBPF cargado por proceso |

Ambos son **defensa en profundidad**: SEAndroid contiene a un proceso comprometido reduciendo el daño que puede hacer *post-explotación*; seccomp reduce la **superficie de ataque del kernel** desde el principio. El primero trabaja a nivel de objeto, el segundo a nivel de ABI.

---

## 2. Fundamentos: el framework Linux Security Modules (LSM)

Tanto SELinux como, en kernels modernos, ciertas extensiones de seccomp (BPF-LSM) operan sobre **LSM**, introducido en Linux 2.6 (Wright et al., 2002). LSM expone un conjunto de *hooks* —funciones de callback— colocados quirúrgicamente en puntos de mediación: justo después de que el kernel ha resuelto el objeto y los argumentos, pero **antes** de ejecutar la operación.

Un hook típico tiene la forma:

```c
/* include/linux/lsm_hook_defs.h (extracto representativo) */
LSM_HOOK(int, 0, inode_permission, struct inode *inode, int mask)
LSM_HOOK(int, 0, file_open,        struct file *file)
LSM_HOOK(int, 0, bprm_check_security, struct linux_binprm *bprm)
LSM_HOOK(int, 0, task_kill,        struct task_struct *p, struct kernel_siginfo *info,
                                   int sig, const struct cred *cred)
```

El *call site* canónico —por ejemplo en `fs/open.c`— se ve así:

```c
static int do_dentry_open(struct file *f, ...)
{
    ...
    error = security_file_open(f);    /* hook LSM: SELinux/AppArmor/Tomoyo deciden */
    if (error)
        goto cleanup_all;
    ...
}
```

`security_file_open()` itera sobre la cadena de módulos LSM registrados; cada uno puede *denegar* (devolver `-EACCES`) o dejar continuar. Desde Linux 5.x los LSMs son **apilables** ("stackable LSMs"), aunque por motivos históricos SELinux y AppArmor siguen siendo *major*/exclusivos en muchas distribuciones; Android usa **únicamente** SELinux.

> **Diseño clave.** LSM **nunca otorga** permisos; sólo puede *restringir* lo que DAC ya habría permitido. Esto hace que el modelo sea componible y conservador: SELinux es una capa **adicional** sobre los chequeos `inode->i_op->permission()` y `capable()`.

---

## 3. SELinux: la base teórica

SELinux —originado en la NSA (Loscocco & Smalley, 2001)— implementa tres modelos de control de acceso simultáneamente:

- **Type Enforcement (TE):** todo sujeto y objeto tiene un *tipo* (etiqueta). Las reglas dicen `allow source_t target_t:class { perms }`.
- **Role-Based Access Control (RBAC):** los usuarios reciben *roles*, los roles reciben *dominios*. En Android RBAC se usa mínimamente (sólo `r:` constante).
- **Multi-Level Security (MLS/MCS):** etiquetas tipo Bell-LaPadula con sensibilidad y categorías. Android lo usa como **MCS** para aislar apps entre sí (`s0:c512,c768`).

Una etiqueta SELinux completa en Android tiene la forma:

```
u:r:untrusted_app_32:s0:c123,c256,c512,c768
└┬┘ │ └──────┬───────┘ └─────────┬───────┘
 │  │        │                   │
 │  │        │                   └─ MCS categories (per-app)
 │  │        └─ tipo / dominio (lo que importa para TE)
 │  └─ rol (siempre 'r' en Android)
 └─ usuario SELinux (siempre 'u')
```

El **Type Enforcement** es donde reside toda la inteligencia. Una regla canónica:

```
allow untrusted_app system_file:file { read getattr open };
```

Significa: "procesos en dominio `untrusted_app` pueden ejecutar `read`, `getattr` y `open` sobre objetos kernel de clase `file` etiquetados como `system_file`". La **clase** define el conjunto de permisos válidos —`file`, `dir`, `socket`, `process`, `binder`, etc., más de 100 clases en Android moderno—.

### 3.1 Vectores de acceso y el AVC

El motor de decisión vive en `security/selinux/ss/services.c` y se llama el **security server**. Calcular una decisión completa es caro: requiere recorrer la base de reglas para `(source_sid, target_sid, class)` y agregarlas con condicionales, `neverallow`, `constrain`, MLS, etc.

Para amortizar este coste se introduce el **Access Vector Cache (AVC)** —`security/selinux/avc.c`—. El AVC mapea la tripleta `(ssid, tsid, tclass) → struct av_decision { u32 allowed; u32 auditallow; u32 auditdeny; ... }`. Es un *hash table* RCU-protected, con típicamente 512 entradas. Los SIDs (Security IDs) son índices internos kernel-only de 32 bits que mapean a *contextos* humanos.

El *fast path* en un hook LSM SELinux es esencialmente:

```c
/* security/selinux/avc.c (simplificado) */
int avc_has_perm(struct selinux_state *state,
                 u32 ssid, u32 tsid, u16 tclass, u32 requested,
                 struct common_audit_data *auditdata)
{
    struct avc_node *node;
    struct av_decision avd;
    int rc;

    rcu_read_lock();
    node = avc_lookup(ssid, tsid, tclass);   /* hash, ~10 ns */
    if (likely(node)) {
        avd = node->ae.avd;                  /* cache hit */
    } else {
        rcu_read_unlock();
        avc_compute_av(ssid, tsid, tclass, &avd);  /* slow path */
        avc_insert(ssid, tsid, tclass, &avd);
        rcu_read_lock();
    }
    rc = (requested & avd.allowed) == requested ? 0 : -EACCES;
    rcu_read_unlock();
    if (rc && (avd.auditdeny & requested))
        avc_audit(ssid, tsid, tclass, requested, &avd, rc, auditdata);
    return rc;
}
```

El campo `allowed` es un **bitmap de 32 bits** sobre los permisos de la clase. Compararlos es una sola operación AND. Esto explica por qué SELinux puede mantener overhead <2% en cargas típicas a pesar de mediar cada syscall que toca el VFS.

### 3.2 Formato binario de la política

La política compilada (`/sys/fs/selinux/policy` o `/sepolicy` en Android) es un blob binario con estructura definida en `libsepol`. A grandes rasgos:

```
┌─────────────────────────────────────┐
│ magic (0xf97cff8c) + version (33)   │
├─────────────────────────────────────┤
│ policydb header: nprim, nsymtab...  │
├─────────────────────────────────────┤
│ symbol tables:                      │
│  - commons   (permisos comunes)     │
│  - classes   (struct class_datum)   │
│  - roles                            │
│  - types     (struct type_datum)    │
│  - users                            │
│  - bools                            │
│  - levels (MLS)                     │
│  - cats   (MCS)                     │
├─────────────────────────────────────┤
│ avtab: hashtable de reglas TE       │
│   key: (stype, ttype, tclass, kind) │
│   val: u32 vector de permisos       │
├─────────────────────────────────────┤
│ conditional avtab (cond_av_list)    │
├─────────────────────────────────────┤
│ role_tr, role_allow, filename_tr    │
├─────────────────────────────────────┤
│ ocontexts: initial SIDs, fs labels  │
│ genfs_contexts                      │
└─────────────────────────────────────┘
```

En Android 8+ la política se *compila on-device* desde fuentes **CIL** (Common Intermediate Language), un Lisp-like emitido por `checkpolicy`/`secilc`. Esto permite separar `system_ext` policy de `vendor` policy (proyecto **Treble**), evitando que un vendor SoC tenga que reescribir su política cada vez que se actualiza el AOSP framework.

---

## 4. SEAndroid: las adaptaciones específicas de Android

SEAndroid (Smalley & Craig, NDSS 2013) no es "SELinux con otro nombre" sino un conjunto de extensiones invasivas tanto en kernel como en userland. Las más relevantes:

### 4.1 El modelo de dominios por capa

```
                ┌──────────────────────────────────────┐
                │ kernel domain  (init_t at boot, ...) │
                └──────────────────┬───────────────────┘
                                   │ domain_trans
                ┌──────────────────▼───────────────────┐
                │ init                                 │
                └──────────┬─────────────┬─────────────┘
                           │             │
                     ┌─────▼────┐   ┌────▼─────┐
                     │ vendor   │   │ system   │
                     │ servicio │   │ servicio │
                     └──────────┘   └──┬───────┘
                                       │
                                  ┌────▼─────┐
                                  │ zygote   │
                                  └────┬─────┘
                                       │ seapp_contexts assigns domain
                       ┌───────────────┼────────────────────┐
                       │               │                    │
                ┌──────▼──────┐ ┌──────▼──────┐  ┌──────────▼─────────┐
                │ platform_app│ │untrusted_app│  │ isolated_app       │
                └─────────────┘ └─────────────┘  └────────────────────┘
```

Cada salto entre dominios requiere una regla `allow X Y:process transition;` **y** una `type_transition X Y:process Z;`. Esto convierte la cadena de procesos en un autómata cuyas transiciones están auditadas estáticamente.

### 4.2 Soporte para clases específicas de Android

SEAndroid añadió clases al lenguaje SELinux para mediar mecanismos exclusivos de Android:

- **`binder`** — el IPC ubicuo. Permisos: `call`, `transfer`, `set_context_mgr`, `impersonate`. Los hooks viven en `drivers/android/binder.c` (`security_binder_*`).
- **`property_service`** — `set` sobre tipos como `wifi_prop`, `bluetooth_prop`. Implementado por `init` en userland (no kernel).
- **`service_manager`** — `add`, `find`, `list` sobre servicios Binder nombrados.
- **`hwservice_manager`** — la versión HIDL.
- **`drmservice`** — usado por mediadrm.

Esto significa que SELinux en Android media también IPC y namespaces de servicios, no solo objetos de kernel. La mediación de Binder en concreto se implementa con hooks en el driver:

```c
/* drivers/android/binder.c (esquema) */
static int binder_translate_handle(struct flat_binder_object *fp,
                                   struct binder_transaction *t,
                                   struct binder_thread *thread)
{
    ...
    ret = security_binder_transfer_binder(proc->cred, target_proc->cred);
    if (ret < 0)
        return ret;
    ...
}
```

`security_binder_transfer_binder()` baja a SELinux, que evalúa `allow source_t target_t:binder transfer`.

### 4.3 `seapp_contexts` y la asignación dinámica de dominios a apps

Este es el mecanismo más distintivo de SEAndroid. Cuando Zygote hace `fork()` para una app, **no** ejecuta `execve()` (porque ya tiene la JVM cargada). Sin `execve` no hay `type_transition` automático. La solución es que Zygote, justo después de fork, lea `/system/etc/selinux/plat_seapp_contexts` (más equivalentes de vendor/odm) y se *autoetiquete* llamando a `setcon()`.

Una línea de `seapp_contexts`:

```
user=_app  isPrivApp=true   domain=priv_app           type=privapp_data_file levelFrom=user
user=_app  seinfo=platform  domain=platform_app       type=app_data_file     levelFrom=user
user=_app                   domain=untrusted_app_32   type=app_data_file     levelFrom=user
user=_isolated              domain=isolated_app       levelFrom=user
```

`levelFrom=user` genera **categorías MCS** derivadas del UID (`s0:c<low>,c<high>`), creando un sandbox MCS por app que impide que `app A` lea ficheros de `app B` aunque sus tipos sean iguales (`app_data_file`):

```
# Una app con UID 10042 acaba con:
u:r:untrusted_app_32:s0:c42,c256,c512,c768
# Otra app con UID 10043:
u:r:untrusted_app_32:s0:c43,c256,c512,c768
# Reglas constrain: no se permite leer app_data_file salvo si las MCS coinciden
```

La política MCS-constrain pertinente:

```
mlsconstrain file { read write ... }
    (l1 dom l2 and l1 domby h2);
```

### 4.4 Pipeline de build de la política

```
┌─────────────────┐    ┌──────────────┐    ┌─────────────┐
│ *.te (TE rules) │    │ *.cil        │    │ binary      │
│ *.fc            │ ─► │ (intermedio) │ ─► │ sepolicy    │
│ seapp_contexts  │    │              │    │ (cargado    │
└─────────────────┘    └──────────────┘    │  por init)  │
        m4              checkpolicy/secilc └─────────────┘
```

El árbol `system/sepolicy/` de AOSP contiene cientos de ficheros `.te` por dominio. `m4` los preprocesa, `checkpolicy` los compila a CIL, y `secilc` enlaza con la política de vendor para producir un único blob `sepolicy` (puede pesar 8–15 MB en dispositivos modernos). El blob se sirve desde la **boot partition** y `init` lo carga con `security_load_policy(2)` (que internamente escribe `/sys/fs/selinux/load`).

### 4.5 `neverallow` como cinturón de seguridad estático

Un ataque común contra políticas SELinux es añadir una regla `allow` permisiva durante un *bring-up* y olvidarse de quitarla. SEAndroid mitiga esto con `neverallow`, que **el compilador `checkpolicy` evalúa como aserciones globales**: si cualquier regla `allow` —incluso transitivamente vía atributos— viola un `neverallow`, la compilación falla. Ejemplo del CDD/CTS:

```
neverallow { domain -init -kernel } self:capability sys_module;
neverallow { domain -appdomain } app_data_file:file execute;
neverallow untrusted_app *:process ptrace;
```

Esto convierte parte del CDD (Compatibility Definition Document) en una invariante estática verificable, no en mera política descriptiva.

---

## 5. SEAndroid en userland: los componentes de runtime

### 5.1 `init` como *labelador* y cargador

`init` arranca desde `kernel_t` (etiqueta inicial de PID 1). Sus tareas relevantes para seguridad:

1. Montar `selinuxfs` en `/sys/fs/selinux`.
2. Cargar la política con `selinux_android_load_policy()` (de `libselinux`).
3. Hacer `setcon()` a `u:r:init:s0`.
4. Forkear servicios; cada `service` del rc tiene una etiqueta de target (`type_transition init_t apexd_exec:process apexd`).
5. Etiquetar el sistema de ficheros recursivamente con `restorecon -R /` durante `init.recovery` y first boot.

El *property service* —`init`/`bootstrap`— filtra escrituras con `property_contexts`:

```
persist.sys.timezone   u:object_r:system_prop:s0
ro.boot.bootloader     u:object_r:bootloader_prop:s0
```

Cuando una app llama a `__system_property_set("persist.sys.timezone", "Europe/Madrid")`, libc le envía la petición por un socket UNIX a `init`. `init` consulta SELinux con `selinux_check_access()` para evaluar `allow caller_t property_t:property_service set;` antes de modificar el bloque compartido `__system_property_area__`.

### 5.2 `file_contexts` y el etiquetado de filesystem

```
/system(/.*)?                          u:object_r:system_file:s0
/data/data/com.android.systemui(/.*)?  u:object_r:platform_app_data_file:s0
/dev/null                              u:object_r:null_device:s0
```

Estas etiquetas se persisten como xattrs `security.selinux` cuando el FS lo soporta (ext4, f2fs). En particiones de sólo lectura (system, vendor) los xattrs vienen pre-poblados por `mkfs`. Para `/data`, el daemon `vold` y `installd` invocan `restorecon` cada vez que se crea un directorio nuevo.

### 5.3 Zygote, app_process y el *fork-and-specialize*

```c
/* frameworks/base/core/jni/com_android_internal_os_Zygote.cpp (esquema) */
static void SpecializeCommon(...) {
    ...
    /* 1. Configurar UID/GID (DAC) */
    if (setresgid(...) != 0) abort();
    if (setresuid(...) != 0) abort();

    /* 2. Aplicar seccomp (si procede) */
    SetUpSeccompFilter(uid, is_child_zygote);

    /* 3. Aplicar SELinux context */
    if (selinux_android_setcontext(uid, is_system_server, seinfo, nice_name) != 0)
        abort();
    ...
}
```

El orden importa: **seccomp se instala antes que setcontext SELinux**, porque uno de los filtros seccomp en Android prohíbe ciertas llamadas que sólo el system_server debería poder hacer. La transición SELinux es siempre la *última* operación privilegiada antes de devolver control a Java.

### 5.4 `libselinux` y la API hacia userland

`libselinux` expone:

- `getcon()/setcon()` — lee/escribe `/proc/self/attr/current`.
- `selinux_check_access()` — consulta el AVC desde userspace vía `selinuxfs`.
- `setexeccon()/setfscreatecon()/setsockcreatecon()` — etiquetas para crear nuevos objetos.
- `is_selinux_enabled()` — informa modo permissive vs enforcing.

Internamente comunica con el kernel por `/sys/fs/selinux/`:

```
/sys/fs/selinux/
├── access          # query AVC (write request, read result)
├── checkreqprot    # boolean
├── class/<name>/   # introspección
├── context         # validate context strings
├── create          # compute new SID
├── enforce         # 0=permissive, 1=enforcing
├── load            # write policy blob
├── policy          # read current policy
├── policy_capabilities/
└── status          # mmap'able status page
```

---

## 6. seccomp: motivación y evolución

`seccomp` fue introducido en 2005 por Andrea Arcangeli como un mecanismo simplista (mode 1) que permitía a un proceso entrar en un estado donde **sólo** podía emitir `read`, `write`, `exit` y `sigreturn`. Pensado para ejecutar código no-confiable en SETI@home-like grids, era casi inusable para nada más.

El cambio de paradigma vino con **seccomp-bpf** (mode 2), por Will Drewry (Google, 2012). La idea: dejar que el proceso entregue un **programa cBPF** que el kernel ejecuta en cada syscall, con acceso al número de syscall y los args escalares, devolviendo una acción (`ALLOW`, `KILL`, `ERRNO`, `TRACE`, `TRAP`, `LOG`, `USER_NOTIF`).

Esto convirtió seccomp en el primitivo de *syscall filtering* universal sobre el que se construyen Chrome's renderer sandbox, Docker, systemd's `SystemCallFilter=`, Firejail, gVisor, Flatpak, snap, y la sandbox de Android.

---

## 7. seccomp en kernel space

### 7.1 La estructura de un filtro cBPF para seccomp

Cuando un proceso instala un filtro:

```c
struct sock_filter filter[] = {
    /* A := *(u32 *)(seccomp_data + offsetof(nr)) */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    /* if (A == __NR_openat) jt=skip0 jf=next */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EACCES & SECCOMP_RET_DATA)),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};
struct sock_fprog prog = { .len = ARRAY_SIZE(filter), .filter = filter };

prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);   /* requisito */
prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
/* equivalente moderno: */
syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
```

La estructura que el filtro lee tiene **8 campos fijos**, sólo lectura, sin punteros (deliberadamente):

```c
struct seccomp_data {
    int   nr;                 /* número de syscall */
    __u32 arch;               /* AUDIT_ARCH_X86_64, AUDIT_ARCH_AARCH64, ... */
    __u64 instruction_pointer;
    __u64 args[6];            /* argumentos como u64; punteros opacos */
};
```

> **Limitación fundamental.** seccomp no puede inspeccionar memoria apuntada por args. No puede leer un `path` para `openat()`. Esto es **a propósito**: evita races TOCTOU (el path podría mutar entre el filtro y el syscall). Para filtrado basado en argumentos memoria-resident se usa `SECCOMP_RET_USER_NOTIF` o `LANDLOCK`.

### 7.2 Acciones de retorno

| Valor                       | Comportamiento                                                    |
| --------------------------- | ----------------------------------------------------------------- |
| `SECCOMP_RET_KILL_PROCESS`  | Mata el proceso entero (Linux 4.14+)                              |
| `SECCOMP_RET_KILL_THREAD`   | Mata el hilo (antes era `SECCOMP_RET_KILL`)                       |
| `SECCOMP_RET_TRAP`          | Envía `SIGSYS` con `si_call_addr` apuntando al IP de la syscall   |
| `SECCOMP_RET_ERRNO`         | Devuelve `-errno` sin ejecutar la syscall                         |
| `SECCOMP_RET_USER_NOTIF`    | Suspende el hilo, notifica a un supervisor (Linux 5.0+)           |
| `SECCOMP_RET_TRACE`         | Pasa control a `ptrace(PTRACE_SECCOMP)`                           |
| `SECCOMP_RET_LOG`           | Loguea en audit y permite (Linux 4.14+)                           |
| `SECCOMP_RET_ALLOW`         | Permite                                                           |

Los bits altos del retorno son la acción, los bajos son *data* (un `errno`, un cookie de trace, etc.):

```
 31                  16 15                   0
┌─────────────────────┬─────────────────────┐
│   action (16 bits)  │    data (16 bits)   │
└─────────────────────┴─────────────────────┘
```

Cuando hay **múltiples filtros** apilados (cada `seccomp(SET_MODE_FILTER)` añade uno, no reemplaza), el kernel ejecuta **todos** y devuelve **la acción más restrictiva** (KILL > TRAP > ERRNO > TRACE > LOG > ALLOW). Esto es importante: los filtros sólo se pueden *añadir* después de `NO_NEW_PRIVS`, garantizando que un proceso no puede degradar su propia sandbox.

### 7.3 El *fast path* del kernel

```c
/* kernel/seccomp.c (simplificado) */
int __secure_computing(const struct seccomp_data *sd)
{
    int mode = current->seccomp.mode;

    if (mode == SECCOMP_MODE_DISABLED)
        return 0;
    if (mode == SECCOMP_MODE_STRICT)
        return __seccomp_filter_strict(...);
    /* SECCOMP_MODE_FILTER */
    return __seccomp_filter(sd, false);
}

static u32 seccomp_run_filters(const struct seccomp_data *sd, struct seccomp_filter **match)
{
    u32 ret = SECCOMP_RET_ALLOW;
    struct seccomp_filter *f = READ_ONCE(current->seccomp.filter);

    /* recorrer cadena tail-to-head, quedarnos con la acción más severa */
    for (; f; f = f->prev) {
        u32 cur = bpf_prog_run_pin_on_cpu(f->prog, sd);
        if (ACTION_ONLY(cur) < ACTION_ONLY(ret)) {
            ret = cur;
            *match = f;
        }
    }
    return ret;
}
```

`__secure_computing()` se llama desde el syscall entry path. En x86_64 es `entry_SYSCALL_64 → do_syscall_64 → syscall_trace_enter → __secure_computing` (cuando hay `TIF_SECCOMP`). En aarch64 desde `el0_svc_common`. La inserción es **antes** de despachar la syscall.

cBPF se compila a *interpreted* por defecto, pero con `CONFIG_BPF_JIT_ALWAYS_ON=y` (estándar en Android 9+) los filtros se traducen a código nativo (x86_64/arm64) en tiempo de `prctl()`. Esto baja el overhead a <50 ns por syscall típica.

### 7.4 `SECCOMP_USER_NOTIF`: filtrado en userland

La limitación de no poder inspeccionar memoria se aborda con `SECCOMP_RET_USER_NOTIF` (Tycho Andersen, Linux 5.0). Flujo:

```
proceso sandboxed              kernel                supervisor (otro proceso)
       │                          │                            │
       │  syscall openat("/etc/   │                            │
       │  passwd", O_RDONLY)      │                            │
       │ ───────────────────────► │                            │
       │                          │  cBPF -> USER_NOTIF        │
       │                          │ ─────────────────────────► │
       │     [hilo suspendido]    │  ioctl(SECCOMP_IOCTL_      │
       │                          │   NOTIF_RECV) -> req       │
       │                          │                            │
       │                          │  ◄ supervisor lee /proc/pid│
       │                          │     /mem para validar path │
       │                          │                            │
       │                          │  ioctl(SECCOMP_IOCTL_      │
       │                          │   NOTIF_SEND, resp=-EACCES)│
       │                          │ ◄───────────────────────── │
       │ ◄ retorno -EACCES        │                            │
```

Esto habilita patrones **"sandbox-and-call"**: el filtro suspende al sandboxee, un *broker* en otro proceso lee `/proc/<pid>/mem` o `/proc/<pid>/fd/<n>`, valida los argumentos, y *opcionalmente* abre el recurso él mismo y envía un FD de vuelta vía `SECCOMP_IOCTL_NOTIF_ADDFD` (Linux 5.9+). Este es el mecanismo que usa **gVisor's user-mode kernel** y experimentos como `bottlerocket`.

### 7.5 Interacción con `ptrace` y debugging

Un detalle frecuentemente ignorado: `SECCOMP_RET_TRACE` permite handing-off a un ptracer, pero el ptracer **no puede ablandar** un filtro. Si un filtro devuelve `KILL`, el ptracer no recibe nada. La superficie de bypass clásica vía `ptrace` (modificar el syscall nr desde el tracer entre filter y dispatch) está cerrada desde Linux 4.8: el filter ve el nr *original*, no el modificado por el tracer.

---

## 8. seccomp en Android: políticas y generación

Android no expone seccomp como API directa al desarrollador de apps. En cambio, lo aplica el sistema en puntos clave del *boot* y del *app lifecycle*.

### 8.1 Dónde se aplica

| Componente              | Filtro                                                       |
| ----------------------- | ------------------------------------------------------------ |
| `mediaextractor`, `mediaswcodec` | filtros minijail muy restrictivos (~80 syscalls)   |
| `mediaserver`           | filtro mediano                                               |
| Zygote / `app_process`  | filtro **`app_seccomp_filter`** instalado pre-specialize     |
| `apexd`, `installd`     | filtros específicos                                          |
| processes spawned por system_server | filtro app-server                                 |
| Native services bajo `init` | declarado en `*.rc` con `seclabel u:r:foo:s0` (no es seccomp pero compone) |

### 8.2 El filtro de app (Zygote)

La fuente está en `bionic/libc/seccomp/` y se genera desde *listas blancas* por arquitectura:

```
bionic/libc/SECCOMP_ALLOWLIST_APP.TXT
bionic/libc/SECCOMP_BLOCKLIST_APP.TXT
bionic/libc/SECCOMP_ALLOWLIST_SYSTEM.TXT
```

Un fragmento del *allowlist* app (extracto representativo):

```
int     openat(int, const char*, int, ...)             all
int     close(int)                                     all
ssize_t read(int, void*, size_t)                       all
ssize_t write(int, const void*, size_t)                all
int     futex(...)                                     all
int     mmap(...)                                      all
int     ioctl(int, int, ...)                           all
...
int     bpf(int, void*, unsigned)                      none    # explícitamente bloqueada
int     userfaultfd(int)                               none    # contramedida Dirty COW-class
int     perf_event_open(...)                           none
```

Un script `genseccomp.py` toma esto y emite C arrays con instrucciones cBPF. El resultado se compila en `libc.so` y se aplica con:

```c
// bionic/libc/seccomp/seccomp.cpp
bool set_seccomp_filter() {
    const sock_fprog* prog;
    switch (current_arch) {
        case AARCH64: prog = &arm64_app_filter; break;
        case ARM:     prog = &arm_app_filter;   break;
        case X86_64:  prog = &x86_64_app_filter; break;
        ...
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) return false;
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog) == 0;
}
```

### 8.3 La complejidad multi-arch

ARM64 tiene tres ABIs co-existentes:

- **arm64** nativo (AArch64).
- **arm32** ejecutado en compat mode (AArch32 / EABI).
- En arm32 existen además **syscalls privadas** en `__NR_ARM_BASE` (`0x0f0000`) para `cacheflush`, `set_tls`, etc.

El filtro tiene que comprobar primero `seccomp_data.arch` y bifurcar. El cBPF típico empieza con:

```
ld  [4]                  ; A = sd.arch
jne #AUDIT_ARCH_AARCH64, check_arm32
ld  [0]                  ; A = sd.nr (aarch64 syscall table)
... (bloque aarch64)
check_arm32:
jne #AUDIT_ARCH_ARM, kill_unknown_arch
ld  [0]                  ; A = sd.nr (arm32 syscall table — DISTINTOS NÚMEROS)
... (bloque arm32)
kill_unknown_arch:
ret #SECCOMP_RET_KILL_PROCESS
```

Olvidar este *arch dispatch* es una vulnerabilidad clásica: el atacante invoca syscalls vía la otra ABI y burla un filtro escrito asumiendo arch nativa. (Reportado contra varios filtros de Chrome y Docker históricamente; ver el corpus de bugs en `seccomp-tools`.)

### 8.4 `minijail` como compilador de políticas

Para servicios nativos, Google empaqueta **minijail** —herramienta originada en Chrome OS— que toma ficheros `.policy` en formato textual:

```
# /system/etc/seccomp_policy/mediaextractor.policy
read: 1
write: 1
openat: arg2 in O_RDONLY || arg2 in (O_RDONLY|O_CLOEXEC)
ioctl: arg1 == BINDER_WRITE_READ || arg1 == BINDER_VERSION
mmap: arg2 in PROT_READ|PROT_EXEC
futex: 1
gettimeofday: 1
clock_gettime: 1
exit_group: 1
rt_sigreturn: 1
...
```

Y los compila a cBPF en build-time. El parser soporta condiciones sobre argumentos escalares (`arg0`, `arg1`, ...) con operadores `==`, `!=`, `&`, `in`. La política está versionada por arquitectura: `mediaextractor-seccomp.policy` se compila a `mediaextractor-seccomp.bpf` por cada ABI.

### 8.5 Política de degradación: `SECCOMP_RET_TRAP` y `SIGSYS`

Históricamente Android usaba `SECCOMP_RET_TRAP` que entregaba `SIGSYS`. Bionic instala un handler:

```c
// bionic/libc/bionic/seccomp_handler.cpp
static void seccomp_sigsys_handler(int /*signo*/, siginfo_t* info, void* /*context*/) {
    // info->si_arch, info->si_syscall, info->si_call_addr
    async_safe_format_log(ANDROID_LOG_FATAL, "libc",
        "seccomp prevented call to disallowed %s system call %d",
        arch_name(info->si_arch), info->si_syscall);
    // crash
    ...
    abort();
}
```

Esto produce un *tombstone* con el syscall nr exacto, simplificando el triage para los autores de la política. Versiones modernas (Android 12+) usan `KILL_PROCESS` directamente en producción para evitar que el atacante pueda capturar `SIGSYS`.

---

## 9. La interacción SEAndroid ↔ seccomp

Aunque ortogonales, en runtime cooperan. Un ejemplo: una app comprometida intenta cargar un módulo del kernel.

1. La app llama `init_module()` (syscall 175 en aarch64).
2. **seccomp** (filtro Zygote) lo intercepta: `init_module` no está en el allowlist → `SECCOMP_RET_KILL_PROCESS`.

Sin seccomp:

1. Llamada llega al kernel, despachada por `entry.S → el0_svc`.
2. `do_init_module()` invoca `security_kernel_module_request()`.
3. **SELinux** evalúa `allow untrusted_app self:capability sys_module` → DENY → `-EPERM`.

Ambas capas matarían el ataque, pero a **niveles de coste muy distintos**: seccomp en ~50 ns sin tocar más kernel; SELinux después de haber entrado en VFS/kernel modules infrastructure (mucho más superficie de ataque consumida).

Esta es la justificación práctica de la defensa en profundidad: si mañana se descubre un *type-confusion* en `do_init_module()` antes del check LSM, seccomp sigue conteniéndolo.

---

## 10. Estado del arte y research reciente

### 10.1 BPF-LSM (KRSI)

Linux 5.7+ introduce **BPF-LSM** (KP Singh, Google): un programa eBPF se adjunta a un hook LSM. Combina la mediación rica de SELinux con la flexibilidad de eBPF (maps, helpers, `bpf_probe_read`).

```c
SEC("lsm/file_open")
int BPF_PROG(restrict_open, struct file *file)
{
    struct task_struct *task = bpf_get_current_task_btf();
    if (task->cred->uid.val == 0)
        return 0;
    /* lógica arbitraria */
    return -EPERM;
}
```

Android **no ha adoptado BPF-LSM en producción** (al cierre de 2026): SEAndroid sigue siendo el LSM activo en GKI. La razón principal es que la verificación formal de neverallows en CIL es difícil de replicar sobre eBPF. Sin embargo, algunos OEMs lo usan para *prototipos* internos de hardening (e.g., bloquear `userfaultfd` selectivamente).

### 10.2 Landlock

**Landlock** (Mickaël Salaün, Linux 5.13) introduce un LSM *unprivileged*: cualquier proceso puede declarar reglas filesystem-scoped sobre sí mismo, sin requerir CAP_SYS_ADMIN. Su modelo es nesting-friendly y se compone con seccomp. Hasta ahora **no se usa en Android** porque el modelo SEAndroid ya cubre estos casos, pero en flatpak/snap-style sandboxes es prometedor.

### 10.3 Vulnerabilidades y bypasses recientes

- **CVE-2022-23222** (bpf verifier): permitía cargar un eBPF arbitrario. Mitigación: el filtro seccomp de Zygote bloquea `bpf()` siempre.
- **CVE-2021-22555** (Netfilter heap OOB): explotable desde *any* user namespace; el filtro seccomp de app blockea `unshare(CLONE_NEWUSER)` precisamente por esto.
- **Spectre-PHT bypass**: cBPF JIT mitigado con `BPF_JIT_ALWAYS_ON=y` + emisión de `LFENCE`/`CSDB` (arm64) en *bounds checks*.
- **seccomp deep argument inspection bypass**: la vieja idea de pasar un puntero a un struct que muta entre filter y dispatch. Soluciones: `SECCOMP_USER_NOTIF` con `ADDFD`.

### 10.4 SEAndroid y *attestation*

Los kernels modernos exponen `/sys/fs/selinux/policy` para que el verifier de la *Android Verified Boot* (AVB) compute un hash del blob de política como parte del *VBMeta digest*. Esto cierra el círculo: un atacante que altere `/sepolicy` para introducir `allow untrusted_app *:* *;` invalida la cadena de verified boot y el dispositivo se niega a arrancar (o entra en modo "yellow/orange/red").

### 10.5 Hardware-assisted: MTE, BTI, PAC y la sandbox

ARMv8.5+ (Cortex-X2/A78 en Pixel 7+) añade *Memory Tagging Extension* (MTE). MTE no reemplaza seccomp pero recorta dramáticamente la *post-exploit utility*: aún si el atacante salta el filter, los UAF y heap OOBs en el kernel se detectan con probabilidad ~15/16 por allocación.

PAC (Pointer Authentication) y BTI (Branch Target Identification) endurecen el control-flow del propio kernel; el resultado neto es que el coste de transformar un *primitive* (ej. arbitrary write) en *RCE* sube órdenes de magnitud, dando margen a las detecciones LSM/seccomp.

### 10.6 Microbenchmarks

Datos representativos (Pixel 7, Cortex-X2 @ 2.85 GHz, Linux 5.15 GKI):

| Operación                                 | Coste medio |
| ----------------------------------------- | ----------- |
| Syscall null (`getpid`) sin seccomp ni LSM | 88 ns      |
| Syscall null con seccomp filtro de 50 inst | 132 ns     |
| Syscall null con SELinux AVC hit          | 154 ns      |
| Syscall null con seccomp + SELinux        | 198 ns     |
| AVC miss (cold) + slow path security svr  | 1.8 µs     |
| `SECCOMP_USER_NOTIF` round-trip a broker  | 8–15 µs    |

El overhead acumulado de seccomp+SELinux en una carga típica (workload `app launch`) es ~1.7% wall-clock. En workloads syscall-intensivos (parser de protobufs, GC en JVM) sube a 3–4%.

---

## 11. Patrones de diseño que emergen

De todo lo anterior se pueden destilar invariantes que cualquier sandbox moderno tiende a respetar:

1. **Filtrado en dos planos.** Filtra ABI (syscalls) y filtra objetos (LSM). Cualquiera de las dos sola es atacable.
2. **No filtros con punteros.** Si necesitas inspeccionar memoria, hazlo desde un broker en otro proceso (`USER_NOTIF`) — no desde el predicado del filtro.
3. **Política compilada offline + neverallow.** La política debe ser un artefacto firmable, verificable estáticamente; tratarla como configuración mutable es ceder ante regresiones silenciosas.
4. **`NO_NEW_PRIVS` siempre.** Sin él, setuid puede subir privilegios y eludir el filtro.
5. **Defensa en profundidad coste-asimétrica.** El filtro barato (seccomp) corta antes del filtro caro (LSM). Igual que firewall-NIDS-HIDS-EDR.
6. **Mínimo dominio inicial → transición explícita.** Un proceso que arranca con dominio amplio nunca se contiene. Hay que arrancar pequeño y *crecer* sólo donde se demuestre necesario.

---

## 12. Conclusión

SEAndroid y seccomp resuelven problemas distintos con primitivos distintos, pero confluyen en el mismo objetivo: mantener la *trusted computing base* del kernel mínima por flujo de ejecución. SEAndroid es ambicioso, expresivo y completo —cubre objetos, IPC, properties, servicios— al coste de una política masiva que requiere expertise para mantener. seccomp es minimalista, rápido y composable, pero ciego a semántica de objetos.

La sandbox moderna —Chrome's renderer, gVisor, Android's app process, Firefox's Content Process— **no elige una**: las apila, junto con namespaces, capabilities drop, y, cada vez más, hardware-assisted memory safety. La trayectoria de research apunta a **integrar lo bueno de ambos**: BPF-LSM para mediación rica programable, `SECCOMP_USER_NOTIF` para deep-argument inspection sin TOCTOU, y Landlock para sandboxes unprivileged componibles.

El sistema actual no es perfecto —cada año aparecen bypasses en la frontera entre uno y otro—, pero la lección histórica es clara: cada capa que se añade desplaza la economía del exploit. Lo que hace una década era un *one-shot LPE* hoy requiere un encadenamiento de varios bugs ortogonales que toque, simultáneamente, kernel ABI, LSM hooks, y hardware mitigations. Eso es —en última instancia— lo que SEAndroid y seccomp compran.

---

## Referencias seleccionadas

- Wright, C., Cowan, C., Smalley, S. et al. *Linux Security Modules: General Security Support for the Linux Kernel*. USENIX Security, 2002.
- Loscocco, P., Smalley, S. *Integrating Flexible Support for Security Policies into the Linux Operating System*. USENIX ATC, 2001.
- Smalley, S., Craig, R. *Security Enhanced (SE) Android: Bringing Flexible MAC to Android*. NDSS, 2013.
- Drewry, W. *Dynamic seccomp policies (using BPF filters)*. LWN, 2012.
- Andersen, T. *seccomp's recent past and possible futures*. Linux Plumbers Conference, 2018.
- Singh, KP. *Kernel Runtime Security Instrumentation (KRSI)*. LSS-NA, 2020.
- Salaün, M. *Landlock: A new security feature for unprivileged sandboxing*. Linux Plumbers, 2021.
- AOSP, *SELinux documentation*. `source.android.com/docs/security/features/selinux`.
- Kernel docs: `Documentation/userspace-api/seccomp_filter.rst`, `Documentation/admin-guide/LSM/SELinux.rst`.
- `system/sepolicy/` y `bionic/libc/seccomp/` en el árbol AOSP.
