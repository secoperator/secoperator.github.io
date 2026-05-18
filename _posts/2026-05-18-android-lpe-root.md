---
layout: post
title: "LPE a root en Android: introducción y cronología de vulnerabilidades"
date: 2026-05-18 10:00:00
description: Panorama y cronología de Local Privilege Escalation hasta root en Android, incluyendo bugs del kernel Linux que también impactan a dispositivos Android.
tags: android security lpe kernel exploits
categories: security
toc:
  beginning: true
related_posts: false
---

## Introducción

En seguridad ofensiva, **Local Privilege Escalation (LPE)** describe el paso de un contexto de baja confianza (una app sin permisos sensibles, un proceso del sandbox, una shell ADB sin privilegios) a otro contexto privilegiado en el mismo dispositivo. En Android, el objetivo final suele ser uno de estos tres:

- **UID `root`** (UID 0): control total sobre el espacio de usuario.
- **Contexto de kernel** (ring 0 efectivo): se rompen además las restricciones de SELinux, capabilities y seccomp.
- **Bypass de SELinux** desde un dominio confinado a un dominio sin confinar (por ejemplo `untrusted_app` → `init` o `vendor_init`).

En la práctica, un "root exploit" en Android moderno casi siempre implica encadenar varias primitivas, no sólo escalar UID:

1. **Salir del sandbox de la app** (escapar de `untrusted_app` / Zygote / `isolated_app`).
2. **Comprometer el kernel** o un servicio privilegiado (Binder, `system_server`, drivers de GPU/DSP).
3. **Eludir SELinux** y mitigaciones como CFI, KASLR, hypervisor (`pKVM`), MTE en ARMv9, _Page Table Isolation_, y _Kernel Lockdown_.
4. **Persistir**, lo cual con Verified Boot / dm-verity es cada vez más difícil sin desbloquear el bootloader.

### Por qué Android es un caso distinto a "Linux a secas"

Android comparte kernel con Linux, así que muchos bugs de kernel upstream (netfilter, eBPF, io_uring, ALSA, etc.) afectan también a teléfonos. Pero el resto del stack es muy específico:

- **Binder** es el IPC central; cualquier UAF o race aquí es una puerta directa a `system_server`.
- Los drivers de **GPU vendor** (Mali de ARM, Adreno de Qualcomm, PowerVR) y los de **DSP** (Hexagon, Cypress) están expuestos al sandbox de apps y son la superficie más explotada por _spyware_ comercial.
- **SELinux en modo enforcing** está activo desde Android 5; un bug de kernel sin bypass SELinux a menudo no es suficiente para `root` "real".
- **GKI (Generic Kernel Image)** desde Android 11 ha homogeneizado el kernel base, pero los **modules vendor** siguen siendo el eslabón débil.
- **Play Protect**, **Knox**, **TrustZone/TEE** y el coprocesador **Titan M/M2** añaden capas de defensa fuera del kernel.

Por todo esto, en Android distinguimos cuatro tipos de vulnerabilidad que llevan a root:

| Tipo                            | Superficie                                           | Ejemplo típico |
| ------------------------------- | ---------------------------------------------------- | -------------- |
| Userland → System               | Binder, `system_server`, `installd`, `run-as`        | CVE-2024-0044  |
| Userland → Kernel (kernel core) | syscalls genéricas Linux (netfilter, eBPF, io_uring) | CVE-2021-22555 |
| Userland → Kernel (vendor)      | Mali, Adreno, DSP, MTK, Samsung NPU                  | CVE-2023-26083 |
| Bootchain / firmware            | Bootloader, fastboot, TEE                            | CVE-2024-32896 |

A continuación una cronología centrada en los últimos años, con énfasis en bugs **explotados en el mundo real** o con PoC público que se sabe que **funciona en Android**. Si un CVE es de kernel Linux pero no llegó a impactar dispositivos Android reales (por ejemplo porque sólo afecta a Ubuntu con `overlayfs` modificado), no aparece.

---

## Recordatorios históricos (pre-2020)

Sólo como referencia, porque marcaron la cultura del "rooting":

- **CVE-2014-3153** — _Towelroot_ (geohot). Bug en `futex` del kernel Linux; rooteó casi cualquier Android < 4.4.4.
- **CVE-2015-3636** — _PingPongRoot_. UAF en sockets `ping` del kernel, Android 5.x.
- **CVE-2016-5195** — _Dirty COW_. COW race en el kernel Linux; portada a Android como **DirtyCow** y luego **DirtyCopy**.
- **CVE-2019-2215** — _Bad Binder_ (Project Zero, Maddie Stone). UAF en el driver Binder, explotado in-the-wild por NSO contra Pixel 1/2, Galaxy S7/S8/S9, Huawei P20 y más.

---

## 2020

- **CVE-2020-0041** _(Binder)_ — Out-of-bounds write en `binder_release_work` permitiendo escapar del sandbox de app a `system_server`. Publicado por GRIMM con PoC encadenando una segunda vuln para kernel.
- **CVE-2020-0069** — **MediaTek-SU**. Falla en el driver `CMDQ` de MediaTek (`/dev/mtk_cmdq`) que daba **root + bypass SELinux** trivialmente desde una app sin permisos. Afectó a decenas de modelos con SoCs MT6735, MT6737, MT6739, MT6753, MT6757, MT6761, MT6762, MT6763, MT6765, MT6771, MT6797 y muchos más. Fue masivo: se vendía como "one-click root" durante años antes de ser parcheado en marzo de 2020.
- **CVE-2020-0423** _(Binder, UAF)_ — Use-after-free en el reaping de procesos, parte del _bug class_ Binder que llevaría a CVE-2021-0920.

---

## 2021

Año récord para LPE in-the-wild en Android, en parte por la actividad de vendors comerciales (NSO, Cytrox, Intellexa).

- **CVE-2021-1048** _(Linux/Android, epoll UAF)_ — UAF en `epoll` por race en `ep_loop_check_proc`. Explotado **in-the-wild** según Project Zero (TAG-0; "Forced Entry"-era).
- **CVE-2021-0920** _(Binder)_ — UAF en el ciclo de `fd` de Binder. Documentado como **explotado en ataques dirigidos** contra Android antes del parche.
- **CVE-2021-22600** — Double-free en `AF_PACKET` (`packet_set_ring`). Reportado por @vv474172261, recompensado por Google con **$157,500** (récord en su momento para una LPE Android). PoC público disponible.
- **CVE-2021-3490** — eBPF: verificación insuficiente de operaciones ALU 32-bit, permite OOB R/W. Funcional en kernels Android con eBPF habilitado para apps no-root (caso de algunos OEM).
- **CVE-2021-22555** — _"Five Years of Bug-doors"_: heap OOB write en `netfilter` (`x_tables`). Linux y Android. Una de las primitivas más limpias de la década.
- **CVE-2021-39793** — UAF en el GPU Mali (`kbase_jd_user_buf_pin_pages`), reportado por Man Yue Mo (GitHub Security Lab).

---

## 2022

- **CVE-2022-20186** — OOB write en el driver Mali (`kbase_mem_alias`). Cadena completa publicada por Man Yue Mo contra un Pixel 6 stock.
- **CVE-2022-38181** — Mali GPU UAF. **Explotada in-the-wild** según el TAG report de marzo de 2023 (cadena de exploits de un vendor comercial contra Samsung).
- **CVE-2022-22057** — UAF en el driver de GPU **Adreno** (`kgsl`), reportado por Man Yue Mo. Afectó a SoCs Qualcomm en Android.
- **CVE-2022-25636** — Heap OOB write en `nf_tables` (`nft_fwd_dup_netdev_offload`). Aplicable a varios kernels Android.
- **CVE-2022-32250** — UAF en `nft_tables` (Linux/Android). Cadena pública contra Ubuntu, adaptable a Android.
- **CVE-2022-2588** — Double-free en `cls_route` del kernel Linux. Funcional contra kernels Android antiguos con QoS habilitado.
- **CVE-2022-0492** — Container escape vía cgroups v1 `release_agent`. Relevante para Android principalmente en el contexto de `app_zygote` y procesos aislados con cgroups.
- **CVE-2022-22265** — Bug en el driver del **NPU** de Samsung (Exynos). Restringido a dispositivos Samsung con Exynos, escalada de UID `system_server`-equivalente a kernel.

---

## 2023

- **CVE-2023-0266** — UAF en ALSA (`snd_ctl_elem_*`). **Explotada in-the-wild** según TAG en cadenas contra Samsung Android (junto a CVE-2022-4262 en V8 para la entrada).
- **CVE-2023-26083** — Memory leak en el driver Mali GPU, usada para **infoleak** de direcciones de kernel. Empleada por **Cytrox/Intellexa** para entregar el spyware **Predator** sobre Samsung Galaxy S22, según el reporte de TAG/Amnesty.
- **CVE-2023-21400** — Múltiples bugs en `io_uring` (`io_*_rsrc`) en kernels Android.
- **CVE-2023-33063** — Use-after-free en el firmware del **DSP Hexagon** (Qualcomm). Marcada por Qualcomm como "may be under limited, targeted exploitation". Ataques tipo _Operation Triangulation_ pero en Android.
- **CVE-2023-33107** — Integer overflow en el driver **Adreno** (`KGSL_IOCTL_GPUOBJ_IMPORT`). **Explotada in-the-wild** según Qualcomm/Google (octubre 2023).
- **CVE-2023-22071** — Buffer overflow en el driver Adreno, también Qualcomm.
- **CVE-2023-35690** — Memory corruption en `Modem` (Qualcomm), parcheado en el boletín de seguridad Android de diciembre 2023.
- **CVE-2023-4147** — UAF en `nft_chain` de netfilter (Linux/Android).
- **CVE-2023-21256** — LPE en el stack Bluetooth de Android System.

---

## 2024

- **CVE-2024-0044** — _"AnyRoot"_: error de validación en `run-as` (Android 12 y 13) que permite a una shell ADB sin privilegios suplantar a cualquier paquete y leer/escribir sus datos privados. No es UID 0, pero sí _de-facto_ compromiso completo de cualquier app. PoC trivial y muy extendido. Reportado por Meta Red Team X.
- **CVE-2024-31317** — _Zygote command injection_: inyección en argumentos del `Zygote` desde `WindowManager`, permite ejecutar código como cualquier UID al que el Zygote pueda forkear, incluyendo `system` (UID 1000). Descubierto por Meta Red Team X.
- **CVE-2024-32896** — Bug en el firmware/ROM de Pixel ("Pixel Lock Screen Bypass"), **explotada por herramientas forenses** (Cellebrite). Aunque originalmente reportado contra Pixel internos, fue extendido al resto de Pixel.
- **CVE-2024-29748** — Bug que permite cancelar el factory reset en Pixel, también utilizado en cadenas forenses.
- **CVE-2024-43093** — LPE en el Android Framework (path traversal en `Environment`), permitía acceder a directorios con paths con caracteres unicode normalizados. Marcada por Google como "may be under limited, targeted exploitation".
- **CVE-2024-1086** — UAF en `nft_verdict_init` (netfilter, `nf_tables`). PoC público de @Notselwyn, kernel Linux 5.14 – 6.6. **Aplicable a kernels Android** que tengan `nf_tables` habilitado para `user_namespaces` (depende del OEM; AOSP estándar lo restringe pero algunos vendors no).
- **CVE-2024-36971** — UAF en `__dst_negative_advice` (Linux netfilter), parcheado en julio 2024 e incluido en el Android Security Bulletin de septiembre 2024 como exploit _in-the-wild_.
- **CVE-2024-36978** — Bug en `net/sched` confirmado afectando kernels Android via patchlevel.

---

## 2025

- **CVE-2025-27363** — OOB write en **FreeType** ≤ 2.13.0 al parsear fuentes TrueType GX. Android distribuye FreeType vulnerable hasta Android 14 patch level marzo 2025. **Explotada in-the-wild** según el boletín de seguridad Android de mayo 2025 (Google fija el flag _limited, targeted exploitation_). Funciona como RCE → LPE en cadenas modernas.
- **CVE-2025-0072** — Memory corruption en Mali GPU r49p0 – r52p0 (ARM driver), reportada por Project Zero. Pixel y muchos Samsung.
- **CVE-2025-21043** — Buffer overflow en `libimagecodec.quram` (Samsung Galaxy). **Explotada in-the-wild** contra Samsung según el reporte de Samsung de septiembre 2025; cadena junto con un bug de mensajería para alcanzar `system_server`-equivalente.
- **CVE-2025-21479** y **CVE-2025-21480** — Memory corruption en el GPU **Adreno** (Qualcomm GPU microcode). **Explotadas in-the-wild** según Qualcomm en junio 2025 (vendor comercial no nombrado, dispositivos Snapdragon 8 Gen 1/2/3).
- **CVE-2025-27038** — UAF en Adreno (`process_private`), parcheado por Qualcomm en mayo 2025.
- **CVE-2025-48543** — LPE en Android Runtime (ART). Permite a una app no privilegiada escalar a otra app o a UID `system` mediante una race durante carga de `dex`. Boletín Android octubre 2025.
- **CVE-2025-48530** — Bug en Android System (Bluetooth pairing), encadenable con CVE-2025-48543 para escalada completa.

---

## Observaciones generales de la cronología

1. **El GPU es la nueva superficie estrella**. Desde 2022, casi todas las cadenas explotadas en el mundo real contra Android usan un bug de **Mali (ARM)** o **Adreno (Qualcomm)**, porque están directamente expuestos a apps sin permisos y los vendors tardan en publicar parches.
2. **Binder se sigue rompiendo**, pero menos: GKI, KCFI y los mitigaciones de Project Zero han reducido el ratio.
3. **Los bugs de kernel Linux genéricos** (netfilter, eBPF, io_uring, ALSA) **sí impactan Android**, pero su explotación pública suele requerir `user_namespaces`, que AOSP por defecto restringe; los vendors que los habilitan amplían la superficie.
4. **El bypass de SELinux** rara vez aparece como un CVE propio; suele ser una propiedad emergente de cómo se monta el exploit de kernel (sobreescribir `selinux_state.enforcing`, o falsear el contexto del thread actual).
5. La etiqueta **"under limited, targeted exploitation"** en los Android Security Bulletins desde 2023 es un buen indicador de qué CVEs realmente se usaron por vendors comerciales (NSO, Cytrox, Intellexa, Variston).

---

## Referencias y lecturas recomendadas

- Boletines de seguridad de Android: <https://source.android.com/docs/security/bulletin>
- Boletines de Qualcomm: <https://docs.qualcomm.com/product/publicresources/securitybulletin/>
- Boletines de Samsung Mobile: <https://security.samsungmobile.com/securityUpdate.smsb>
- Project Zero — _Issue Tracker_ y posts de Man Yue Mo y Maddie Stone sobre Mali, Adreno y Binder.
- Google TAG: reportes anuales de exploits 0-day in-the-wild.

> Nota: esta cronología cubre desde 2020 hasta mayo de 2026. Los CVEs marcados como _in-the-wild_ son los que tanto Google como los vendors han confirmado que se usaron en ataques reales antes del parche; el resto tienen PoC público o privado conocido contra Android.
