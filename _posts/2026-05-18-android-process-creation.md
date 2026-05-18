---
layout: post
title: "Anatomía de la creación de procesos en Android: del kernel a Zygote y app_process"
date: 2026-05-18 10:00:00
description: Walkthrough técnico y detallado del ciclo completo de creación de un proceso en Android, desde fork() en el kernel Linux hasta el bootstrap de una aplicación a través de Zygote y app_process.
tags: android internals zygote kernel security
categories: android-internals
featured: true
toc:
  beginning: true
---

> Este artículo recorre, con un nivel de detalle considerable, el camino que sigue Android para materializar un proceso de aplicación. Empezaremos en el kernel Linux (la llamada `clone()` y `copy_process()`), pasaremos por `init`, el binario `app_process`, la inicialización de `AndroidRuntime`, la bifurcación del **Zygote** y terminaremos cuando `ActivityThread.main()` empieza a despachar mensajes en el hilo principal de la app. El objetivo es entender no solo "cómo se lanza una app", sino qué primitivas, decisiones de diseño y consideraciones de seguridad están en juego en cada paso.

## 1. Contexto: por qué importa entender este flujo

Android es, en esencia, un Linux con un userland radicalmente distinto al de cualquier distribución GNU/Linux. La capa de aplicación se ejecuta sobre una máquina virtual gestionada (ART) y cada app vive en su propio proceso aislado por UID, SELinux y seccomp. Toda esa arquitectura descansa sobre un truco muy concreto: en lugar de arrancar una nueva instancia de ART desde cero cada vez que el usuario abre una app, Android **clona** un proceso ya inicializado con todas las clases del framework cargadas. Ese proceso plantilla es el **Zygote**.

Entender este flujo es valioso para:

- **Ingeniería de rendimiento**: las optimizaciones de _cold start_, _preload_, y _class preinit_ se sitúan justo aquí.
- **Seguridad ofensiva y defensiva**: la superficie de ataque de Zygote (sockets `UNIX`, comandos en texto, herencia de descriptores) ha producido múltiples CVEs.
- **Forense y análisis de malware**: distinguir un proceso forkeado legítimamente de uno inyectado vía `app_process` "a mano" requiere reconocer estas señales.
- **Diseño de sandboxes**: muchas decisiones (SELinux domain transition, seccomp, capabilities drop) ocurren post-fork y no antes.

## 2. La base: `fork`, `clone` y `copy_process` en el kernel

### 2.1 De `fork(2)` a `clone(2)`

En Linux moderno **`fork()` no es una syscall propia**: la libc (Bionic en Android) la implementa sobre `clone()`. Bionic, en `bionic/libc/bionic/fork.cpp`, hace algo equivalente a:

```c
int fork(void) {
    __bionic_atfork_run_prepare();

    pid_t pid = clone(nullptr,
                      nullptr,
                      (SIGCHLD | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID),
                      nullptr,
                      nullptr,
                      nullptr,
                      &(self->tid));

    if (pid == 0) {
        // Child
        __bionic_atfork_run_child();
    } else {
        // Parent
        __bionic_atfork_run_parent();
    }
    return pid;
}
```

Lo importante:

- `SIGCHLD` indica al padre que reciba esa señal cuando el hijo muera (semántica clásica de `fork`).
- `CLONE_CHILD_SETTID` / `CLONE_CHILD_CLEARTID` permiten que el TID del hijo se publique en una dirección de memoria y se limpie al exit; esto es lo que hace que `pthread_join`/futex funcionen correctamente.
- **No se pasa ningún flag `CLONE_VM`, `CLONE_FS`, `CLONE_FILES`, `CLONE_SIGHAND`**: por eso el hijo recibe una copia (copy-on-write) del espacio de direcciones, su propia tabla de descriptores, su propia tabla de señales, etc. Esto es la diferencia entre `fork()` y un hilo.

### 2.2 Lo que ocurre en `copy_process()`

Dentro del kernel (`kernel/fork.c`), `clone()` invoca a `kernel_clone()` que llama a `copy_process()`. Allí se construye el nuevo `task_struct`:

```c
static __latent_entropy struct task_struct *copy_process(
        struct pid *pid,
        int trace,
        int node,
        struct kernel_clone_args *args)
{
    /* 1. dup_task_struct: nuevo task_struct + stack del kernel */
    p = dup_task_struct(current, node);

    /* 2. Comprobaciones de credenciales y rlimit RLIMIT_NPROC */
    retval = copy_creds(p, clone_flags);
    if (atomic_read(&p->real_cred->user->processes) >=
        task_rlimit(p, RLIMIT_NPROC)) ...

    /* 3. Duplicación de subsistemas según los flags CLONE_* */
    retval = copy_files(clone_flags, p);
    retval = copy_fs(clone_flags, p);
    retval = copy_sighand(clone_flags, p);
    retval = copy_signal(clone_flags, p);
    retval = copy_mm(clone_flags, p);   /* COW vía dup_mmap */
    retval = copy_namespaces(clone_flags, p);
    retval = copy_io(clone_flags, p);
    retval = copy_thread(clone_flags, args->stack, ...);

    /* 4. Alta en las tablas: pid hash, lista del padre, cgroup */
    attach_pid(p, PIDTYPE_PID);
    ...
}
```

Lo más relevante para Android:

- **`copy_mm()` y COW**: el `mm_struct` se duplica con `dup_mmap()`. Las VMAs anónimas y privadas se marcan **copy-on-write**: las páginas físicas no se replican hasta la primera escritura. Esto es la razón por la que un fork de Zygote (que tiene cientos de MB de heap ART, `boot.art`, clases del framework, recursos, etc.) cuesta pocos milisegundos y unos pocos KB iniciales de RAM.
- **`copy_files()`**: el hijo hereda los `fd` abiertos del padre. Esto **es un problema de seguridad** que Zygote ataja explícitamente cerrando descriptores antes y validando los que sobreviven.
- **`copy_creds()`**: por defecto el hijo hereda UID/GID; Android sobrescribe estas credenciales post-fork con `setresuid/setresgid` para asignar el UID de la app.

### 2.3 SELinux, capabilities y seccomp también se heredan

El kernel propaga al hijo:

- El **dominio SELinux** actual (definido por la política, transitable con `setexeccon`/`security_bounded_transition`).
- El conjunto de **capabilities** (`cap_effective`, `cap_permitted`, `cap_inheritable`, `cap_bset`, `cap_ambient`).
- Los filtros **seccomp-bpf** instalados con `PR_SET_SECCOMP` o `seccomp(2)`.

Esto significa que cualquier endurecimiento aplicado **antes** del fork se hereda, y cualquier endurecimiento adicional debe aplicarse **después** en el hijo. Zygote utiliza ambos enfoques (algunos seccomp filters están en el Zygote, otros se instalan en el child).

## 3. Userspace: del `init` al Zygote

### 3.1 `init` arranca todo

`init` (PID 1) es el primer proceso de userland. Está implementado en C++ (`system/core/init/`) y parsea `init.rc`. Una sección relevante de `system/core/rootdir/init.zygote64.rc` se ve así:

```bash
service zygote /system/bin/app_process64 -Xzygote /system/bin --zygote --start-system-server
    class main
    priority -20
    user root
    group root readproc reserved_disk
    socket zygote stream 660 root system
    socket usap_pool_primary stream 660 root system
    onrestart write /sys/android_power/request_state wake
    onrestart restart audioserver
    onrestart restart cameraserver
    onrestart restart media
    onrestart restart netd
    onrestart restart wificond
    writepid /dev/cpuset/foreground/tasks
```

Puntos a destacar:

- **`/system/bin/app_process64`** es el binario que arranca: es ELF nativo, no Dalvik/ART.
- **`socket zygote stream 660 root system`**: `init` crea un socket Unix de tipo `SOCK_STREAM` en `/dev/socket/zygote` antes de hacer `execve`, y pasa el `fd` ya abierto al proceso via la variable de entorno `ANDROID_SOCKET_zygote`. Es a través de ese socket por donde `system_server` (y luego el framework) le pedirá nuevos forks.
- **`onrestart ...`**: si Zygote muere, varios servicios críticos se reinician en cascada. Matar al Zygote equivale efectivamente a reiniciar el espacio de usuario.
- **`--start-system-server`**: la primera tarea de Zygote, tras inicializar el runtime, es forkearse para crear `system_server`.

En arquitecturas de 64 bits con apps de 32, conviven `zygote64` y `zygote` (32 bits) o el llamado `zygote64_32` en modo dual. Ambos escuchan en sockets distintos.

### 3.2 Anatomía de `app_process`

`frameworks/base/cmds/app_process/app_main.cpp` es el `main()` nativo. Simplificado:

```c++
int main(int argc, char* const argv[])
{
    // ...parseo de flags --zygote, --start-system-server, --application,
    //    --nice-name=, etc...

    AppRuntime runtime(argv[0], computeArgBlockSize(argc, argv));
    runtime.addOption(strdup(argv0));

    // Procesar runtime args: -Xzygote, etc.
    for (i = 1; i < argc; i++) { ... }

    if (zygote) {
        runtime.start("com.android.internal.os.ZygoteInit",
                      args, zygote);
    } else if (className) {
        runtime.start("com.android.internal.os.RuntimeInit",
                      args, zygote);
    } else {
        fprintf(stderr, "Error: no class name or --zygote supplied.\n");
        app_usage();
        LOG_ALWAYS_FATAL("app_process: no class name or --zygote supplied.");
    }
}
```

Lo que hace, paso a paso:

1. Construye un `AppRuntime` (subclase de `AndroidRuntime`).
2. Parsea los argumentos. `--zygote` activa la rama de bootstrap del Zygote; `--application` arranca una clase Java arbitraria (modo "ejecutable java").
3. Llama a `AndroidRuntime::start("com.android.internal.os.ZygoteInit", ...)`.

`app_process` es también el binario que utilizan cosas como `am`, `pm`, herramientas de debug y, notablemente, ataques o pruebas de inyección donde se quiere lanzar código Java arbitrario con una identidad determinada. Por eso ver `app_process` ejecutándose con argumentos no estándar es siempre una señal a vigilar.

### 3.3 `AndroidRuntime::start` crea la VM

`frameworks/base/core/jni/AndroidRuntime.cpp`:

```c++
void AndroidRuntime::start(const char* className, const Vector<String8>& options, bool zygote)
{
    // 1. Inicializar JNI invocando JNI_CreateJavaVM con opciones ART.
    JNIEnv* env;
    if (startVm(&mJavaVM, &env, zygote, primary_zygote) != 0) {
        return;
    }
    onVmCreated(env);

    // 2. Registrar todas las funciones JNI del framework (cientos).
    if (startReg(env) < 0) { ... }

    // 3. Localizar la clase Java de entrada (ZygoteInit o RuntimeInit).
    char* slashClassName = toSlashClassName(className);
    jclass startClass = env->FindClass(slashClassName);

    // 4. Localizar el método estático main([Ljava/lang/String;)V
    jmethodID startMeth = env->GetStaticMethodID(startClass, "main",
            "([Ljava/lang/String;)V");

    // 5. Invocarlo. Aquí cedemos el control al mundo Java.
    env->CallStaticVoidMethod(startClass, startMeth, strArray);
}
```

Cosas clave:

- **`startVm`** decide los argumentos para `JNI_CreateJavaVM`: tamaño de heap, image path (`boot.art`), modo JIT, opciones de GC, debug, etc. Algunas opciones son distintas según _es Zygote_ o no (por ejemplo, el GC se comporta diferente para favorecer el COW).
- **`startReg`** invoca `register_jni_procs()`, que registra una tabla enorme de funciones nativas. Esto es lo que permite que `Surface`, `Binder`, `ParcelFileDescriptor`, etc. tengan implementación nativa.
- A partir del `CallStaticVoidMethod`, **estamos en Java dentro del Zygote**.

## 4. El Zygote en Java: `ZygoteInit.main()`

El fichero clave es `frameworks/base/core/java/com/android/internal/os/ZygoteInit.java`. Su `main()` realiza la inicialización pesada **una sola vez** para que todos los hijos hereden el trabajo ya hecho.

```java
public static void main(String[] argv) {
    ZygoteServer zygoteServer = null;
    try {
        Trace.traceBegin(Trace.TRACE_TAG_DALVIK, "ZygoteInit");

        RuntimeInit.preForkInit();

        // Bootclasspath y librerías
        bootTimingsTraceLog.traceBegin("ZygoteInit");
        ZygoteInit.preload(bootTimingsTraceLog);

        // GC explícito y heap trim: deja la imagen "limpia"
        // antes de empezar a forkear.
        gcAndFinalize();

        Zygote.initNativeState(isPrimaryZygote);

        ZygoteHooks.stopZygoteNoThreadCreation();

        zygoteServer = new ZygoteServer(isPrimaryZygote);

        if (startSystemServer) {
            Runnable r = forkSystemServer(abiList, zygoteSocketName, zygoteServer);
            if (r != null) {
                r.run();
                return;
            }
        }

        // Bucle de servidor: aceptar conexiones del socket y forkear.
        caller = zygoteServer.runSelectLoop(abiList);
    } finally {
        if (zygoteServer != null) zygoteServer.closeServerSocket();
    }

    // Si llegamos aquí, somos un proceso forkeado al que
    // runSelectLoop le ha devuelto un Runnable. Lo ejecutamos.
    if (caller != null) caller.run();
}
```

Hay varias fases distintas que conviene desgranar.

### 4.1 `preload()`: el corazón del modelo Zygote

```java
static void preload(TimingsTraceLog bootTimingsTraceLog) {
    beginIcuCachePinning();
    bootTimingsTraceLog.traceBegin("PreloadClasses");
    preloadClasses();
    bootTimingsTraceLog.traceEnd();

    bootTimingsTraceLog.traceBegin("CacheNonBootClasspathClassLoaders");
    cacheNonBootClasspathClassLoaders();
    bootTimingsTraceLog.traceEnd();

    bootTimingsTraceLog.traceBegin("PreloadResources");
    Resources.preloadResources();
    bootTimingsTraceLog.traceEnd();

    nativePreloadAppProcessHALs();
    maybePreloadGraphicsDriver();
    preloadSharedLibraries();
    preloadTextResources();
    WebViewFactory.prepareWebViewInZygote();

    endIcuCachePinning();
    warmUpJcaProviders();
    sPreloadComplete = true;
}
```

- **`preloadClasses()`** lee `/system/etc/preloaded-classes` (varios miles de nombres totalmente cualificados) y las inicializa con `Class.forName(name, true, classLoader)`. El `initialize=true` ejecuta los `<clinit>` estáticos, lo que llena los pools y caches del framework. Coste: ~30–60 segundos en el primer boot. Beneficio: cada app forkeada arranca con todo eso "gratis" gracias al COW.
- **`Resources.preloadResources()`** carga drawables y atributos comunes del `framework-res.apk`.
- **`WebViewFactory.prepareWebViewInZygote()`** mapea y enlaza la WebView seleccionada en el Zygote para que sus apps la compartan sin pagar otra vez la carga.
- **`preloadSharedLibraries()`** hace `System.loadLibrary` de `android`, `compiler_rt`, `jnigraphics`, etc.

> **Nota de rendimiento**: cualquier clase que **no** esté en `preloaded-classes` y que la app cargue en arranque, paga JIT/PLT/relocaciones por su cuenta. Los OEMs ajustan este fichero para reducir _cold start_.

### 4.2 `gcAndFinalize()` y la magia del COW

Después del `preload`, el Zygote ejecuta:

```java
static void gcAndFinalize() {
    Runtime runtime = Runtime.getRuntime();
    System.runFinalization();
    runtime.gc();
    System.runFinalization();
    runtime.gc();
}
```

El objetivo es **dejar el heap lo más compacto y "tocado" posible** justo antes de empezar a forkear. ART implementa el GC con la compactación pensada para esto: si el heap está bien empaquetado, los hijos comparten páginas físicas durante mucho más tiempo y la métrica `PSS` (Proportional Set Size) por app se mantiene baja.

### 4.3 `ZygoteServer`: socket + select-loop

`ZygoteServer` recupera el `fd` heredado de `init` desde la variable `ANDROID_SOCKET_zygote` y se sitúa a escuchar:

```java
ZygoteServer(boolean isPrimaryZygote) {
    mUsapPoolEventFd = Zygote.getUsapPoolEventFD();
    if (isPrimaryZygote) {
        mZygoteSocket = Zygote.createManagedSocketFromInitSocket(
                Zygote.PRIMARY_SOCKET_NAME);   // "zygote"
        mUsapPoolSocket = Zygote.createManagedSocketFromInitSocket(
                Zygote.USAP_POOL_PRIMARY_SOCKET_NAME);
    } else {
        mZygoteSocket = Zygote.createManagedSocketFromInitSocket(
                Zygote.SECONDARY_SOCKET_NAME); // "zygote_secondary"
        ...
    }
    fetchUsapPoolPolicyProps();
}
```

`runSelectLoop` se queda en un `Os.poll()` sobre tres tipos de descriptores:

1. El socket de servidor: nuevas conexiones (típicamente desde `system_server`).
2. Las conexiones aceptadas: comandos `--fork-child`, `--query-abi-list`, etc.
3. El `eventfd` que controla el _USAP pool_.

Cuando llega un comando, lo deserializa con `ZygoteArguments` (una bolsa de flags como `--setuid=`, `--setgid=`, `--target-sdk-version=`, `--nice-name=`, `--seinfo=`, `--instruction-set=`) y dispara `Zygote.forkAndSpecialize(...)`.

### 4.4 USAP: el _Unspecialized App Process_ pool

A partir de Android 10 existe el _USAP pool_: un conjunto de procesos hijos del Zygote **ya forkeados pero todavía sin especializar** (sin UID, sin SELinux domain final, sin seccomp final). Cuando llega una petición de arranque, el Zygote elige uno del pool y le envía la "especialización" por su socket. Esto evita el `fork()` en la ruta crítica de _cold start_.

El pool se gestiona con un `eventfd` que se señaliza cuando hay que rellenar; los USAP esperan en un `read()` bloqueante sobre su socket personal.

## 5. El fork especializado: `Zygote.forkAndSpecialize`

El método `Zygote.forkAndSpecialize` es la puerta entre el mundo "soy el Zygote" y el mundo "soy una app concreta". Su firma es enorme porque recibe absolutamente todo lo necesario para configurar el hijo antes de que ejecute código de aplicación:

```java
public static int forkAndSpecialize(int uid, int gid, int[] gids,
        int runtimeFlags, int[][] rlimits, int mountExternal,
        String seInfo, String niceName, int[] fdsToClose, int[] fdsToIgnore,
        boolean startChildZygote, String instructionSet, String appDataDir,
        boolean isTopApp, String[] pkgDataInfoList,
        String[] allowlistedDataInfoList, boolean bindMountAppDataDirs,
        boolean bindMountAppStorageDirs) {

    ZygoteHooks.preFork();

    int pid = nativeForkAndSpecialize(uid, gid, gids, runtimeFlags, rlimits,
            mountExternal, seInfo, niceName, fdsToClose, fdsToIgnore,
            startChildZygote, instructionSet, appDataDir, isTopApp,
            pkgDataInfoList, allowlistedDataInfoList,
            bindMountAppDataDirs, bindMountAppStorageDirs);

    if (pid == 0) {
        Trace.setTracingEnabled(true, runtimeFlags);
        Trace.traceBegin(Trace.TRACE_TAG_ACTIVITY_MANAGER, "PostFork");
    } else {
        Trace.setTracingEnabled(false, 0);
    }

    ZygoteHooks.postForkCommon();
    return pid;
}
```

### 5.1 El descenso a JNI: `com_android_internal_os_Zygote.cpp`

El `nativeForkAndSpecialize` salta a C++ en `frameworks/base/core/jni/com_android_internal_os_Zygote.cpp`. La estructura, simplificada, es:

```c++
static pid_t ForkCommon(JNIEnv* env, bool is_system_server,
                        const std::vector<int>& fds_to_close,
                        const std::vector<int>& fds_to_ignore,
                        bool is_priority_fork) {

    SetSignalHandlers();                              // (1)

    // Bloquear SIGCHLD durante el fork
    BlockSignal(SIGCHLD, fail_fn);

    __android_log_close();                            // (2)
    AStatsSocket_close();
    stats_log_close();

    // Cerrar los fds que NO deben heredarse, validar el resto
    FileDescriptorAllowlist::Get()->Allow(fds_to_ignore);
    fds_to_close_table.Restat();                      // (3)

    pid_t pid = fork();

    if (pid == 0) {
        // ---------- HIJO ----------
        if (is_priority_fork) {
            setpriority(PRIO_PROCESS, 0, PROCESS_PRIORITY_MAX);
        }
        PreApplicationInit();
    } else {
        // ---------- PADRE ----------
        UnblockSignal(SIGCHLD, fail_fn);
    }
    return pid;
}
```

Notas:

1. **`SetSignalHandlers`** reinstala manejadores; entre otras cosas un handler de `SIGCHLD` que abortar limpia si un hijo muere antes de especializarse.
2. **Cerrar logs, statsd, etc.**: evita que dos procesos compartan descriptores de log y se pisen.
3. **`FileDescriptorTable`** (`bionic` + framework) lleva un registro de **qué `fd` están permitidos** en el Zygote (sockets de log allowlisted, `/dev/null`, fonts, etc.). Cualquier `fd` no allowlisted que sobreviva al fork **es un error** y aborta el proceso. Este mecanismo cierra un vector clásico de fuga de privilegios.

Después de `ForkCommon`, en el hijo se ejecuta `SpecializeCommon`:

```c++
static void SpecializeCommon(JNIEnv* env, uid_t uid, gid_t gid,
        jintArray gids, jint runtime_flags, jobjectArray rlimits,
        jlong permitted_capabilities, jlong effective_capabilities,
        jint mount_external, jstring managed_se_info,
        jstring managed_nice_name, bool is_system_server,
        bool is_child_zygote, jstring managed_instruction_set,
        jstring managed_app_data_dir, bool is_top_app,
        jobjectArray pkg_data_info_list, ...) {

    // (a) Mount namespace y vista del almacenamiento externo.
    MountEmulatedStorage(uid, mount_external, ...);

    // (b) Configurar UID/GID. ¡Esto es lo que convierte al proceso
    //     en "la app". No vuelve atrás.
    if (setresgid(gid, gid, gid) == -1) fail_fn(...);
    if (setgroups(gids_size, gids_data) == -1) fail_fn(...);
    SetInheritable(permitted_capabilities, fail_fn);
    DropCapabilitiesBoundingSet(fail_fn);
    if (setresuid(uid, uid, uid) == -1) fail_fn(...);

    // (c) Capabilities efectivas finales.
    SetCapabilities(permitted_capabilities, effective_capabilities,
                    permitted_capabilities, fail_fn);

    // (d) Aplicar seccomp.
    SetSchedulerPolicy(fail_fn, is_top_app);
    SetUpSeccompFilter(uid, is_child_zygote);

    // (e) Transición de dominio SELinux.
    rc = selinux_android_setcontext(uid, is_system_server, se_info_c_str,
                                    nice_name_c_str);

    // (f) Nombre del proceso (visible en /proc/<pid>/comm).
    if (nice_name.has_value()) SetThreadName(nice_name.value());

    // (g) Re-inicializar pseudo-aleatoriedad, OpenSSL, etc.
    __android_log_close();
    AndroidLogger_OnLogChanged();
    stats_log_init();

    // (h) Hooks Java post-fork (resetear caches, hilos de finalizer, GC).
    env->CallStaticVoidMethod(gZygoteClass, gCallPostForkChildHooks,
            runtime_flags, is_system_server, is_child_zygote, instruction_set);
}
```

El orden importa muchísimo. En particular:

- `setresgid`, `setgroups`, `setresuid` se hacen **después** de configurar capabilities permitidas heredables, porque `setresuid` desde root con UID no-cero puede limpiar el conjunto efectivo si no se ha preparado `PR_SET_KEEPCAPS` correctamente.
- `selinux_android_setcontext` aplica `setcon` para que el siguiente `execve` (si lo hubiera) o las syscalls del proceso pasen por el dominio `untrusted_app`, `priv_app`, `platform_app`, etc., según el `seinfo` que asigna `PackageManager`.
- `SetUpSeccompFilter` instala un BPF filter distinto según se trate de `system_server`, app o app aislada (`isolated_app`). El filtro restringe el conjunto de syscalls; cualquier desviación produce `SIGSYS`.

### 5.2 `PreApplicationInit` y el regreso a Java

Al final, en el hijo se llaman los hooks de Java `Zygote.callPostForkChildHooks`, que:

- Resetean el `Random` per-process (no queremos que dos apps deriven la misma secuencia).
- Notifican a ART que ahora puede activar JIT/profile saving (en el Zygote estaba deshabilitado).
- Reactivan el _heap task daemon_.
- Resetean caches dependientes de PID/UID.

Y por fin se devuelve un `Runnable` al `runSelectLoop`. Ese `Runnable` es lo que ejecutará el `main` de la app.

## 6. De `Zygote` a `ActivityThread.main`

El `Runnable` devuelto por el Zygote, para una app normal, lo construye `ZygoteConnection.handleChildProc -> ZygoteInit.zygoteInit`:

```java
public static final Runnable zygoteInit(int targetSdkVersion, long[] disabledCompatChanges,
        String[] argv, ClassLoader classLoader) {
    RuntimeInit.redirectLogStreams();

    RuntimeInit.commonInit();
    ZygoteInit.nativeZygoteInit();   // (1)

    return RuntimeInit.applicationInit(targetSdkVersion, disabledCompatChanges,
            argv, classLoader);
}
```

1. **`nativeZygoteInit`** llama, vía JNI, a `AppRuntime::onZygoteInit()` que arranca el **Binder thread pool** (`ProcessState::self()->startThreadPool()`). Desde este momento, el proceso puede recibir transacciones Binder.
2. **`applicationInit`** parsea los argumentos restantes y reflexivamente invoca el `main` de la clase indicada, que para una app es `android.app.ActivityThread`:

```java
protected static Runnable applicationInit(int targetSdkVersion, long[] disabledCompatChanges,
        String[] argv, ClassLoader classLoader) {
    nativeSetExitWithoutCleanup(true);
    VMRuntime.getRuntime().setTargetSdkVersion(targetSdkVersion);
    VMRuntime.getRuntime().setDisabledCompatChanges(disabledCompatChanges);

    final Arguments args = new Arguments(argv);

    return findStaticMain(args.startClass, args.startArgs, classLoader);
}
```

`findStaticMain` no invoca directamente, devuelve un `Runnable` que cuando se ejecute hará `methodMain.invoke(null, (Object) args)`. Eso permite al Zygote **devolver el control limpio** al loop principal: el `Runnable` se ejecuta fuera de cualquier `try/catch` de Zygote, en el stack mínimo del proceso recién especializado.

### 6.1 `ActivityThread.main`

```java
public static void main(String[] args) {
    Trace.traceBegin(Trace.TRACE_TAG_ACTIVITY_MANAGER, "ActivityThreadMain");

    Looper.prepareMainLooper();

    ActivityThread thread = new ActivityThread();
    thread.attach(false, startSeq);   // <-- llama a AMS.attachApplication

    if (sMainThreadHandler == null) {
        sMainThreadHandler = thread.getHandler();
    }

    Looper.loop();
    throw new RuntimeException("Main thread loop unexpectedly exited");
}
```

Cosas importantes:

- **`Looper.prepareMainLooper()`**: instala el `MessageQueue` del hilo principal. El _UI thread_ y el _main thread_ son el mismo en Android para las apps.
- **`thread.attach(false, startSeq)`** realiza una llamada Binder a `ActivityManagerService.attachApplication(IApplicationThread, long)`. Es ese `attachApplication` el que cierra el lazo con `system_server`: AMS estaba esperando este momento desde que pidió el fork al Zygote. Ahora AMS sabe a qué proceso enviar `bindApplication`, `scheduleLaunchActivity`, etc.
- A partir de `Looper.loop()`, el proceso vive despachando mensajes hasta que el sistema lo mate.

## 7. La vista panorámica: secuencia completa

Si juntamos todo, una llamada a `Context.startActivity(intent)` que arranca una app fría se traduce, simplificadamente, en:

1. La app emisora hace IPC Binder a `ActivityManagerService` (en `system_server`).
2. AMS resuelve el `ComponentName`, comprueba permisos, encuentra que el proceso _target_ no existe.
3. AMS llama a `Process.start("android.app.ActivityThread", ...)` que termina hablando por el socket Unix `/dev/socket/zygote` con un comando textual.
4. `ZygoteServer.runSelectLoop` despierta del `poll`, lee el comando, construye `ZygoteArguments` y llama a `Zygote.forkAndSpecialize`.
5. JNI: `ForkCommon` cierra `fd` no allowlisted y hace `fork()`.
6. El kernel ejecuta `copy_process` (COW del heap ART, duplicado de fd allowed, herencia de namespaces, capabilities, seccomp, contexto SELinux).
7. En el hijo, `SpecializeCommon` aplica UID/GID, GIDs suplementarios, drop de capabilities, transición SELinux y seccomp final.
8. `nativeZygoteInit` arranca el pool de hilos Binder.
9. `RuntimeInit.applicationInit` devuelve el `Runnable` que llama a `ActivityThread.main`.
10. `ActivityThread.attach` llama a `AMS.attachApplication` por Binder.
11. AMS responde con `bindApplication` + `scheduleLaunchActivity`, y la actividad se infla.

Visualmente:

```text
init (PID 1)
  └── app_process64 --zygote --start-system-server   (Zygote, UID 0)
        ├── system_server (UID 1000)
        │     └── ActivityManagerService
        ├── com.android.systemui (UID 10078)
        ├── com.google.android.gms (UID 10095)
        └── com.example.app (UID 10212)              <-- nuestro fork
```

## 8. Implicaciones de seguridad

Esta arquitectura tiene consecuencias de seguridad muy concretas que conviene tener presentes:

### 8.1 El socket del Zygote es un punto de poder enorme

Quien pueda escribir comandos válidos en `/dev/socket/zygote` puede pedir un fork con cualquier UID y `seinfo` que la peer-credential validation permita. Por eso:

- El socket es `0660 root:system`. Solo procesos del grupo `system` (esencialmente `system_server`) escriben.
- El Zygote valida `SO_PEERCRED` y rechaza peticiones de UIDs no esperados.
- Hubo CVEs históricos (por ejemplo, alrededor del parseo de argumentos o de fugas de `fd`) precisamente en esta superficie.

### 8.2 Herencia descontrolada de descriptores = escalada

Si Zygote dejara abierto, accidentalmente, un `fd` a, digamos, `/data/system/packages.xml`, **todas las apps** lo heredarían. Por eso existe `FileDescriptorAllowlist`: se mantiene una whitelist explícita y todo lo demás aborta el proceso. Cualquier ingeniero que añada un `open()` en el path del Zygote debe registrar el path en la allowlist o asegurarse de cerrarlo antes del fork.

### 8.3 Capabilities y `PR_SET_NO_NEW_PRIVS`

Las apps acaban con conjunto de capabilities **vacío** y `NO_NEW_PRIVS=1`, lo que invalida bits SUID/SGID en `execve`. Esto es lo que hace inviable elevar privilegios desde una app simplemente ejecutando un binario.

### 8.4 SELinux divide la superficie

Tras `selinux_android_setcontext`, una app cae típicamente en `untrusted_app_<sdk>`. La política prohíbe explícitamente:

- Abrir la mayoría de devices de `/dev` salvo los necesarios (binder, ashmem, render node).
- Conectarse a sockets de servicios privilegiados.
- Leer rutas como `/proc/<pid>` de otros UIDs.

Esto se aplica **después** del fork, lo cual significa que **cualquier acción que el Zygote haga antes de la especialización corre con el dominio del Zygote (`zygote`)**, no con el dominio de la app. Cuidado al añadir hooks en `preload()`.

### 8.5 Seccomp como red de seguridad

El filtro seccomp instalado en apps bloquea syscalls "raras" (e.g. `add_key`, `keyctl`, varias de `ioperm`, `ptrace` con condiciones, etc.) que rara vez necesita código Java pero que han sido históricamente vector de exploit a kernel. Un `SIGSYS` mata a la app inmediatamente y aparece en el dropbox.

### 8.6 Análisis forense

Para detectar uso anómalo de `app_process` (por ejemplo, malware que se relanza con un `nice_name` legítimo pero clase de entrada distinta), las señales útiles son:

- `/proc/<pid>/cmdline` muestra los argumentos originales: si ves `app_process` con `--application` y una clase no estándar, sospecha.
- `/proc/<pid>/status` te da `PPid`: un proceso de app cuyo `PPid` **no es** el del Zygote es muy raro.
- `/proc/<pid>/attr/current` te dice el dominio SELinux. Una "app" con dominio `shell` o `su` es señal clarísima de inyección manual.

## 9. Cosas que la gente suele entender mal

- **"Zygote usa `exec`"**: no. Zygote **nunca** hace `execve` para crear apps. Solo `fork`. Por eso el COW funciona y por eso las clases preloaded sirven de algo.
- **"Cada app tiene su propia VM"**: a nivel lógico sí, pero comparten la imagen `boot.art` mapeada y muchas páginas de heap inicial por COW. La VM "instance" es lógica.
- **"El UID se asigna al instalar"**: sí, `PackageManager` asigna un UID al instalar la app, pero el proceso solo adquiere ese UID en el `setresuid` post-fork. Antes del fork, el Zygote es root.
- **"`system_server` es un proceso aparte del Zygote"**: lo es _conceptualmente_, pero **es un fork temprano del Zygote**, no un `exec` independiente. Por eso muchas clases del framework ya están cargadas en él.
- **"`app_process` y `dalvikvm` son lo mismo"**: muy parecidos, pero `app_process` arranca con la convención del runtime Android (Zygote o no), mientras `dalvikvm` (donde aún existe) es un wrapper minimalista para ejecutar `main` de un jar.

## 10. Referencias y lecturas recomendadas

Para profundizar, las fuentes primarias son insuperables (todo está en AOSP):

- `frameworks/base/cmds/app_process/app_main.cpp`
- `frameworks/base/core/jni/AndroidRuntime.cpp`
- `frameworks/base/core/jni/com_android_internal_os_Zygote.cpp`
- `frameworks/base/core/java/com/android/internal/os/ZygoteInit.java`
- `frameworks/base/core/java/com/android/internal/os/Zygote.java`
- `frameworks/base/core/java/com/android/internal/os/ZygoteServer.java`
- `frameworks/base/core/java/com/android/internal/os/ZygoteConnection.java`
- `frameworks/base/core/java/com/android/internal/os/RuntimeInit.java`
- `frameworks/base/core/java/android/app/ActivityThread.java`
- `system/core/init/` y `system/core/rootdir/init.zygote*.rc`
- `bionic/libc/bionic/fork.cpp`
- En el kernel: `kernel/fork.c`, en concreto `copy_process()` y `dup_mmap()`.

Dos consejos prácticos para explorar AOSP por tu cuenta:

1. Usa `cs.android.com` (Code Search de Google) y enlaza por símbolo: `Zygote.forkAndSpecialize`, `ForkCommon`, `SpecializeCommon`.
2. En un dispositivo real, `dumpsys activity processes` y `cat /proc/<zygote_pid>/maps | head` enseñan cuánta memoria es compartida vía COW. Es muy ilustrativo.

---

Con esto debería quedar clara la trazabilidad completa: un `startActivity` de tu app cruza Binder, IPCs, sockets Unix, una syscall `clone`, miles de líneas de inicialización Java y termina en un `Looper.loop()` que parece magia… pero es la cuidadosa coreografía que acabamos de recorrer.
