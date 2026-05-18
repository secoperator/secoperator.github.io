// get the ninja-keys element
const ninja = document.querySelector('ninja-keys');

// add the home and posts menu items
ninja.data = [{
    id: "nav-about",
    title: "about",
    section: "Navigation",
    handler: () => {
      window.location.href = "/";
    },
  },{id: "nav-notes",
          title: "notes",
          description: "",
          section: "Navigation",
          handler: () => {
            window.location.href = "/blog/";
          },
        },{id: "post-introducción-a-la-explotación-moderna-de-v8-laboratorio-heap-cage-trusted-space-y-sandbox",
        
          title: "Introducción a la explotación moderna de V8: laboratorio, heap cage, trusted space y...",
        
        description: "Montaje de un laboratorio con d8, flags y logs útiles, modelo de memoria de V8 con pointer compression, qué vive en la heap cage frente al trusted space, y por qué existe el V8 sandbox.",
        section: "Posts",
        handler: () => {
          
            window.location.href = "/blog/2026/modern-v8-exploitation-intro/";
          
        },
      },{id: "post-anatomía-de-la-creación-de-procesos-en-android-del-kernel-a-zygote-y-app-process",
        
          title: "Anatomía de la creación de procesos en Android: del kernel a Zygote y...",
        
        description: "Walkthrough técnico y detallado del ciclo completo de creación de un proceso en Android, desde fork() en el kernel Linux hasta el bootstrap de una aplicación a través de Zygote y app_process.",
        section: "Posts",
        handler: () => {
          
            window.location.href = "/blog/2026/android-process-creation/";
          
        },
      },{id: "post-lpe-a-root-en-android-introducción-y-cronología-de-vulnerabilidades",
        
          title: "LPE a root en Android: introducción y cronología de vulnerabilidades",
        
        description: "Panorama y cronología de Local Privilege Escalation hasta root en Android, incluyendo bugs del kernel Linux que también impactan a dispositivos Android.",
        section: "Posts",
        handler: () => {
          
            window.location.href = "/blog/2026/android-lpe-root/";
          
        },
      },{
        id: 'social-rss',
        title: 'RSS Feed',
        section: 'Socials',
        handler: () => {
          window.open("/feed.xml", "_blank");
        },
      },{
        id: 'social-github',
        title: 'GitHub',
        section: 'Socials',
        handler: () => {
          window.open("https://github.com/secoperator", "_blank");
        },
      },{
      id: 'light-theme',
      title: 'Change theme to light',
      description: 'Change the theme of the site to Light',
      section: 'Theme',
      handler: () => {
        setThemeSetting("light");
      },
    },
    {
      id: 'dark-theme',
      title: 'Change theme to dark',
      description: 'Change the theme of the site to Dark',
      section: 'Theme',
      handler: () => {
        setThemeSetting("dark");
      },
    },
    {
      id: 'system-theme',
      title: 'Use system default theme',
      description: 'Change the theme of the site to System Default',
      section: 'Theme',
      handler: () => {
        setThemeSetting("system");
      },
    },];
