# Nuxt/Nitro BFF reference

This example demonstrates the intended security boundary; it is not bundled into the Python package.

The browser receives only an opaque `__Host-colors_session` cookie. Nitro stores access, refresh and CSRF material server-side under that identifier. Configure Nitro storage with Redis or another durable private driver in production; do not use browser storage or expose tokens through `useState`/Pinia.

The snippets assume `runtimeConfig.authApiBase`, `runtimeConfig.public.appOrigin`, and a private Nitro storage mount named `auth`.
