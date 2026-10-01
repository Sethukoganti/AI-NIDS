/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_BACKEND_URL?: string
  readonly VITE_HMR_CLIENT_PORT?: string
  readonly VITE_HMR_PROTOCOL?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
