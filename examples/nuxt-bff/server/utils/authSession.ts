import { randomBytes } from 'node:crypto'
import type { H3Event } from 'h3'
import { createError, deleteCookie, getCookie, setCookie } from 'h3'

const SESSION_COOKIE = '__Host-colors_session'

export interface ServerAuthSession {
  accessToken: string
  refreshToken: string
  csrfToken: string
  accessExpiresAt: number
  refreshAbsoluteExpiresAt: number
  user: Record<string, unknown>
}

function cookieValue(headers: Headers, name: string): string {
  const entries = headers.getSetCookie?.() ?? []
  for (const value of entries) {
    const [pair] = value.split(';', 1)
    const separator = pair.indexOf('=')
    if (separator > 0 && pair.slice(0, separator) === name) {
      return pair.slice(separator + 1)
    }
  }
  throw createError({ statusCode: 502, statusMessage: `Upstream did not set ${name}` })
}

export async function createBrowserSession(
  event: H3Event,
  upstream: Response,
  payload: any,
): Promise<void> {
  const config = useRuntimeConfig(event)
  const id = randomBytes(32).toString('base64url')
  const session: ServerAuthSession = {
    accessToken: payload.access_token,
    refreshToken: cookieValue(upstream.headers, '__Host-epok_refresh'),
    csrfToken: payload.csrf_token,
    accessExpiresAt: Date.now() + payload.expires_in * 1000,
    refreshAbsoluteExpiresAt: Date.parse(payload.refresh_absolute_expires_at),
    user: payload.user,
  }
  await useStorage('auth').setItem(id, session)
  setCookie(event, SESSION_COOKIE, id, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/',
    maxAge: Math.floor((session.refreshAbsoluteExpiresAt - Date.now()) / 1000),
  })
}

export async function requireBrowserSession(event: H3Event): Promise<[string, ServerAuthSession]> {
  const id = getCookie(event, SESSION_COOKIE)
  if (!id) throw createError({ statusCode: 401, statusMessage: 'Unauthorized' })
  const session = await useStorage('auth').getItem<ServerAuthSession>(id)
  if (!session) throw createError({ statusCode: 401, statusMessage: 'Unauthorized' })
  return [id, session]
}

export async function destroyBrowserSession(event: H3Event): Promise<void> {
  const id = getCookie(event, SESSION_COOKIE)
  if (id) await useStorage('auth').removeItem(id)
  deleteCookie(event, SESSION_COOKIE, { secure: true, sameSite: 'lax', path: '/' })
}
