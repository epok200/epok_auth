import { requireBrowserSession } from '../../utils/authSession'

export default defineEventHandler(async (event) => {
  const [, session] = await requireBrowserSession(event)
  return { authenticated: true, user: session.user }
})
