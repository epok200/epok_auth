import { createBrowserSession } from '../../utils/authSession'

export default defineEventHandler(async (event) => {
  const config = useRuntimeConfig(event)
  const credentials = await readBody(event)
  const response = await $fetch.raw(`${config.authApiBase}/api/v1/auth/login`, {
    method: 'POST',
    body: credentials,
    headers: { Origin: config.public.appOrigin },
  })
  await createBrowserSession(event, response, response._data)
  return { user: response._data.user }
})
