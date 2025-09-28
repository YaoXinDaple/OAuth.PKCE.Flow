<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { API_BASE, CLIENT_ID, REDIRECT_URI } from '../config'

const router = useRouter()
const route = useRoute()
const err = ref<string | null>(null)

function toFormBody(params: Record<string, string>) {
  const usp = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) usp.set(k, v)
  return usp.toString()
}

onMounted(async () => {
  const code = String(route.query.code || '')
  const state = String(route.query.state || '')
  const savedState = sessionStorage.getItem('pkce:state')
  const verifier = sessionStorage.getItem('pkce:verifier')

  if (!code || !state || !savedState || !verifier || state !== savedState) {
    err.value = '回调参数或状态无效'
    return
  }

  try {
    const body = toFormBody({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier: verifier
    })

    const resp = await fetch(API_BASE + '/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body
    })

    if (!resp.ok) throw new Error(`${resp.status} ${resp.statusText}`)
    const json = await resp.json()

    localStorage.setItem('access_token', json.access_token)
    // 清理一次性数据
    sessionStorage.removeItem('pkce:state')
    sessionStorage.removeItem('pkce:verifier')

    router.replace('/')
  } catch (e: any) {
    err.value = e.message || String(e)
  }
})
</script>

<template>
  <main style="max-width: 720px; margin: 32px auto;">
    <h3>正在处理回调...</h3>
    <p v-if="err" style="color:crimson;">{{ err }}</p>
  </main>
</template>

