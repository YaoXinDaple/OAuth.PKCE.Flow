<script setup lang="ts">
import { ref } from 'vue'
import { API_BASE, CLIENT_ID, REDIRECT_URI } from '../config'

const accessToken = ref<string | null>(localStorage.getItem('access_token'))
const me = ref<any>(null)
const error = ref<string | null>(null)

function base64UrlEncode(bytes: ArrayBuffer) {
  let binary = ''
  const bytesArr = new Uint8Array(bytes)
  for (const b of bytesArr) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function sha256(input: string): Promise<ArrayBuffer> {
  const encoder = new TextEncoder()
  const data = encoder.encode(input)
  return await crypto.subtle.digest('SHA-256', data)
}

function randomString(bytes = 32) {
  const arr = new Uint8Array(bytes)
  crypto.getRandomValues(arr)
  return base64UrlEncode(arr.buffer)
}

async function startLogin() {
  error.value = null
  // 1) 生成 code_verifier & code_challenge
  const codeVerifier = randomString(64)
  const challengeBuffer = await sha256(codeVerifier)
  const codeChallenge = base64UrlEncode(challengeBuffer)

  // 2) 生成 state 并保存 verifier/state 到 sessionStorage
  const state = randomString(16)
  sessionStorage.setItem('pkce:verifier', codeVerifier)
  sessionStorage.setItem('pkce:state', state)

  // 3) 重定向到授权端点
  const authorizeUrl = new URL(API_BASE + '/authorize')
  authorizeUrl.searchParams.set('response_type', 'code')
  authorizeUrl.searchParams.set('client_id', CLIENT_ID)
  authorizeUrl.searchParams.set('redirect_uri', REDIRECT_URI)
  authorizeUrl.searchParams.set('code_challenge', codeChallenge)
  authorizeUrl.searchParams.set('code_challenge_method', 'S256')
  authorizeUrl.searchParams.set('state', state)

  window.location.href = authorizeUrl.toString()
}

async function callApi() {
  if (!accessToken.value) return
  error.value = null
  me.value = null
  try {
    const resp = await fetch(API_BASE + '/me', {
      headers: {
        Authorization: `Bearer ${accessToken.value}`
      }
    })
    if (!resp.ok) throw new Error(`${resp.status} ${resp.statusText}`)
    me.value = await resp.json()
  } catch (e: any) {
    error.value = e.message || String(e)
  }
}

function logout() {
  localStorage.removeItem('access_token')
  accessToken.value = null
  me.value = null
}
</script>

<template>
  <main style="max-width: 720px; margin: 0 auto;">
    <h2>PKCE 授权演示（Vue 客户端）</h2>

    <section style="margin: 16px 0;">
      <button v-if="!accessToken" @click="startLogin">使用 PKCE 登录</button>
      <div v-else>
        <div style="margin-bottom:8px;">已获取 access_token: <code>{{ accessToken }}</code></div>
        <button @click="callApi">调用 API /me</button>
        <button style="margin-left:8px;" @click="logout">清除令牌</button>
      </div>
    </section>

    <section v-if="me" style="margin-top: 16px;">
      <h3>/me 返回</h3>
      <pre>{{ JSON.stringify(me, null, 2) }}</pre>
    </section>

    <p v-if="error" style="color:crimson;">错误：{{ error }}</p>
  </main>
</template>

<style scoped>
button { padding: 8px 12px; }
code { word-break: break-all; }
</style>
