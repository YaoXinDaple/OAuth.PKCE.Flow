import { createRouter, createWebHistory } from 'vue-router'
import Home from './views/Home.vue'
import Callback from './views/Callback.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'home', component: Home },
    { path: '/callback', name: 'callback', component: Callback }
  ]
})

export default router

