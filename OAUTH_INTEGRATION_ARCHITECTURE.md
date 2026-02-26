# Dify Chat OAuth集成架构方案

## 概述

本文档详细描述了Dify Chat项目（网站B）通过网站A的OAuth服务接入网站A用户管理体系的架构实现方案。本方案旨在实现单点登录（SSO）功能，使用户可以通过网站A的认证体系无缝访问Dify Chat平台。

## 一、整体架构设计

### 1.1 系统角色
- **网站A**：主平台，拥有OAuth2.0认证服务，管理主用户体系
- **网站B**：Dify Chat AI对话子站点，依赖网站A的认证信息，维护用户扩展数据
- **用户**：统一用户体系下的终端用户

### 1.2 架构原则
1. **最小侵入**：尽可能减少对现有代码的修改
2. **向后兼容**：保留现有匿名用户认证作为备选方案
3. **安全优先**：遵循OAuth2.0安全最佳实践
4. **用户体验**：实现无缝的单点登录体验

### 1.3 技术栈整合
- **现有技术栈**：
  - 平台服务：Next.js 16 + NextAuth + Prisma + MySQL
  - React应用：React 19 + 浏览器指纹认证
- **新增集成**：
  - NextAuth OAuth提供商
  - 外部用户关联系统
  - 统一认证状态管理

## 二、用户访问流程

### 2.1 场景一：网站A已登录，首次进入网站B
```
1. 用户在网站A点击【AI功能模块】或相关入口
2. 网站A前端携带用户的身份凭证（session/token）跳转到网站B
   - URL示例：https://site-b.com/entry?token=xxx&redirect_uri=...
3. 网站B接收请求，提取token，调用网站A的【Token验证接口】
4. 网站A验证token有效性，返回用户基本信息（user_id, name, email等）
5. 网站B根据user_id查询本地数据库：
   - 若存在关联用户，更新最后登录时间
   - 若不存在，自动创建关联用户记录
6. 网站B生成自己的登录态（NextAuth session），记录登录日志
7. 跳转到网站B首页（或AI对话页），用户直接进入，无需再次登录
```

### 2.2 场景二：网站A已登录，再次进入网站B
```
1. 流程同场景一，但网站B已有用户记录，直接登录
2. 优化：网站B通过cookie/session判断是否仍有效，减少重复验证
```

### 2.3 场景三：网站A未登录，直接访问网站B
```
1. 用户直接访问网站B（如输入网址或书签）
2. 网站B检查本地登录态，发现未登录
3. 重定向到网站A的【OAuth登录页】，并携带return_url参数
   - URL示例：https://site-a.com/oauth/authorize?client_id=xxx&response_type=code&redirect_uri=https://site-b.com/api/oauth/callback
4. 用户在网站A登录成功后，授权并重定向回网站B的【回调地址】
5. 网站B用授权码换取网站A的【Access Token】，再获取用户信息
6. 后续流程同场景一（创建/更新用户 + 生成网站B登录态）
```

### 2.4 场景四：网站A退出登录
```
方案A（推荐）：异步验证
  - 网站B的session设置合理有效期（如2小时）
  - 用户操作时验证token有效性（懒验证）
  - 定期刷新或重新验证

方案B（同步退出）：需要网站A提供登出回调接口
  - 网站B提供【登出回调接口】，网站A登出时通知网站B清除本地登录态
  - 实现复杂度较高，依赖网站A的支持
```

## 三、数据库模型扩展

### 3.1 新增表：external_users（外部用户关联表）
```prisma
model ExternalUser {
  id           String   @id @default(cuid())
  // 网站A的用户ID
  externalId   String   @unique @map("external_id")
  // 关联的本地用户ID
  userId       String   @unique @map("user_id")
  // 用户来源（site-a）
  provider     String
  // 网站A的用户信息（JSON格式）
  profileData  Json?    @map("profile_data")
  // 访问令牌（加密存储）
  accessToken  String?  @map("access_token")
  refreshToken String?  @map("refresh_token")
  tokenExpiry  DateTime? @map("token_expiry")
  // 同步信息
  lastSyncedAt DateTime? @map("last_synced_at")
  createdAt    DateTime @default(now()) @map("created_at")
  updatedAt    DateTime @updatedAt @map("updated_at")

  // 关联到本地用户
  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@map("external_users")
  @@unique([provider, externalId])
}
```

### 3.2 扩展现有表：users
```prisma
// 在现有User模型中添加字段
model User {
  // ... 现有字段不变

  // 新增字段
  lastLoginAt   DateTime? @map("last_login_at")
  loginCount    Int      @default(0) @map("login_count")
  isExternal    Boolean  @default(false) @map("is_external")

  // 关联关系
  externalUsers ExternalUser[]

  // ... 其他字段不变
}
```

### 3.3 新增表：user_sessions（用户会话记录）
```prisma
model UserSession {
  id           String   @id @default(cuid())
  userId       String   @map("user_id")
  sessionId    String   @unique @map("session_id")
  provider     String   // 'site-a' 或 'local'
  ipAddress    String?  @map("ip_address")
  userAgent    String?  @map("user_agent")
  loginAt      DateTime @default(now()) @map("login_at")
  lastActiveAt DateTime @updatedAt @map("last_active_at")
  expiresAt    DateTime @map("expires_at")
  isValid      Boolean  @default(true) @map("is_valid")

  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@map("user_sessions")
  @@index([userId])
  @@index([expiresAt])
}
```

## 四、API接口设计

### 4.1 网站A需要提供的接口（需要补充）

#### ① Token验证接口
```
用途：网站B验证从网站A带来的token是否有效，并获取用户信息
请求方式：POST /api/oauth/verify_token
请求参数：
  - token：从跳转链接中获取的凭证
  - client_id：网站B的客户端ID（可选，用于验证）
  - client_secret：网站B的客户端密钥（可选，用于验证）
响应：
  - 成功（200 OK）：
    {
      "valid": true,
      "user_id": "12345",
      "username": "john_doe",
      "email": "john@example.com",
      "avatar_url": "...",
      "expires_in": 3600,
      "scope": "read:user email"
    }
  - 失败（401 Unauthorized）：
    {
      "valid": false,
      "error": "token invalid or expired"
    }
安全要求：建议使用内部密钥签名或IP白名单限制
```

#### ② OAuth2.0授权接口
```
用途：用户未登录时，引导到网站A进行登录授权
请求方式：GET /oauth/authorize
标准OAuth参数：
  - client_id：网站B的客户端ID
  - response_type=code
  - redirect_uri：网站B的回调地址
  - scope：请求的权限范围（如：read:user email）
  - state：防CSRF随机字符串
```

#### ③ 换取Access Token接口
```
用途：网站B用授权码换取access_token
请求方式：POST /oauth/token
参数：
  - grant_type=authorization_code
  - code：授权码
  - redirect_uri：必须与授权请求一致
  - client_id
  - client_secret
响应：
  - access_token
  - token_type
  - expires_in
  - refresh_token (可选)
  - scope
```

#### ④ 获取用户信息接口
```
用途：用access_token获取用户详情
请求方式：GET /api/userinfo
请求头：Authorization: Bearer {access_token}
响应：
  - user_id
  - username
  - email
  - avatar_url
  - name
  - 其他用户信息字段
```

#### ⑤ 登出回调接口（可选）
```
用途：网站A登出时通知网站B
请求方式：POST /api/logout/callback
参数：
  - user_id
  - logout_token（JWT格式，包含事件信息）
  - timestamp
  - signature（用于验证请求合法性）
```

### 4.2 网站B需要新增的接口

#### ① 入口处理接口
```
用途：接收从网站A的跳转
URL：/api/oauth/entry
请求方式：GET
参数：
  - token：网站A的用户令牌
  - redirect_uri：跳转目标（可选，默认/chat）
处理逻辑：
  1. 验证token参数是否存在
  2. 调用网站A的【Token验证接口】
  3. 根据验证结果创建/更新本地用户
  4. 创建NextAuth会话
  5. 重定向到目标页面
安全要求：验证redirect_uri是否在白名单内
```

#### ② OAuth回调地址
```
用途：接收网站A的授权回调
URL：/api/oauth/callback
请求方式：GET
参数：
  - code：授权码
  - state：状态参数（防CSRF）
  - error：错误信息（如有）
处理逻辑：
  1. 验证state参数防止CSRF攻击
  2. 调用网站A的【换取Token接口】
  3. 调用【获取用户信息接口】
  4. 创建/更新本地用户记录
  5. 创建NextAuth会话
  6. 重定向到应用页面
```

#### ③ 用户信息同步接口
```
用途：同步网站A的用户信息到本地
URL：/api/oauth/sync
请求方式：POST
请求头：需要认证（NextAuth session）
处理逻辑：
  1. 验证用户会话
  2. 获取用户的access_token
  3. 调用网站A的【获取用户信息接口】
  4. 更新本地用户信息
  5. 返回同步结果
```

#### ④ 登出接口
```
用途：用户主动登出网站B
URL：/api/oauth/logout
请求方式：POST
请求头：需要认证
处理逻辑：
  1. 清除NextAuth会话
  2. 可选：调用网站A的登出接口（单点登出）
  3. 返回登出结果
```

#### ⑤ 认证状态检查接口
```
用途：React应用检查认证状态
URL：/api/auth/status
请求方式：GET
响应：
  - authenticated: boolean
  - user: { id, name, email, avatar } 或 null
  - provider: 'site-a' | 'local' | null
```

## 五、NextAuth配置修改

### 5.1 新增OAuth提供商配置
在 `packages/platform/lib/auth.ts` 中添加自定义OAuth提供商：

```typescript
import SiteAProvider from '@/lib/auth/providers/site-a'

export const authOptions = {
  // ... 现有配置

  providers: [
    // 现有CredentialsProvider...
    SiteAProvider(),
  ],

  // ... 其他配置
}
```

### 5.2 自定义OAuth提供商实现
创建 `packages/platform/lib/auth/providers/site-a.ts`：

```typescript
import type { OAuthConfig, OAuthUserConfig } from 'next-auth/providers/oauth'
import { getSiteAUserInfo, verifySiteAToken } from '@/lib/auth/site-a-client'

export interface SiteAProfile {
  user_id: string
  username: string
  email: string
  name?: string
  avatar_url?: string
}

export default function SiteAProvider(
  options: OAuthUserConfig<SiteAProfile>
): OAuthConfig<SiteAProfile> {
  return {
    id: 'site-a',
    name: 'Site A',
    type: 'oauth',
    authorization: {
      url: `${process.env.SITEA_OAUTH_URL}/oauth/authorize`,
      params: {
        scope: 'read:user email',
      },
    },
    token: `${process.env.SITEA_OAUTH_URL}/oauth/token`,
    userinfo: {
      url: `${process.env.SITEA_OAUTH_URL}/api/userinfo`,
      async request(context) {
        return await getSiteAUserInfo(context.tokens.access_token!)
      },
    },
    profile(profile) {
      return {
        id: profile.user_id,
        name: profile.name || profile.username,
        email: profile.email,
        image: profile.avatar_url,
      }
    },
    options,
  }
}
```

### 5.3 自定义回调处理
在NextAuth配置中添加自定义回调，处理外部用户关联：

```typescript
callbacks: {
  async signIn({ user, account, profile }) {
    if (account?.provider === 'site-a') {
      // 处理网站A用户登录
      return await handleSiteASignIn(user, account, profile)
    }
    return true
  },

  async jwt({ token, user, account, profile }) {
    if (account?.provider === 'site-a' && profile) {
      // 在JWT token中添加外部用户信息
      token.externalId = (profile as SiteAProfile).user_id
      token.provider = 'site-a'
    }
    return token
  },

  async session({ session, token }) {
    if (token.provider === 'site-a') {
      session.user.provider = 'site-a'
      session.user.externalId = token.externalId
    }
    return session
  },
},
```

## 六、React应用认证流程改造

### 6.1 修改现有认证钩子
更新 `packages/react-app/src/hooks/use-auth.ts`：

```typescript
import { useState, useEffect } from 'react'
import { LocalStorageKeys, LocalStorageStore } from '@dify-chat/helpers'
import { useHistory } from 'pure-react-router'
import { checkAuthStatus, loginWithSiteA } from '@/services/auth'

export const useAuth = () => {
  const history = useHistory()
  const [isAuthorized, setIsAuthorized] = useState<boolean>(false)
  const [user, setUser] = useState<any>(null)
  const [loading, setLoading] = useState<boolean>(true)

  // 检查认证状态
  useEffect(() => {
    const checkAuth = async () => {
      try {
        const status = await checkAuthStatus()
        if (status.authenticated) {
          setIsAuthorized(true)
          setUser(status.user)
        } else {
          setIsAuthorized(false)
          setUser(null)
        }
      } catch (error) {
        console.error('检查认证状态失败:', error)
        setIsAuthorized(false)
      } finally {
        setLoading(false)
      }
    }

    checkAuth()
  }, [])

  // 跳转到认证页面
  const goAuthorize = () => {
    // 根据配置选择认证方式
    if (process.env.PUBLIC_AUTH_MODE === 'site-a') {
      // 跳转到平台服务的OAuth入口
      window.location.href = `${process.env.PUBLIC_APP_API_BASE}/oauth/authorize?redirect_uri=${encodeURIComponent(window.location.href)}`
    } else {
      // 使用原有的浏览器指纹认证
      history.push('/auth')
    }
  }

  // 登出
  const logout = async () => {
    try {
      await logoutFromSiteA()
      setIsAuthorized(false)
      setUser(null)
      LocalStorageStore.remove(LocalStorageKeys.USER_ID)
      history.push('/')
    } catch (error) {
      console.error('登出失败:', error)
    }
  }

  return {
    isAuthorized,
    user,
    loading,
    goAuthorize,
    logout,
  }
}
```

### 6.2 新增认证服务
创建 `packages/react-app/src/services/auth.ts`：

```typescript
import { apiClient } from './api-client'

export interface AuthStatus {
  authenticated: boolean
  user: {
    id: string
    name: string
    email: string
    avatar?: string
    provider?: string
  } | null
}

export interface LoginParams {
  token?: string
  code?: string
  state?: string
}

/**
 * 检查认证状态
 */
export async function checkAuthStatus(): Promise<AuthStatus> {
  try {
    const response = await apiClient.get('/auth/status')
    return response.data
  } catch (error) {
    console.error('检查认证状态失败:', error)
    return { authenticated: false, user: null }
  }
}

/**
 * 通过网站A token登录
 */
export async function loginWithSiteAToken(token: string): Promise<AuthStatus> {
  const response = await apiClient.post('/oauth/login', { token })
  return response.data
}

/**
 * 处理OAuth回调
 */
export async function handleOAuthCallback(params: LoginParams): Promise<AuthStatus> {
  const response = await apiClient.post('/oauth/callback', params)
  return response.data
}

/**
 * 登出
 */
export async function logoutFromSiteA(): Promise<void> {
  await apiClient.post('/oauth/logout')
}
```

### 6.3 修改认证页面
更新 `packages/react-app/src/pages/auth/index.tsx` 以支持多种认证方式：

```typescript
import { useEffect } from 'react'
import { useSearchParams } from 'pure-react-router'
import { Spin } from 'antd'

import { Logo } from '@/components'
import { useAuth } from '@/hooks/use-auth'
import { handleOAuthCallback, loginWithSiteAToken } from '@/services/auth'

export default function AuthPage() {
  const [searchParams] = useSearchParams()
  const { isAuthorized } = useAuth()

  // 处理OAuth回调
  useEffect(() => {
    const token = searchParams.get('token')
    const code = searchParams.get('code')

    const handleAuth = async () => {
      if (token) {
        // 场景一：从网站A跳转带token
        await loginWithSiteAToken(token)
      } else if (code) {
        // 场景三：OAuth回调
        const state = searchParams.get('state')
        await handleOAuthCallback({ code, state })
      } else {
        // 默认跳转到网站A OAuth授权
        window.location.href = `${process.env.PUBLIC_APP_API_BASE}/oauth/authorize?redirect_uri=${encodeURIComponent(window.location.origin)}`
      }
    }

    if (!isAuthorized && (token || code)) {
      handleAuth()
    }
  }, [searchParams, isAuthorized])

  return (
    <div className="flex h-screen w-screen flex-col items-center justify-center bg-theme-bg">
      <div className="absolute left-0 top-0 z-50 flex h-full w-full flex-col items-center justify-center">
        <Logo hideGithubIcon />
        <div className="text-theme-text">正在跳转到认证服务...</div>
        <div className="mt-6">
          <Spin spinning />
        </div>
      </div>
    </div>
  )
}
```

## 七、环境变量配置

### 7.1 平台服务环境变量
在 `packages/platform/.env.template` 中添加：

```env
# 网站A OAuth配置
SITEA_OAUTH_URL=https://site-a.com
SITEA_CLIENT_ID=your_client_id
SITEA_CLIENT_SECRET=your_client_secret
SITEA_TOKEN_VERIFY_URL=https://site-a.com/api/oauth/verify_token

# OAuth回调配置
NEXTAUTH_URL=http://localhost:5300
NEXTAUTH_SECRET=your_nextauth_secret

# 会话配置
SESSION_MAX_AGE=7200 # 2小时
SESSION_UPDATE_AGE=1800 # 30分钟

# 安全配置
ALLOWED_REDIRECT_URIS=http://localhost:5300,http://localhost:3000,https://your-domain.com
CSRF_SECRET=your_csrf_secret
```

### 7.2 React应用环境变量
在 `packages/react-app/.env.template` 中添加：

```env
# 认证模式配置
PUBLIC_AUTH_MODE=site-a # site-a | fingerprint | mixed
PUBLIC_APP_API_BASE=http://localhost:5300/api/client

# 网站A前端配置（用于直接跳转）
PUBLIC_SITEA_ENTRY_URL=https://site-a.com/ai-entry
```

## 八、实现步骤与工作排序

### 第一阶段：基础设施准备（预计2-3天）

#### 1.1 获取网站A的OAuth配置信息（需要用户提供）
- [ ] 网站A的OAuth授权端点URL
- [ ] Token验证接口URL
- [ ] 用户信息接口URL
- [ ] 客户端ID和密钥
- [ ] 支持的scope范围
- [ ] 令牌有效期策略

#### 1.2 数据库迁移
- [ ] 设计数据库迁移脚本
- [ ] 创建external_users表
- [ ] 扩展users表字段
- [ ] 创建user_sessions表
- [ ] 测试迁移脚本

#### 1.3 环境变量配置
- [ ] 更新平台服务环境变量模板
- [ ] 更新React应用环境变量模板
- [ ] 创建环境变量文档

### 第二阶段：后端API开发（预计3-4天）

#### 2.1 NextAuth OAuth提供商集成
- [ ] 创建SiteA OAuth提供商
- [ ] 实现token验证客户端
- [ ] 实现用户信息同步客户端
- [ ] 测试OAuth流程

#### 2.2 新增API路由
- [ ] 创建/oauth/entry接口
- [ ] 创建/oauth/callback接口
- [ ] 创建/oauth/sync接口
- [ ] 创建/oauth/logout接口
- [ ] 创建/auth/status接口

#### 2.3 用户管理逻辑
- [ ] 实现外部用户关联逻辑
- [ ] 实现自动用户创建/更新
- [ ] 实现会话管理
- [ ] 添加登录日志记录

### 第三阶段：前端集成（预计2-3天）

#### 3.1 React应用认证改造
- [ ] 修改use-auth钩子
- [ ] 创建认证服务
- [ ] 更新认证页面
- [ ] 添加认证状态管理

#### 3.2 平台服务前端调整
- [ ] 更新登录页面提示
- [ ] 添加OAuth登录按钮
- [ ] 优化用户信息展示

### 第四阶段：测试与部署（预计2-3天）

#### 4.1 集成测试
- [ ] 测试场景一：网站A跳转到网站B
- [ ] 测试场景二：重复登录
- [ ] 测试场景三：直接访问网站B
- [ ] 测试场景四：登出流程
- [ ] 测试错误处理

#### 4.2 安全审计
- [ ] CSRF防护测试
- [ ] Token安全测试
- [ ] 重定向安全测试
- [ ] 会话安全测试

#### 4.3 文档与部署
- [ ] 更新项目文档
- [ ] 创建部署指南
- [ ] 配置生产环境
- [ ] 监控与日志配置

## 九、需要网站A提供的信息

### 9.1 OAuth端点信息
- [ ] **授权端点**：`https://site-a.com/oauth/authorize`
- [ ] **Token端点**：`https://site-a.com/oauth/token`
- [ ] **用户信息端点**：`https://site-a.com/api/userinfo`
- [ ] **Token验证端点**：`https://site-a.com/api/oauth/verify_token`

### 9.2 客户端凭证
- [ ] **Client ID**：网站B在网站A的客户端标识
- [ ] **Client Secret**：客户端密钥（用于安全通信）
- [ ] **Redirect URI**：`https://site-b.com/api/oauth/callback`
- [ ] **授权范围**：需要的权限范围（如：`read:user email`）

### 9.3 用户信息字段
- [ ] **用户ID字段名**：在响应中的用户标识字段（如：`user_id`, `id`, `sub`）
- [ ] **必需字段**：用户名、邮箱、头像等字段的JSON路径
- [ ] **扩展字段**：可用的额外用户信息字段

### 9.4 安全配置
- [ ] **Token有效期**：Access Token和Refresh Token的有效期
- [ ] **签名算法**：JWT签名算法（如：RS256, HS256）
- [ ] **IP白名单**：是否需要配置IP白名单
- [ ] **请求签名**：是否需要请求签名验证

### 9.5 跳转参数
- [ ] **Token参数名**：从网站A跳转到网站B时的token参数名（如：`token`, `access_token`）
- [ ] **状态参数**：OAuth state参数的处理方式
- [ ] **错误处理**：OAuth错误时的重定向参数

## 十、风险与缓解措施

### 10.1 技术风险
1. **OAuth流程中断**
   - 风险：网站A的OAuth服务不可用导致网站B无法登录
   - 缓解：保留原有的浏览器指纹认证作为备选方案
   - 监控：实现OAuth端点健康检查

2. **数据不一致**
   - 风险：网站A和网站B的用户数据不一致
   - 缓解：定期同步用户信息，提供手动同步功能
   - 监控：记录数据同步日志和错误

3. **会话管理**
   - 风险：会话过期或无效导致用户体验差
   - 缓解：实现会话刷新机制，优化过期处理
   - 监控：记录会话创建、更新、过期事件

### 10.2 安全风险
1. **CSRF攻击**
   - 风险：OAuth回调被CSRF攻击
   - 缓解：使用state参数防CSRF，验证redirect_uri
   - 监控：记录可疑的OAuth请求

2. **Token泄露**
   - 风险：Access Token被泄露导致账户被盗
   - 缓解：使用HTTPS，短期Token，加密存储
   - 监控：异常登录检测，Token使用审计

3. **重定向攻击**
   - 风险：恶意重定向到外部站点
   - 缓解：白名单验证redirect_uri，防止开放重定向
   - 监控：记录所有重定向请求

### 10.3 业务风险
1. **依赖风险**
   - 风险：过度依赖网站A的服务
   - 缓解：设计降级方案，服务熔断机制
   - 监控：服务依赖健康度监控

2. **用户体验**
   - 风险：跨站登录流程复杂导致用户流失
   - 缓解：优化登录流程，减少跳转次数
   - 监控：登录成功率，用户反馈

## 十一、监控与维护

### 11.1 关键指标监控
- **登录成功率**：各场景登录成功率
- **登录时长**：从开始登录到完成的时间
- **错误率**：OAuth流程各阶段的错误率
- **用户活跃**：外部用户与本地用户的活跃对比

### 11.2 日志记录
- **审计日志**：所有认证相关操作
- **错误日志**：详细的错误信息和上下文
- **性能日志**：各接口的响应时间和资源使用

### 11.3 告警配置
- **服务不可用**：OAuth端点连续失败
- **异常登录**：短时间内大量失败登录
- **数据不一致**：用户信息同步失败率过高

## 十二、附录

### 12.1 相关文件位置
```
packages/platform/
├── lib/auth/
│   ├── providers/site-a.ts      # SiteA OAuth提供商
│   └── site-a-client.ts         # SiteA API客户端
├── app/api/
│   ├── oauth/
│   │   ├── entry/route.ts       # 入口处理接口
│   │   ├── callback/route.ts    # OAuth回调接口
│   │   ├── sync/route.ts        # 用户信息同步
│   │   └── logout/route.ts      # 登出接口
│   └── auth/
│       └── status/route.ts      # 认证状态接口
├── prisma/
│   └── migrations/              # 数据库迁移
└── scripts/
    └── oauth-setup.ts          # OAuth初始化脚本

packages/react-app/
├── src/hooks/
│   └── use-auth.ts             # 更新后的认证钩子
├── src/services/
│   └── auth.ts                 # 认证服务
├── src/pages/
│   └── auth/
│       └── index.tsx           # 更新后的认证页面
└── .env.template               # 环境变量模板
```

### 12.2 测试用例
1. **单元测试**
   - OAuth提供商配置测试
   - Token验证测试
   - 用户关联逻辑测试

2. **集成测试**
   - 完整OAuth流程测试
   - 跨站跳转测试
   - 错误场景测试

3. **端到端测试**
   - 用户从网站A到网站B的完整流程
   - 多种浏览器的兼容性测试
   - 移动端响应式测试

### 12.3 部署检查清单
- [ ] 数据库迁移已执行
- [ ] 环境变量已正确配置
- [ ] OAuth客户端已注册
- [ ] SSL证书已配置
- [ ] 监控告警已设置
- [ ] 备份策略已实施
- [ ] 回滚方案已准备

---

**文档版本**：1.0
**创建日期**：2026-02-26
**最后更新**：2026-02-26
**负责人**：架构团队

**下一步行动**：
1. 请确认本架构方案是否符合需求
2. 提供网站A的OAuth配置信息（第九节）
3. 确认实现优先级和时间安排
4. 开始第一阶段的基础设施准备