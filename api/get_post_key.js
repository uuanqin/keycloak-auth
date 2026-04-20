// api/get-key.js
const jwt = require('jsonwebtoken');
const crypto = require('crypto-js');

const KEYCLOAK_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----\n${process.env.KC_PUB_KEY}\n-----END PUBLIC KEY-----`;
const MASTER_SECRET = process.env.MASTER_SECRET;

export default async function handler(req, res) {
  const { method, headers } = req;
  const origin = headers.origin;

  // --- 1. 严格的环境变量跨域控制 ---
  // 从环境变量读取，支持逗号分隔。如果环境变量没设，则默认为空数组。
  const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
    : [];

  // 校验逻辑：只有在允许列表中的 Origin 才会设置响应头
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else {
    // 如果不在白名单，不返回 Access-Control-Allow-Origin 头，浏览器会自动拦截
    console.warn(`[Auth-Server] 拦截到未授权域名请求: ${origin}`);
  }

  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');

  if (method === 'OPTIONS') return res.status(200).end();

  // --- 2. 调试日志 ---
  console.log(`[Auth-Server] 收到请求: ${method} 来自: ${origin || '未知'}`);

  if (method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    // --- 3. JWT 验证 ---
    const authHeader = headers.authorization;
    if (!authHeader) throw new Error('Missing token');

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, KEYCLOAK_PUBLIC_KEY, { algorithms: ['RS256'] });

    console.log(`[Auth-Server] 用户认证通过: ${decoded.preferred_username || decoded.sub}`);

    // --- 4. 生成动态密钥 ---
    const { path } = req.body;
    if (!path) throw new Error('Missing article path');

    // 核心公式：HMAC(主密钥, 文章路径)
    const articleKey = crypto.HmacSHA256(path, MASTER_SECRET).toString();

    console.log(`[Auth-Server] 成功为路径 [${path}] 下发密钥`);

    return res.status(200).json({ key: articleKey });

  } catch (error) {
    console.error(`[Auth-Server] 认证失败: ${error.message}`);
    const message = error.name === 'TokenExpiredError' ? 'Token expired' : 'Unauthorized';
    return res.status(401).json({ error: 'Unauthorized', message });
  }
}