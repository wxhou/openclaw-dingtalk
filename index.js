/**
 * Moltbot-Dingtalk 桥接服务
 *
 * 功能：
 * 1. 接收钉钉群机器人的 WebHook 消息
 * 2. 调用 Moltbot CLI 发送消息给 agent
 * 3. 将 agent 回复发送回钉钉
 */

const express = require('express');
const { spawn } = require('child_process');
const crypto = require('crypto');
const axios = require('axios');
const url = require('url');

const app = express();
app.use(express.json());

// 配置
const CONFIG = {
  // 钉钉机器人 WebHook 密钥（加签模式）
  dingtalkSecret: process.env.DINGTALK_SECRET || '',

  // Moltbot CLI 路径
  moltbotPath: process.env.MOLTBOT_PATH || 'moltbot',

  // 钉钉 WebHook URL（用于发送消息回钉钉）
  dingtalkWebhookUrl: process.env.DINGTALK_WEBHOOK_URL || '',

  // 钉钉关键字（用于验证消息，不含此关键字的消息将被忽略）
  dingtalkKeyword: process.env.DINGTALK_KEYWORD || '',

  // 会话超时（毫秒）
  sessionTimeout: 5 * 60 * 1000,

  // 请求限制（毫秒）
  rateLimitWindow: 1000,

  // 会话存储
  sessions: new Map(),

  // 请求记录（用于限速）
  requestLog: new Map()
};

/**
 * 生成钉钉签名（用于发送消息到钉钉）
 * 钉钉签名算法：HMAC-SHA256(Base64(HMAC-SHA256(timestamp + "\n" + secret)))
 * @param {string} timestamp - 时间戳（毫秒）
 * @param {string} secret - 密钥
 * @returns {string} 签名
 */
function generateDingtalkSign(timestamp, secret) {
  const stringToSign = `${timestamp}\n${secret}`;
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(stringToSign);
  const sign = hmac.digest('base64');
  // URL 编码
  return encodeURIComponent(sign);
}

/**
 * 发送消息到钉钉（支持加签模式）
 */
async function sendToDingtalk(webhookUrl, message) {
  if (!webhookUrl) {
    console.error('未配置钉钉 WebHook URL');
    return false;
  }

  const payload = {
    msgtype: 'text',
    text: {
      content: message
    }
  };

  try {
    let finalUrl = webhookUrl;

    // 如果配置了密钥，使用加签模式
    if (CONFIG.dingtalkSecret) {
      const timestamp = Date.now().toString();
      const sign = generateDingtalkSign(timestamp, CONFIG.dingtalkSecret);
      // 将签名添加到 URL 参数中
      const parsedUrl = new url.URL(webhookUrl);
      parsedUrl.searchParams.set('timestamp', timestamp);
      parsedUrl.searchParams.set('sign', sign);
      finalUrl = parsedUrl.toString();
    }

    await axios.post(finalUrl, payload, {
      headers: { 'Content-Type': 'application/json' }
    });
    return true;
  } catch (error) {
    console.error('发送钉钉消息失败:', error.response?.data || error.message);
    return false;
  }
}

/**
 * 验证钉钉签名（用于接收消息时的安全验证）
 * 注意：钉钉的签名验证有两种方式：
 * 1. 加签模式：在 URL 中传递 timestamp 和 sign 参数
 * 2. 关键字模式：消息中包含指定关键字
 */
function verifyDingtalkSignature(body, timestamp, sign) {
  if (!CONFIG.dingtalkSecret || !timestamp || !sign) {
    return true; // 没有配置密钥，跳过验证
  }

  // 验证签名
  const stringToSign = `${timestamp}\n${CONFIG.dingtalkSecret}`;
  const hmac = crypto.createHmac('sha256', CONFIG.dingtalkSecret);
  hmac.update(stringToSign);
  const computedSign = hmac.digest('base64');

  // 对比签名（注意：钉钉返回的签名可能已经 URL 编码）
  const decodedSign = decodeURIComponent(sign);
  return computedSign === decodedSign;
}

/**
 * 解析钉钉 WebHook 消息
 * 钉钉消息格式参考：https://open.dingtalk.com/document/orgapp/robot-message-types-and-data-format
 */
function parseDingtalkMessage(data) {
  // 文本消息
  if (data.msgtype === 'text' && data.text?.content) {
    return {
      type: 'text',
      content: data.text.content.trim(),
      userId: data.senderStaffId || data.senderId?.id || data.sender?.id,
      chatId: data.conversationId,
      isGroup: data.conversationType === 'group'
    };
  }

  // 忽略其他消息类型
  return null;
}

/**
 * 调用 Moltbot 发送消息
 */
async function sendToMoltbot(message, chatId) {
  return new Promise((resolve) => {
    try {
      const child = spawn(CONFIG.moltbotPath, ['agent', '--message', message, '--timeout', '120'], {
        timeout: 130000,
        killSignal: 'SIGTERM'
      });

      let stdout = '';
      let stderr = '';

      child.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      child.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      child.on('close', (code) => {
        const response = stdout.trim();
        if (response) {
          resolve(response);
        } else if (stderr) {
          resolve(stderr.trim());
        } else {
          resolve('消息已发送，但未收到回复');
        }
      });

      child.on('error', (error) => {
        console.error('执行 Moltbot 失败:', error.message);
        resolve(`处理失败: ${error.message}`);
      });

    } catch (error) {
      console.error('调用 Moltbot 失败:', error.message);
      resolve(`处理失败: ${error.message}`);
    }
  });
}

/**
 * 获取会话 ID
 */
function getSessionId(chatId, userId) {
  return `${chatId}:${userId}`;
}

/**
 * 清理过期会话
 */
function cleanupSessions() {
  const now = Date.now();
  for (const [id, session] of CONFIG.sessions.entries()) {
    if (now - session.lastActivity > CONFIG.sessionTimeout) {
      CONFIG.sessions.delete(id);
    }
  }
}

/**
 * 检查速率限制
 */
function checkRateLimit(ip) {
  const now = Date.now();
  const lastRequest = CONFIG.requestLog.get(ip);

  if (lastRequest && now - lastRequest < CONFIG.rateLimitWindow) {
    return false;
  }

  CONFIG.requestLog.set(ip, now);

  // 清理旧的记录
  for (const [key, time] of CONFIG.requestLog.entries()) {
    if (now - time > CONFIG.rateLimitWindow) {
      CONFIG.requestLog.delete(key);
    }
  }

  return true;
}

// 定时清理会话
setInterval(cleanupSessions, CONFIG.sessionTimeout);

// WebHook 端点
app.post('/webhook/dingtalk', async (req, res) => {
  try {
    // 速率限制
    const clientIp = req.ip || req.connection.remoteAddress;
    if (!checkRateLimit(clientIp)) {
      console.log('请求过于频繁:', clientIp);
      return res.status(429).json({ error: '请求过于频繁' });
    }

    // 钉钉 WebHook 消息体直接是 JSON，不需要包装
    const body = req.body;

    // 验证签名（从 URL 参数或请求头获取）
    // 钉钉可能在 URL 中传递 timestamp 和 sign 参数
    const timestamp = req.query.timestamp || req.headers['x-dingtalk-signature-timestamp'];
    const sign = req.query.sign || req.headers['x-dingtalk-signature'];

    if (timestamp && sign && !verifyDingtalkSignature(body, timestamp, sign)) {
      console.error('签名验证失败');
      return res.status(401).json({ error: '签名验证失败' });
    }

    // 解析消息
    const message = parseDingtalkMessage(body);
    if (!message) {
      console.log('忽略非消息类型:', JSON.stringify(body).substring(0, 200));
      return res.json({ status: 'ignored' });
    }

    // 检查关键字（如果配置了）
    if (CONFIG.dingtalkKeyword && !message.content.includes(CONFIG.dingtalkKeyword)) {
      console.log('消息不包含关键字，跳过');
      return res.json({ status: 'keyword_mismatch' });
    }

    console.log(`收到消息 [${message.isGroup ? '群' : '私'}聊] ${message.userId}: ${message.content}`);

    // 发送确认（钉钉要求快速响应）
    res.json({ status: 'ok' });

    // 处理消息（异步）
    (async () => {
      const sessionId = getSessionId(message.chatId, message.userId);

      // 检查是否正在处理
      if (CONFIG.sessions.has(sessionId)) {
        await sendToDingtalk(CONFIG.dingtalkWebhookUrl, '请稍候，我正在处理上一个请求...');
        return;
      }

      // 创建会话
      CONFIG.sessions.set(sessionId, {
        lastActivity: Date.now(),
        processing: true
      });

      try {
        const response = await sendToMoltbot(message.content, message.chatId);
        await sendToDingtalk(CONFIG.dingtalkWebhookUrl, response);
      } catch (error) {
        console.error('处理消息失败:', error);
        await sendToDingtalk(CONFIG.dingtalkWebhookUrl, '抱歉，处理消息时出错');
      } finally {
        CONFIG.sessions.delete(sessionId);
      }
    })();

  } catch (error) {
    console.error('处理 WebHook 失败:', error);
    res.status(500).json({ error: '内部错误' });
  }
});

// 健康检查端点
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// 状态端点
app.get('/status', (req, res) => {
  res.json({
    status: 'ok',
    sessions: CONFIG.sessions.size,
    config: {
      hasDingtalkWebhookUrl: !!CONFIG.dingtalkWebhookUrl,
      hasSecret: !!CONFIG.dingtalkSecret,
      hasKeyword: !!CONFIG.dingtalkKeyword
    }
  });
});

// 启动服务
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Moltbot-Dingtalk Bridge started on port ${PORT}`);
  console.log(`   WebHook 端点: http://localhost:${PORT}/webhook/dingtalk`);
  console.log(`   健康检查: http://localhost:${PORT}/health`);
});
