// index.js
import express from 'express';
import crypto from 'crypto';
import bodyParser from 'body-parser';
import dotenv from 'dotenv'

dotenv.config()

const app = express();
const VERIFY_TOKEN = process.env.VERIFY_TOKEN
const APP_SECRET = process.env.APP_SECRET

app.use(bodyParser.json());

// 🌐 Webhook verification (GET)
app.get('/webhook', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode === 'subscribe' && token === VERIFY_TOKEN) {
    console.log('Webhook verified');
    res.status(200).send(challenge);
  } else {
    res.sendStatus(403);
  }
});

// 📩 Webhook event handler (POST)
app.post('/webhook', (req, res) => {
  const signature = req.headers['x-hub-signature-256'];
  const body = JSON.stringify(req.body);

  const expectedSignature = `sha256=${crypto
    .createHmac('sha256', APP_SECRET)
    .update(body)
    .digest('hex')}`;

  if (signature !== expectedSignature) {
    return res.sendStatus(403); // not legit
  }

  console.log('✅ Webhook event received:', req.body);
  res.sendStatus(200);
});
const port = process.env.PORT || 3003

// Start server
app.listen(port, () => {
  console.log(`Webhook server is running on port: ${port}`);
});
