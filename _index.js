import express from 'express';
import cors from 'cors';
import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';
import { OAuth2Client } from 'google-auth-library';

const app = express();
app.use(cors({ origin: 'http://localhost:5500', credentials: true }));
app.use(express.json());

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

const db = new Map();

app.post('/auth/google', async (req, res) => {
  const { credential } = req.body;
  const ticket = await client.verifyIdToken({
    idToken: credential,
    audience: GOOGLE_CLIENT_ID,
  });
  const payload = ticket.getPayload();
  const userId = payload.sub;

  if (!db.has(userId)) db.set(userId, { id: userId, credentials: [] });

  res.json({ userId });
});

app.post('/webauthn/register-options', (req, res) => {
  const { userId } = req.body;
  const user = db.get(userId);
  const options = generateRegistrationOptions({
    rpName: 'My App',
    userID: user.id,
    userName: user.id,
  });
  user.currentChallenge = options.challenge;
  res.json(options);
});

app.post('/webauthn/register', async (req, res) => {
  const { userId, attestation } = req.body;
  const user = db.get(userId);
  const verification = await verifyRegistrationResponse({
    response: attestation,
    expectedChallenge: user.currentChallenge,
    expectedOrigin: 'http://localhost:5500',
    expectedRPID: 'localhost',
  });
  if (verification.verified) {
    user.credentials.push(verification.registrationInfo);
    res.json({ verified: true });
  } else {
    res.status(400).json({ verified: false });
  }
});

app.post('/webauthn/auth-options', (req, res) => {
  const { userId } = req.body;
  const user = db.get(userId);
  const options = generateAuthenticationOptions({
    allowCredentials: user.credentials.map(c => ({
      id: c.credentialID,
      type: 'public-key',
    })),
  });
  user.currentChallenge = options.challenge;
  res.json(options);
});

app.post('/webauthn/auth', async (req, res) => {
  const { userId, assertion } = req.body;
  const user = db.get(userId);
  const verification = await verifyAuthenticationResponse({
    response: assertion,
    expectedChallenge: user.currentChallenge,
    expectedOrigin: 'http://localhost:5500',
    expectedRPID: 'localhost',
    authenticator: user.credentials[0],
  });
  res.json({ verified: verification.verified });
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));

