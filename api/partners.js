import { Client, Databases, ID } from 'node-appwrite';

function corsHeaders(origin = '*') {
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
  };
}

function getAppwrite() {
  const endpoint = process.env.APPWRITE_ENDPOINT;
  const projectId = process.env.APPWRITE_PROJECT_ID;
  const apiKey = process.env.APPWRITE_API_KEY;
  const databaseId = process.env.APPWRITE_DATABASE_ID;
  const partnersCollectionId = process.env.APPWRITE_PARTNERS_COLLECTION_ID;
  const missing = [];

  if (!endpoint) missing.push('APPWRITE_ENDPOINT');
  if (!projectId) missing.push('APPWRITE_PROJECT_ID');
  if (!apiKey) missing.push('APPWRITE_API_KEY');
  if (!databaseId) missing.push('APPWRITE_DATABASE_ID');
  if (!partnersCollectionId) missing.push('APPWRITE_PARTNERS_COLLECTION_ID');

  if (missing.length) {
    throw new Error('Missing Appwrite env vars: ' + missing.join(', '));
  }

  const client = new Client().setEndpoint(endpoint).setProject(projectId).setKey(apiKey);
  const databases = new Databases(client);
  return { databases, databaseId, partnersCollectionId };
}

function cleanString(value) {
  return typeof value === 'string' ? value.trim() : '';
}

export default async function handler(req, res) {
  const origin = req.headers.origin || '*';
  const headers = corsHeaders(origin);
  Object.entries(headers).forEach(([key, value]) => res.setHeader(key, value));

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const firstName = cleanString(req.body?.firstName || req.body?.['first-name']);
    const lastName = cleanString(req.body?.lastName || req.body?.['last-name']);
    const email = cleanString(req.body?.email);
    const phone = cleanString(req.body?.phone);
    const partnerType = cleanString(req.body?.partnerType || req.body?.['partner-type']);
    const message = cleanString(req.body?.message);

    if (!firstName || !lastName || !email || !phone || !partnerType) {
      return res.status(400).json({ error: 'Please complete all required fields.' });
    }

    const { databases, databaseId, partnersCollectionId } = getAppwrite();
    await databases.createDocument(databaseId, partnersCollectionId, ID.unique(), {
      firstName,
      lastName,
      email,
      phone,
      partnerType,
      message,
      source: 'healthyu-legal-index',
      createdAt: new Date().toISOString(),
    });

    return res.status(200).json({ success: true });
  } catch (error) {
    console.error('partners-api error:', error.message || error);
    return res.status(500).json({ error: error.message || 'Server error' });
  }
}
