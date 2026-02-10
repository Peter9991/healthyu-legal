/**
 * Delivery tracking API for HealthyU.
 * Deploy to Vercel: project root = delivery-track-api, so route is /api/delivery.
 *
 * Env (Vercel): APPWRITE_ENDPOINT, APPWRITE_PROJECT_ID, APPWRITE_API_KEY,
 *   APPWRITE_DATABASE_ID, APPWRITE_ORDERS_COLLECTION_ID
 *
 * GET /api/delivery?orderId=xxx&token=yyy
 *   Returns { destination: { lat, lng }, orderNumber, status }. If status was 'preparing', updates to 'delivering'.
 *
 * POST /api/delivery
 *   Body: { orderId, token, action: 'update_location' | 'mark_delivered', lat?, lng? }
 *   update_location: sends driver location; if distance to customer <= 500m, sets deliveryNearAt. Returns { distanceKm, nearAt, status }.
 *   mark_delivered: if deliveryNearAt exists and >= 15 min ago, sets orderStatus to 'completed'. Returns { success }.
 */

import { Client, Databases, Query } from 'node-appwrite';

const NEAR_RADIUS_KM = 0.5;       // 500 metres
const MIN_NEAR_MINUTES = 15;      // 15 min countdown before marking delivered

function haversineKm(lat1, lon1, lat2, lon2) {
  const R = 6371;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos((lat1 * Math.PI) / 180) * Math.cos((lat2 * Math.PI) / 180) * Math.sin(dLon / 2) ** 2;
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

function getAppwrite() {
  const endpoint = process.env.APPWRITE_ENDPOINT;
  const projectId = process.env.APPWRITE_PROJECT_ID;
  const apiKey = process.env.APPWRITE_API_KEY;
  const databaseId = process.env.APPWRITE_DATABASE_ID;
  const orderCollectionId = process.env.APPWRITE_ORDERS_COLLECTION_ID;
  const missing = [];
  if (!endpoint) missing.push('APPWRITE_ENDPOINT');
  if (!projectId) missing.push('APPWRITE_PROJECT_ID');
  if (!apiKey) missing.push('APPWRITE_API_KEY');
  if (!databaseId) missing.push('APPWRITE_DATABASE_ID');
  if (!orderCollectionId) missing.push('APPWRITE_ORDERS_COLLECTION_ID');
  if (missing.length) {
    const msg = 'Missing Appwrite env vars: ' + missing.join(', ');
    console.error('delivery-track-api:', msg);
    throw new Error(msg);
  }
  const client = new Client().setEndpoint(endpoint).setProject(projectId).setKey(apiKey);
  const databases = new Databases(client);
  return { databases, databaseId, orderCollectionId };
}

async function getOrder(databases, databaseId, orderCollectionId, orderId) {
  const doc = await databases.getDocument(databaseId, orderCollectionId, orderId);
  return doc;
}

function corsHeaders(origin = '*') {
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
  };
}

export default async function handler(req, res) {
  const origin = req.headers.origin || '*';
  const orderId = req.method === 'GET' ? req.query.orderId : req.body?.orderId;
  console.log('delivery-track-api', req.method, orderId ? 'orderId=' + orderId : 'no orderId');
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    return res.status(204).end();
  }

  if (req.method !== 'GET' && req.method !== 'POST') {
    res.setHeader('Access-Control-Allow-Origin', origin);
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { databases, databaseId, orderCollectionId } = getAppwrite();
    const orderId = req.method === 'GET' ? req.query.orderId : req.body?.orderId;
    const token = req.method === 'GET' ? req.query.token : req.body?.token;
    if (!orderId || !token || typeof orderId !== 'string' || typeof token !== 'string') {
      res.setHeader('Access-Control-Allow-Origin', origin);
      return res.status(400).json({ error: 'orderId and token required' });
    }

    const order = await getOrder(databases, databaseId, orderCollectionId, orderId);
    const orderToken = order.deliveryTrackingToken || null;
    if (orderToken !== token) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      return res.status(403).json({ error: 'Invalid token' });
    }

    const destLat = order.latitude != null ? parseFloat(order.latitude) : null;
    const destLng = order.longitude != null ? parseFloat(order.longitude) : null;
    const status = order.orderStatus || 'pending';

    if (req.method === 'GET') {
      if (status === 'preparing') {
        await databases.updateDocument(databaseId, orderCollectionId, orderId, {
          orderStatus: 'delivering',
        });
      }
      res.setHeader('Access-Control-Allow-Origin', origin);
      return res.status(200).json({
        destination: destLat != null && destLng != null ? { lat: destLat, lng: destLng } : null,
        orderNumber: order.orderNumber || orderId,
        status: status === 'preparing' ? 'delivering' : status,
      });
    }

    const action = req.body?.action;
    if (action === 'update_location') {
      const lat = req.body.lat != null ? parseFloat(req.body.lat) : null;
      const lng = req.body.lng != null ? parseFloat(req.body.lng) : null;
      if (lat == null || lng == null || destLat == null || destLng == null) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        return res.status(400).json({ error: 'lat and lng required when destination exists' });
      }
      const distanceKm = haversineKm(lat, lng, destLat, destLng);
      let nearAt = order.deliveryNearAt || null;
      const updates = {};
      if (distanceKm <= NEAR_RADIUS_KM && !nearAt) {
        nearAt = new Date().toISOString();
        updates.deliveryNearAt = nearAt;
      }
      if (Object.keys(updates).length) {
        await databases.updateDocument(databaseId, orderCollectionId, orderId, updates);
      }
      res.setHeader('Access-Control-Allow-Origin', origin);
      return res.status(200).json({
        distanceKm: Math.round(distanceKm * 1000) / 1000,
        nearAt,
        status: order.orderStatus || 'delivering',
      });
    }

    if (action === 'mark_delivered') {
      const nearAt = order.deliveryNearAt ? new Date(order.deliveryNearAt).getTime() : null;
      const now = Date.now();
      const minNearMs = MIN_NEAR_MINUTES * 60 * 1000;
      if (!nearAt || now - nearAt < minNearMs) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        return res.status(400).json({
          error: 'Must be near customer for at least ' + MIN_NEAR_MINUTES + ' minutes',
          nearAt: order.deliveryNearAt || null,
        });
      }
      await databases.updateDocument(databaseId, orderCollectionId, orderId, {
        orderStatus: 'completed',
      });
      res.setHeader('Access-Control-Allow-Origin', origin);
      return res.status(200).json({ success: true });
    }

    res.setHeader('Access-Control-Allow-Origin', origin);
    return res.status(400).json({ error: 'Invalid action' });
  } catch (e) {
    console.error('delivery-track-api error:', e.message || e);
    if (e.code !== undefined) console.error('delivery-track-api code:', e.code);
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
    if (e.code === 404) return res.status(404).json({ error: 'Order not found' });
    const message = e.message || 'Server error';
    return res.status(500).json({ error: message });
  }
}
