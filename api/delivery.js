import { Client, Databases, Query } from 'node-appwrite';

const NEAR_RADIUS_KM = 0.2;       // 200 metres
const MIN_NEAR_MINUTES = 10;      // 10–15 min countdown; we use 10

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
  if (!endpoint || !projectId || !apiKey || !databaseId || !orderCollectionId) {
    throw new Error('Missing Appwrite env vars');
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
    console.error('delivery-track-api', e);
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
    if (e.code === 404) return res.status(404).json({ error: 'Order not found' });
    return res.status(500).json({ error: e.message || 'Server error' });
  }
}
