const admin = require('firebase-admin');

function initFirebase() {
  if (admin.apps.length) return admin.database();

  const databaseURL = process.env.FIREBASE_DATABASE_URL;
  if (!databaseURL) throw new Error('FIREBASE_DATABASE_URL is required');

  const raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (raw) {
    let serviceAccount;
    try {
      serviceAccount = JSON.parse(raw);
    } catch {
      throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON must be valid JSON');
    }
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      databaseURL
    });
  } else {
    // Works on environments configured with Application Default Credentials.
    admin.initializeApp({ credential: admin.credential.applicationDefault(), databaseURL });
  }
  return admin.database();
}

module.exports = { initFirebase };
