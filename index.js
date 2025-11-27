// index.js
import express from "express";
import axios from "axios";
import qs from "qs";
import cors from "cors";

const app = express();
app.use(express.json());
app.use(cors());

// Nota: store en memoria (usar DB en prod)
const store = {}; // userId -> { access_token, refresh_token, expires_at }

// refrescar token si necesario
async function refreshAccessIfNeeded(userId) {
  const rec = store[userId];
  if (!rec) throw new Error("no_tokens");
  if (rec.expires_at > Date.now() + 60000) return rec.access_token;

  const payload = {
    client_id: process.env.CLIENT_ID,
    client_secret: process.env.CLIENT_SECRET,
    refresh_token: rec.refresh_token,
    grant_type: "refresh_token"
  };

  const r = await axios.post(
    "https://oauth2.googleapis.com/token",
    qs.stringify(payload),
    { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
  );

  rec.access_token = r.data.access_token;
  rec.expires_at = Date.now() + (r.data.expires_in || 3600) * 1000;
  store[userId] = rec;
  return rec.access_token;
}

// 1) iniciar autorización (redirige a Google)
app.get("/auth", (req, res) => {
  const user = req.query.user;
  if (!user) return res.status(400).send("Missing user param");
  const url =
    "https://accounts.google.com/o/oauth2/v2/auth?" +
    qs.stringify({
      client_id: process.env.CLIENT_ID,
      redirect_uri: process.env.REDIRECT_URI,
      response_type: "code",
      scope: "https://www.googleapis.com/auth/calendar.events",
      access_type: "offline",
      prompt: "consent",
      state: user
    });
  res.redirect(url);
});

// 2) callback de Google
app.get("/oauth/callback", async (req, res) => {
  const code = req.query.code;
  const user = req.query.state;
  if (!code || !user) return res.status(400).send("Missing code or state");
  const payload = {
    client_id: process.env.CLIENT_ID,
    client_secret: process.env.CLIENT_SECRET,
    code,
    grant_type: "authorization_code",
    redirect_uri: process.env.REDIRECT_URI
  };
  try {
    const r = await axios.post(
      "https://oauth2.googleapis.com/token",
      qs.stringify(payload),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );

    store[user] = {
      access_token: r.data.access_token,
      refresh_token: r.data.refresh_token,
      expires_at: Date.now() + (r.data.expires_in || 3600) * 1000
    };

    // Devuelve una página simple confirmando que autorizó
    res.send("<html><body><h3>Autorización completada. Puedes volver a WhatsApp.</h3></body></html>");
  } catch (err) {
    console.error("oauth callback error:", err?.response?.data || err.message);
    res.status(500).send("Error en intercambio de tokens.");
  }
});

// 3) endpoint para crear evento (Make lo invoca)
// Soporta user en body.user, headers.user o query.user
app.post("/event", async (req, res) => {
  try {
    const payloadUser = req.body.user || req.headers.user || req.query.user;
    if (!payloadUser) return res.status(400).json({ ok: false, error: "missing_user" });

    const user = payloadUser;
    // Si no autenticado -> devolver needs_auth true con auth_url
    if (!store[user]) {
      return res.json({
        ok: false,
        error: "not_authenticated",
        needs_auth: true,
        auth_url: `${process.env.REDIRECT_BASE}/auth?user=${encodeURIComponent(user)}`
      });
    }

    // refrescar token
    let token;
    try {
      token = await refreshAccessIfNeeded(user);
    } catch (e) {
      return res.json({
        ok: false,
        error: "not_authenticated",
        needs_auth: true,
        auth_url: `${process.env.REDIRECT_BASE}/auth?user=${encodeURIComponent(user)}`
      });
    }

    const { title, date, start, end, description } = req.body;
    if (!date || !start || !end) {
      return res.status(400).json({ ok: false, error: "missing_date_or_time" });
    }

    const eventBody = {
      summary: title || "Evento",
      description: description || "",
      start: { dateTime: `${date}T${start}:00` },
      end: { dateTime: `${date}T${end}:00` }
    };

    if (req.body.colorId) eventBody.colorId = req.body.colorId;

    const r = await axios.post(
      "https://www.googleapis.com/calendar/v3/calendars/primary/events",
      eventBody,
      { headers: { Authorization: `Bearer ${token}` } }
    );

    return res.json({ ok: true, needs_auth: false, id: r.data.id });
  } catch (error) {
    console.error("Create event error:", error?.response?.data || error.message);
    if (error?.response?.status === 401) {
      return res.json({
        ok: false,
        error: "not_authenticated",
        needs_auth: true,
        auth_url: `${process.env.REDIRECT_BASE}/auth?user=${encodeURIComponent(req.body.user || req.headers.user || req.query.user)}`
      });
    }
    return res.status(500).json({ ok: false, error: error.message || "unknown_error" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
