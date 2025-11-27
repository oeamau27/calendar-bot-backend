// index.js
import express from "express";
import axios from "axios";
import qs from "qs";
import cors from "cors";

const app = express();
app.use(express.json());
app.use(cors());

// Guardado temporal en memoria (user -> { access_token, refresh_token, expires_at })
const store = {}; // este objeto es volátil. Para producción usa DB.

// Helper: refrescar token si falta o expiró
async function refreshAccessIfNeeded(user) {
  const rec = store[user];
  if (!rec) throw new Error("no_tokens");

  // Si sigue válido por > 60s, lo usamos
  if (rec.expires_at > Date.now() + 60000) {
    return rec.access_token;
  }

  // Refrescar con refresh_token
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
  store[user] = rec;
  return rec.access_token;
}

// === 1) Endpoint para iniciar autorización (redirige a Google) ===
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
      access_type: "offline",      // pide refresh token
      prompt: "consent",          // fuerza pedir refresh_token
      state: user
    });

  res.redirect(url);
});

// === 2) Callback que recibe el code de Google ===
app.get("/oauth/callback", async (req, res) => {
  const code = req.query.code;
  const user = req.query.state; // lo mandamos como state al iniciar /auth

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

    // Guardamos tokens en memoria (usa DB en producción)
    store[user] = {
      access_token: r.data.access_token,
      refresh_token: r.data.refresh_token,
      expires_at: Date.now() + (r.data.expires_in || 3600) * 1000
    };

    // Mensaje simple para el usuario (puedes devolver HTML)
    res.send("Autorización completada. Puedes volver a WhatsApp.");
  } catch (err) {
    console.error("oauth callback error:", err?.response?.data || err.message);
    res.status(500).send("Error en el intercambio de tokens.");
  }
});

// === 2.5) Endpoint de STATUS para que Make pregunte si el usuario ya autorizó ===
app.get("/auth/status", async (req, res) => {
  const user = req.query.user;
  if (!user) return res.status(400).json({ error: "missing_user" });

  // Si nunca autenticó:
  if (!store[user]) {
    return res.json({
      authenticated: false,
      needs_auth: true,
      auth_url: `${process.env.REDIRECT_BASE}/auth?user=${encodeURIComponent(user)}`
    });
  }

  // Intentar refrescar si hace falta (esto también valida)
  try {
    await refreshAccessIfNeeded(user);
    return res.json({
      authenticated: true,
      needs_auth: false
    });
  } catch (err) {
    // Token inválido / no se pudo refrescar
    return res.json({
      authenticated: false,
      needs_auth: true,
      auth_url: `${process.env.REDIRECT_BASE}/auth?user=${encodeURIComponent(user)}`
    });
  }
});

// === 3) Endpoint para crear evento (invocado desde Make) ===
app.post("/event", async (req, res) => {
  try {
    const { user, title, date, start, end, description, colorId } = req.body;
    if (!user) return res.status(400).json({ ok: false, error: "missing_user" });

    // Si no autenticado → responder con needs_auth true (Make lo usará)
    if (!store[user]) {
      return res.json({
        ok: false,
        error: "not_authenticated",
        needs_auth: true,
        auth_url: `${process.env.REDIRECT_BASE}/auth?user=${encodeURIComponent(user)}`
      });
    }

    // Obtener token (refresca si hace falta)
    const token = await refreshAccessIfNeeded(user);

    // Construir event body para Google Calendar
    const eventBody = {
      summary: title || "Evento",
      description: description || "",
      start: { dateTime: `${date}T${start}:00` },  // asume que Make ya colocó offset o zona
      end: { dateTime: `${date}T${end}:00` }
    };

    if (colorId) eventBody.colorId = colorId;

    const r = await axios.post(
      "https://www.googleapis.com/calendar/v3/calendars/primary/events",
      eventBody,
      { headers: { Authorization: `Bearer ${token}` } }
    );

    return res.json({ ok: true, needs_auth: false, id: r.data.id });
  } catch (error) {
    console.error("Create event error:", error?.response?.data || error.message);

    // Si Google responde 401 -> el token no sirve: pedir reauth
    if (error?.response?.status === 401) {
      return res.json({
        ok: false,
        error: "not_authenticated",
        needs_auth: true,
        auth_url: `${process.env.REDIRECT_BASE}/auth?user=${encodeURIComponent(req.body.user)}`
      });
    }

    return res.json({ ok: false, error: error.message || "unknown_error", needs_auth: false });
  }
});

// === 4) Levantar servidor ===
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
