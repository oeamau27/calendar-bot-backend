import express from "express";
import axios from "axios";
import qs from "qs";

const app = express();
app.use(express.json());

// Guardado temporal en memoria
const store = {}; // user → { access, refresh, expires_at }

// Refresca token si está vencido
async function refreshAccessIfNeeded(user) {
  const rec = store[user];
  if (!rec) throw new Error("no_tokens");

  // Si el token sigue siendo válido por 1 minuto → úsalo
  if (rec.expires_at > Date.now() + 60000) {
    return rec.access_token;
  }

  // Refrescar token
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
  rec.expires_at = Date.now() + r.data.expires_in * 1000;
  store[user] = rec;

  return rec.access_token;
}

// === 1) GENERAR URL DE AUTORIZACIÓN ===
app.get("/auth", (req, res) => {
  const user = req.query.user;

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

// === 2) CALLBACK DESPUÉS DE AUTORIZAR ===
app.get("/oauth/callback", async (req, res) => {
  const code = req.query.code;
  const user = req.query.state;

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
      expires_at: Date.now() + r.data.expires_in * 1000
    };

    res.send("Tu Google Calendar ya está conectado. Puedes volver a WhatsApp.");
  } catch (err) {
    res.send("Error: " + err);
  }
});

// === 3) CREAR EVENTO (LLAMADO DESDE MAKE) ===
app.post("/event", async (req, res) => {
  try {
    const { user, title, date, start, end, description, colorId } = req.body;

    // SI NO ESTÁ AUTENTICADO → PEDIR AUTH
    if (!store[user]) {
      return res.json({
        ok: false,
        error: "not_authenticated",
        needs_auth: true,
        auth_url: `${process.env.REDIRECT_BASE}/auth?user=${encodeURIComponent(user)}`
      });
    }

    // Obtener token funcional (refrescado o actual)
    const token = await refreshAccessIfNeeded(user);

    const eventBody = {
      summary: title,
      description,
      start: { dateTime: `${date}T${start}:00-04:00` },
      end: { dateTime: `${date}T${end}:00-04:00` }
    };

    if (colorId) eventBody.colorId = colorId;

    const r = await axios.post(
      "https://www.googleapis.com/calendar/v3/calendars/primary/events",
      eventBody,
      { headers: { Authorization: `Bearer ${token}` } }
    );

    return res.json({
      ok: true,
      needs_auth: false,
      id: r.data.id
    });

  } catch (error) {
    // SI EL TOKEN YA NO FUNCIONA
    if (error.response && error.response.status === 401) {
      return res.json({
        ok: false,
        error: "not_authenticated",
        needs_auth: true,
        auth_url: `${process.env.REDIRECT_BASE}/auth?user=${encodeURIComponent(req.body.user)}`
      });
    }

    res.json({
      ok: false,
      needs_auth: false,
      error: error.message
    });
  }
});

// === 4) INICIAR SERVIDOR ===
app.listen(3000, () => {
  console.log("Server running on port 3000");
});
