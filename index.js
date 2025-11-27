import express from "express";
import axios from "axios";
import qs from "qs";
import cors from "cors";

const app = express();
app.use(express.json());
app.use(cors());

const store = {};

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

app.get("/auth", (req, res) => {
  const user = req.query.user;
  if (!user) return res.status(400).send("Missing user");

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

app.get("/oauth/callback", async (req, res) => {
  const code = req.query.code;
  const user = req.query.state;

  if (!code || !user) return res.status(400).send("Missing params");

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

    res.send("<h2>Autorización completada ✔ — Puedes volver a WhatsApp.</h2>");

  } catch (e) {
    console.error(e?.response?.data);
    res.status(500).send("Token exchange error");
  }
});

app.post("/event", async (req, res) => {
  try {
    const user = req.body.user;
    if (!user) return res.json({ ok: false, error: "missing_user" });

    if (!store[user]) {
      return res.json({
        ok: false,
        needs_auth: true,
        auth_url: `${process.env.REDIRECT_BASE}/auth?user=${encodeURIComponent(user)}`
      });
    }

    let token;
    try {
      token = await refreshAccessIfNeeded(user);
    } catch {
      return res.json({
        ok: false,
        needs_auth: true,
        auth_url: `${process.env.REDIRECT_BASE}/auth?user=${encodeURIComponent(user)}`
      });
    }

    const { title, date, start, end, description } = req.body;

    const eventBody = {
      summary: title,
      description: description || "",
      start: { dateTime: `${date}T${start}:00` },
      end: { dateTime: `${date}T${end}:00` }
    };

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

  } catch (err) {
    console.error(err);
    return res.json({ ok: false, error: "server_error" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Backend listo en puerto", PORT));
