import express from "express";
import axios from "axios";
import qs from "qs";

const app = express();
app.use(express.json());

// Guardado temporal en memoria (luego puedes migrarlo a DB)
const store = {}; // user: tokens

async function refreshAccessIfNeeded(user) {
  const rec = store[user];
  if (!rec) throw new Error("no_tokens");

  if (rec.expires_at > Date.now() + 60000) {
    return rec.access_token;
  }

  const payload = {
    client_id: process.env.CLIENT_ID,
    client_secret: process.env.CLIENT_SECRET,
    refresh_token: rec.refresh_token,
    grant_type: "refresh_token"
  };

  const r = await axios.post("https://oauth2.googleapis.com/token", qs.stringify(payload), {
    headers: { "Content-Type": "application/x-www-form-urlencoded" }
  });

  rec.access_token = r.data.access_token;
  rec.expires_at = Date.now() + r.data.expires_in * 1000;
  store[user] = rec;

  return rec.access_token;
}

// AUTH URL
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

// CALLBACK
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
    const r = await axios.post("https://oauth2.googleapis.com/token", qs.stringify(payload), {
      headers: { "Content-Type": "application/x-www-form-urlencoded" }
    });

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

// CREATE EVENT → Make llama aquí
app.post("/event", async (req, res) => {
  try {
    const { user, title, date, start, end, description, colorId } = req.body;

    if (!store[user]) return res.status(401).json({ error: "not_authenticated" });

    const token = await refreshAccessIfNeeded(user);

    const eventBody = {
      summary: title,
      description,
      start: {
        dateTime: `${date}T${start}:00-04:00`
      },
      end: {
        dateTime: `${date}T${end}:00-04:00`
      }
    };

    if (colorId) eventBody.colorId = colorId;

    const r = await axios.post(
      "https://www.googleapis.com/calendar/v3/calendars/primary/events",
      eventBody,
      {
        headers: { Authorization: `Bearer ${token}` }
      }
    );

    res.json({ ok: true, id: r.data.id });
  } catch (error) {
    res.json({ ok: false, error });
  }
});

app.listen(3000, () => console.log("Server running on port 3000"));
