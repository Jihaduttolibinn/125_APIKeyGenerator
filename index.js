const express = require("express");
const path = require("path");
const mysql = require("mysql2/promise");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const app = express();
const port = 3000;

app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const dbConfig = {
  host: "localhost",
  user: "root",
  password: "123456",
  database: "apikey_db",
  port: 3309
};

let conn;

async function connectDB() {
  try {
    conn = await mysql.createConnection(dbConfig);
    console.log("MySQL Connected!");
  } catch (err) {
    console.error("DB Error:", err);
  }
}
connectDB();

app.post("/admin-register", async (req, res) => {
  const { email, password } = req.body;

  const hashed = await bcrypt.hash(password, 10);

  try {
    await conn.execute(
      "INSERT INTO admin (email, password) VALUES (?, ?)",
      [email, hashed]
    );
    res.json({ success: true, message: "Registrasi admin berhasil!" });
  } catch (err) {
    res.json({ success: false, message: "Email admin sudah terdaftar." });
  }
});

app.post("/admin-login", async (req, res) => {
  const { email, password } = req.body;

  const [rows] = await conn.execute(
    "SELECT * FROM admin WHERE email = ?",
    [email]
  );

  if (rows.length === 0)
    return res.json({ success: false, message: "Email tidak ditemukan." });

  const match = await bcrypt.compare(password, rows[0].password);
  if (!match)
    return res.json({ success: false, message: "Password salah." });

  res.redirect("/dashboard.html");
});

app.post("/generate-key", async (req, res) => {
  const apiKey = crypto.randomBytes(24).toString("hex");

  const [insert] = await conn.execute(
    "INSERT INTO api_keys (api_key) VALUES (?)",
    [apiKey]
  );

  res.json({ success: true, apiKey, apiId: insert.insertId });
});

app.post("/user-register", async (req, res) => {
  const { first_name, last_name, email, api_id } = req.body;

  try {
    await conn.execute(
      "INSERT INTO users (first_name, last_name, email, api_id) VALUES (?, ?, ?, ?)",
      [first_name, last_name, email, api_id]
    );

    res.json({ success: true, message: "User dan API key berhasil dibuat!" });
  } catch (err) {
    res.json({ success: false, message: "Email sudah digunakan user lain!" });
  }
});


app.get("/dashboard-data", async (req, res) => {
  const [rows] = await conn.execute(`
    SELECT 
      users.id AS user_id,
      users.first_name,
      users.last_name,
      users.email,
      api_keys.api_key
    FROM users
    LEFT JOIN api_keys
        ON users.api_id = api_keys.id
  `);

  res.json(rows);
});

app.delete("/delete-user/:id", async (req, res) => {
  const userId = req.params.id;

  try {
    
    const [rows] = await conn.execute(
      "SELECT api_id FROM users WHERE id = ?",
      [userId]
    );

    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "User tidak ditemukan!"
      });
    }

    const apiId = rows[0].api_id;

    
    await conn.execute("DELETE FROM users WHERE id = ?", [userId]);

   
    if (apiId) {
      await conn.execute("DELETE FROM api_keys WHERE id = ?", [apiId]);
    }

    res.json({
      success: true,
      message: "User & API key berhasil dihapus!"
    });

  } catch (err) {
    console.log(err);
    res.status(500).json({
      success: false,
      message: "Gagal menghapus user!",
      error: err
    });
  }
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});