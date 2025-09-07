const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const path = require("path");
const bcrypt = require("bcrypt");

const app = express();
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public"))); // โฟลเดอร์ public สำหรับไฟล์ html/css/js

// เชื่อมต่อ MySQL
const conn = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "booking_db"
});

// สมัครสมาชิก
// register endpoint
app.post("/register", async (req, res) => {
  const { first_name, last_name, email, password, confirm_password } = req.body;

  if (!first_name || !last_name || !email || !password || !confirm_password) {
    return res.status(400).json({ success: false, message: "กรอกข้อมูลให้ครบ" });
  }

  if (password !== confirm_password) {
    return res.status(400).json({ success: false, message: "รหัสผ่านไม่ตรงกัน" });
  }

  conn.query(
    "SELECT * FROM users WHERE email = ?", 
    [email], 
    async (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ success: false, message: "เกิดข้อผิดพลาด" });
      }

      if (results.length > 0) {
        return res.status(400).json({ success: false, message: "อีเมลนี้มีอยู่แล้ว" });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      conn.query(
        "INSERT INTO users (first_name, last_name, email, password, role) VALUES (?, ?, ?, ?, 'user')",
        [first_name, last_name, email, hashedPassword],
        (err2) => {
          if (err2) {
            console.error(err2);
            return res.status(500).json({ success: false, message: "สมัครไม่สำเร็จ" });
          }

          res.json({ success: true, redirect: "/login.html" });
        }
      );
    }
  );
});

// login endpoint
app.post("/login", (req, res) => {
  const { first_name, last_name, password } = req.body;

  if (!first_name || !last_name || !password) {
    return res.status(400).json({ success: false, message: "กรอกข้อมูลให้ครบ" });
  }

  conn.query(
    "SELECT * FROM users WHERE first_name = ? AND last_name = ?", 
    [first_name, last_name], 
    async (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ success: false, message: "เกิดข้อผิดพลาด" });
      }

      if (results.length === 0) {
        return res.status(401).json({ success: false, message: "ไม่พบผู้ใช้" });
      }

      const user = results[0];

      if (user.password.length > 20) {
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
          return res.status(401).json({ success: false, message: "รหัสผ่านไม่ถูกต้อง" });
        }
      } else {
        if (password !== user.password) {
          return res.status(401).json({ success: false, message: "รหัสผ่านไม่ถูกต้อง" });
        }
      }

      const redirect = user.role === "admin" ? "/admin" : "/forms";

      // เก็บ role ไว้ใน sessionStorage ฝั่ง client ด้วย (response)
      res.json({ success: true, role: user.role, redirect });
    }
  );
});

// โหลดหน้า froms.html (ชื่อฟอร์มจอง)
app.get("/forms", (req, res) => {
  res.sendFile(path.join(__dirname, "public/form.html"));
});

// เข้าสู่ระบบ
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, message: "กรอกข้อมูลให้ครบ" });
  }

  conn.query("SELECT * FROM users WHERE username = ?", [username], async (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "เกิดข้อผิดพลาด" });
    }

    if (results.length === 0) {
      return res.status(401).json({ success: false, message: "ชื่อผู้ใช้ไม่ถูกต้อง" });
    }

    const user = results[0];
    
    // สมมติว่า รหัสผ่านที่เข้ารหัสจะมีความยาวมากกว่า 20 (bcrypt hash)
    if (user.password.length > 20) {
      // ถ้าเป็นรหัสผ่านเข้ารหัส
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) {
        return res.status(401).json({ success: false, message: "รหัสผ่านไม่ถูกต้อง" });
      }
    } else {
      // ถ้าเป็นรหัสผ่านที่ไม่เข้ารหัส (plaintext)
      if (password !== user.password) {
        return res.status(401).json({ success: false, message: "รหัสผ่านไม่ถูกต้อง" });
      }
    }

    const redirect = user.role === "admin" ? "/admin" : "/forms";
    res.json({ success: true, role: user.role, redirect });
  });
});


// โหลดหน้าแรก
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public/index.html"));
});

// โหลดหน้าแอดมิน
app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "public/admin.html"));
});

// โหลดหน้าปฏิทิน
app.get("/calendar", (req, res) => {
  res.sendFile(path.join(__dirname, "public/calendar.html"));
});

// ดึงการจองทั้งหมด
app.get("/bookings", (req, res) => {
  conn.query("SELECT * FROM bookings ORDER BY date DESC", (err, rows) => {
    if (err) {
      console.error(err);
      return res.json([]);
    }
    res.json(rows);
  });
});

// ดึงการจองที่อนุมัติแล้ว
app.get("/approved-bookings", (req, res) => {
  conn.query('SELECT * FROM bookings WHERE status="approved"', (err, rows) => {
    if (err) {
      console.error(err);
      return res.json([]);
    }

    // แปลงรูปแบบวันที่และเวลาให้ตรงกับ FullCalendar หรืออื่น ๆ
    const fixed = rows.map(r => {
      let date = new Date(r.date);
      let dateStr = date.toISOString().split("T")[0]; // YYYY-MM-DD

      let startTime = null, endTime = null;
      if (r.time && r.time.includes("-")) {
        const parts = r.time.split("-");
        startTime = parts[0].trim();
        endTime = (parts[1] || parts[0]).trim();
      } else {
        startTime = r.time;
        endTime = r.end_time || r.time;
      }

      return {
        ...r,
        start: `${dateStr}T${startTime}`,
        end: `${dateStr}T${endTime}`
      };
    });

    res.json(fixed);
  });
});

// อนุมัติการจอง
app.post("/approve", (req, res) => {
  const { id } = req.body;
  conn.query("UPDATE bookings SET status='approved' WHERE id=?", [id], err => {
    if (err) {
      console.error(err);
      return res.status(500).send("เกิดข้อผิดพลาด");
    }
    res.send("อนุมัติเรียบร้อย");
  });
});

// ปฏิเสธการจอง
app.post("/reject", (req, res) => {
  const { id } = req.body;
  conn.query("UPDATE bookings SET status='rejected' WHERE id=?", [id], err => {
    if (err) {
      console.error(err);
      return res.status(500).send("เกิดข้อผิดพลาด");
    }
    res.send("ปฏิเสธเรียบร้อย");
  });
});

// เพิ่มการจองใหม่ (สถานะเริ่มต้น pending)
app.post("/book", (req, res) => {
  const { name, type, date, time, end_time, purpose, equipment } = req.body;
  conn.query(
    "INSERT INTO bookings (name, type, date, time, end_time, purpose, equipment, status) VALUES (?,?,?,?,?,?,?, 'pending')",
    [name, type, date, time, end_time, purpose, equipment],
    err => {
      if (err) {
        console.error(err);
        return res.status(500).send("บันทึกไม่สำเร็จ");
      }
      res.send("บันทึกการจองเรียบร้อย");
    }
  );
});

// เริ่มต้นเซิร์ฟเวอร์
app.listen(3000, () => console.log("Server running on http://localhost:3000"));
