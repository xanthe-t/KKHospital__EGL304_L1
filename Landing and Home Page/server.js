import express from "express";
import { Low } from 'lowdb';
import { JSONFile } from 'lowdb/node';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import cookieParser from "cookie-parser";
import bodyParser from "body-parser";
import path from "path";
import fs from "fs";
import bcrypt from "bcrypt";

const saltRounds = 10;
const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const port = 3030;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "css")));
app.use(express.static(path.join(__dirname, "images")));

// Initialize LowDB
const file = join(__dirname, 'db.json');
const adapter = new JSONFile(file);
const defaultData = { activeUser: null, users: [{}], lastActivity: null };
const db = new Low(adapter, defaultData);
await db.read();
db.data ||= defaultData;
await db.write();

// Max idle time
const maxIdleTime = 5 * 60 * 1000; // 5 min

// Middleware: check authentication
async function checkAuth(req, res, next) {
    const username = req.cookies.username;
    if (!username) return res.redirect("/login.html");

    await db.read();
    if (db.data.activeUser === username) {
        const lastActivity = db.data.lastActivity || 0;

        if (Date.now() - lastActivity > maxIdleTime) {
            // Idle logout
            db.data.activeUser = null;
            db.data.lastActivity = null;
            await db.write();

            res.clearCookie("username");
            res.clearCookie("lastActivity");

            return res.redirect("/login.html?loggedOut=idle");
        }

        db.data.lastActivity = Date.now();
        await db.write();
        res.cookie("lastActivity", Date.now().toString());
        return next();
    }

    return res.redirect("/login.html");
}

// Serve login page
app.get("/", (req, res) => res.redirect("/login.html"));

app.get("/login.html", async (req, res) => {
    const username = req.cookies.username;
    await db.read();

    if (username && db.data.activeUser === username) {
        return res.redirect("/index.html");
    }

    res.sendFile(join(__dirname, "pages/login.html"));
});

// Login POST
app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    await db.read();

    if (db.data.activeUser && db.data.activeUser !== username) {
        const idleTime = Date.now() - (db.data.lastActivity || 0);
        if (idleTime <= maxIdleTime) {
            let page = fs.readFileSync(join(__dirname, "pages/login.html"), "utf-8");
            page = page.replace('{{message}}', `System is currently used by ${db.data.activeUser}. Actions disabled.`);
            page = page.replace('style="display: none;"', 'style="display: block;"');
            return res.send(page);
        } else {
            db.data.activeUser = null;
            db.data.lastActivity = null;
            await db.write();
        }
    }

    const user = db.data.users.find(u => u.username === username);
    if (user && await bcrypt.compare(password, user.password)) {
        db.data.activeUser = username;
        db.data.lastActivity = Date.now();
        await db.write();
        res.cookie("username", username);
        res.cookie("lastActivity", Date.now().toString());
        return res.redirect("/index.html");
    } else {
        let page = fs.readFileSync(join(__dirname, "pages/login.html"), "utf-8");
        page = page.replace('{{message}}', 'Invalid username or password.');
        page = page.replace('style="display: none;"', 'style="display: block;"');
        return res.send(page);
    }
});

// Protected index page
app.get("/index.html", checkAuth, (req, res) => {
    res.sendFile(join(__dirname, "pages/index.html"));
});

// Logout
// Logout
app.get("/logout", async (req, res) => {
    const username = req.cookies.username;
    await db.read();
    if (db.data.activeUser === username) {
        db.data.activeUser = null;
        db.data.lastActivity = null;
        await db.write();
    }

    res.clearCookie("username");
    res.clearCookie("lastActivity");

    // Respect type query parameter: 'manual' or 'idle'
    const type = req.query.type || "manual";
    return res.redirect(`/login.html?loggedOut=${type}`);
});


// Status endpoint
app.get("/status", async (req, res) => {
    await db.read();
    res.json({
        activeUser: db.data.activeUser,
        currentUser: req.cookies.username || null
    });
});

app.listen(port, () => console.log(`Server running at http://localhost:${port}`));
