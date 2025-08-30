// Intentionally vulnerable JavaScript code for Semgrep testing

const express = require('express');
const mysql = require('mysql');
const crypto = require('crypto');
const fs = require('fs');
const { exec } = require('child_process');

const app = express();
app.use(express.json());

// 1. SQL Injection vulnerability
function getUserData(userId) {
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'password123', // Hardcoded password
        database: 'users'
    });
    
    // Vulnerable: String concatenation in SQL
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    connection.query(query, (error, results) => {
        console.log(results);
    });
}

// 2. Command Injection
app.post('/backup', (req, res) => {
    const filename = req.body.filename;
    // Vulnerable: Unsanitized input in shell command
    exec(`cp ${filename} /backup/`, (error, stdout, stderr) => {
        res.send('Backup completed');
    });
});

// 3. Path Traversal
app.get('/file/:filename', (req, res) => {
    const filename = req.params.filename;
    // Vulnerable: No path validation
    const filePath = `/uploads/${filename}`;
    fs.readFile(filePath, 'utf8', (err, data) => {
        res.send(data);
    });
});

// 4. Cross-Site Scripting (XSS)
app.get('/search', (req, res) => {
    const query = req.query.q;
    // Vulnerable: Unescaped user input
    res.send(`<h1>Search results for: ${query}</h1>`);
});

// 5. Prototype Pollution
function merge(target, source) {
    for (let key in source) {
        // Vulnerable: No check for __proto__
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// 6. Weak cryptographic practices
function encryptData(data) {
    // Vulnerable: Weak encryption algorithm
    const cipher = crypto.createCipher('des', 'weakkey');
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// 7. Hardcoded secrets
const API_KEY = 'sk-1234567890abcdef'; // Vulnerable: Hardcoded API key
const DB_PASSWORD = 'admin123'; // Vulnerable: Hardcoded password

// 8. eval() usage - Code injection
app.post('/calculate', (req, res) => {
    const expression = req.body.expr;
    try {
        // Vulnerable: Direct eval of user input
        const result = eval(expression);
        res.json({ result: result });
    } catch (error) {
        res.status(400).json({ error: 'Invalid expression' });
    }
});

// 9. Regex Denial of Service (ReDoS)
function validateEmail(email) {
    // Vulnerable: Catastrophic backtracking regex
    const emailRegex = /^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$/;
    return emailRegex.test(email);
}

// 10. Insecure random number generation
function generateToken() {
    // Vulnerable: Using Math.random() for security-sensitive operation
    return Math.random().toString(36).substr(2, 9);
}

// 11. Server-Side Request Forgery (SSRF)
const axios = require('axios');

app.post('/fetch', async (req, res) => {
    const url = req.body.url;
    try {
        // Vulnerable: No URL validation
        const response = await axios.get(url);
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ error: 'Request failed' });
    }
});

// 12. Information disclosure
app.get('/debug', (req, res) => {
    // Vulnerable: Exposing sensitive information
    res.json({
        environment: process.env,
        config: {
            database_password: 'secret123',
            jwt_secret: 'my-secret-key'
        }
    });
});

// 13. Insecure cookie settings
app.get('/login', (req, res) => {
    // Vulnerable: Insecure cookie settings
    res.cookie('sessionId', '123456', {
        httpOnly: false, // Should be true
        secure: false,   // Should be true in production
        sameSite: 'none' // Should be 'strict' or 'lax'
    });
    res.send('Logged in');
});

// 14. XML External Entity (XXE) vulnerability
const xml2js = require('xml2js');

app.post('/parse-xml', (req, res) => {
    const xmlData = req.body.xml;
    // Vulnerable: XXE attack possible
    xml2js.parseString(xmlData, (err, result) => {
        res.json(result);
    });
});

// 15. Weak session management
const sessions = {};

app.post('/create-session', (req, res) => {
    const userId = req.body.userId;
    // Vulnerable: Predictable session ID
    const sessionId = userId + '_' + Date.now();
    sessions[sessionId] = { userId: userId };
    res.json({ sessionId: sessionId });
});

// 16. NoSQL Injection (if using MongoDB)
// app.post('/user', (req, res) => {
//     const userId = req.body.userId;
//     // Vulnerable: Direct object injection
//     db.collection('users').find({ id: userId }).toArray((err, results) => {
//         res.json(results);
//     });
// });

// 17. Timing attack vulnerability
function authenticateUser(username, password) {
    const users = {
        'admin': 'secretpassword123',
        'user': 'password456'
    };
    
    // Vulnerable: Timing attack possible
    if (users[username] && users[username] === password) {
        return true;
    }
    return false;
}

// 18. Insufficient input validation
app.post('/upload', (req, res) => {
    const fileData = req.body.fileData;
    const filename = req.body.filename;
    
    // Vulnerable: No file type validation
    fs.writeFile(`/uploads/${filename}`, fileData, (err) => {
        if (err) {
            res.status(500).send('Upload failed');
        } else {
            res.send('File uploaded successfully');
        }
    });
});

app.listen(3000, '0.0.0.0', () => {
    console.log('Server running on port 3000');
});