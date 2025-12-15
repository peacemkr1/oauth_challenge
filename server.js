const express = require('express');
const session = require('express-session');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// The flag players are trying to get
const FLAG = "davidCTF{weak_0auth_token_generation_peacemker}";

// User database
const USERS = {
    'admin': { password: 'admin123admin123', user_id: '1', role: 'admin' },
    'user': { password: 'password', user_id: '2', role: 'user' }
};

// Store auth codes and tokens
const authCodes = {};
const accessTokens = {};

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'ctf_secret_key',
    resave: false,
    saveUninitialized: false
}));

// VULNERABILITY: Predictable token generation
function generateToken(userId) {
    return crypto.createHash('md5').update(`token_${userId}`).digest('hex');
}

// Routes

app.get('/', (req, res) => {
    if (req.session.access_token && accessTokens[req.session.access_token]) {
        return res.redirect('/dashboard');
    }
    res.send(`
        <h1>OAuth Login Challenge</h1>
        <p>Welcome to the authentication system</p>
        <a href="/login">Click here to login</a>
    `);
});

app.get('/login', (req, res) => {
    res.send(`
        <h2>Login</h2>
        <form method="POST" action="/oauth/authorize">
            <label>Username:</label><br>
            <input name="username" required><br><br>
            <label>Password:</label><br>
            <input name="password" type="password" required><br><br>
            <button type="submit">Login</button>
        </form>
        <p><small>Hint: Try username=user, password=password</small></p>
    `);
});

app.post('/oauth/authorize', (req, res) => {
    const { username, password } = req.body;
    
    // Check credentials
    if (USERS[username] && USERS[username].password === password) {
        const userData = USERS[username];
        
        // Generate auth code
        const authCode = crypto.randomBytes(16).toString('hex');
        authCodes[authCode] = userData;
        
        // Redirect with code
        return res.redirect(`/oauth/callback?code=${authCode}`);
    }
    
    res.send('Invalid credentials. <a href="/login">Try again</a>');
});

app.get('/oauth/callback', (req, res) => {
    const code = req.query.code;
    
    if (!code || !authCodes[code]) {
        return res.send('Invalid authorization code');
    }
    
    const userData = authCodes[code];
    
    // VULNERABILITY: Generate predictable token
    const token = generateToken(userData.user_id);
    
    // Store token
    accessTokens[token] = userData;
    req.session.access_token = token;
    
    // Clean up used code
    delete authCodes[code];
    
    res.redirect('/dashboard');
});

app.get('/dashboard', (req, res) => {
    const token = req.session.access_token;
    
    if (!token || !accessTokens[token]) {
        return res.redirect('/');
    }
    
    const user = accessTokens[token];
    
    let content = `
        <h2>Dashboard</h2>
        <p><strong>Username:</strong> ${user.username}</p>
        <p><strong>Role:</strong> ${user.role}</p>
        <p><strong>User ID:</strong> ${user.user_id}</p>
        <br>
    `;
    
    // Only show flag to admin
    if (user.role === 'admin') {
        content += `<div style="background: #d4edda; padding: 20px; border: 2px solid #28a745;">
            <h3>Congratulations!</h3>
            <p><strong>FLAG: ${FLAG}</strong></p>
        </div>`;
    } else {
        content += `<div style="background: #f8d7da; padding: 20px; border: 2px solid #dc3545;">
            <p>You don't have permission to view the flag.</p>
            <p>Only admins can see it!</p>
        </div>`;
    }
    
    content += `
        <br>
        <a href="/debug">Debug Info</a> | 
        <a href="/logout">Logout</a>
    `;
    
    res.send(content);
});

app.get('/hints', (req, res) => {
    res.send(`
        <h2>Debug Information</h2>
        <hr>
        <h3>Token Generation Pattern:</h3>
        <p>Tokens are MD5 hash of: <code>"token_" + user_id</code></p>
        <hr>
        <h3>Example Tokens:</h3>
        <p><strong>Regular User (user_id=2):</strong> <code>${generateToken('2')}</code></p>
        <hr>
        <h3>Hint:</h3>
        <p>/inject-token?token=</p>
        <p>Try calculating MD5("token_1") yourself!</p>
        <br>
        <a href="/">Home</a>
    `);
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// Solve helper endpoint
app.get('/solve', (req, res) => {
    res.send(`
        <h2>CTF Solution Helper</h2>
        <p>Calculate the admin token:</p>
        <code>MD5("token_1") = ${generateToken('1')}</code>
        <br><br>
        <form method="GET" action="/inject-token">
            <label>Enter the admin token:</label><br>
            <input name="token" value="" size="40"><br><br>
            <button type="submit">Use This Token</button>
        </form>
        <br>
        <a href="/">Home</a>
    `);
});

app.get('/inject-token', (req, res) => {
    const token = req.query.token;
    const correctAdminToken = generateToken('1');
    
    if (token === correctAdminToken) {
        req.session.access_token = token;
        if (!accessTokens[token]) {
            accessTokens[token] = USERS['admin'];
        }
        res.send('Token injected successfully! <a href="/dashboard">Go to dashboard</a>');
    } else {
        res.send('Wrong token! <a href="/solve">Try again</a>');
    }
});

app.listen(PORT, () => {
    console.log(`OAuth CTF Challenge running on http://localhost:${PORT}`);
    console.log(`Test credentials: user / password`);
});
