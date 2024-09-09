const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('./db');

const secretKey = 'tokenexpress';
const refreshTokenSecretKey = 'refreshexpress';
const refreshTokens = new Map(); // In-memory storage for refresh tokens

// Register a new user
const registerEmployee = (username, password, userId, callback) => {
    if (typeof callback !== 'function') {
        throw new TypeError('Callback must be a function');
    }
    const hashedPassword = bcrypt.hashSync(password, 10);
    const sql = `INSERT INTO Emp (id, username, password) VALUES (?, ?, ?)`;
    db.query(sql, [userId, username, hashedPassword], (err, result) => {
        if (err) {
            console.error('Registration error:', err); // Log the error
            return callback(err);
        }
        callback(null); // Invoke the callback with no error
    });
};

// Login and generate tokens
const loginEmployee = (username, password, callback) => {
    if (typeof callback !== 'function') {
        throw new TypeError('Callback must be a function');
    }
    const sql = `SELECT * FROM Emp WHERE username = ?`;
    db.query(sql, [username], (err, results) => {
        if (err || results.length === 0) {
            return callback(err || new Error('User not found'));
        }
        const employee = results[0];
        const isValidPassword = bcrypt.compareSync(password, employee.password);
        if (!isValidPassword) {
            return callback(new Error('Invalid password'));
        }
        const token = generateAccessToken(employee);
        const refreshToken = generateRefreshToken(employee);
        refreshTokens.set(refreshToken, employee.id); // Store refresh token in memory
        callback(null, { token, refreshToken });
    });
};

// Generate an access token
const generateAccessToken = (employee) => {
    return jwt.sign({ id: employee.id, username: employee.username }, secretKey, { expiresIn: '5m' }); // 5 minutes
};

// Generate a refresh token
const generateRefreshToken = (employee) => {
    return jwt.sign({ id: employee.id, username: employee.username }, refreshTokenSecretKey, { expiresIn: '1h' }); // 1 hour
};

// Middleware to authenticate the JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Token not found' });
    }
    jwt.verify(token, secretKey, (err, user) => {
        if (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({ message: 'Token expired. Please refresh your token or log in again.' });
            }
            return res.status(403).json({ message: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Endpoint to refresh the access token
const refreshAccessToken = (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken || !refreshTokens.has(refreshToken)) {
        return res.status(403).json({ message: 'Refresh token not found or invalid' });
    }
    jwt.verify(refreshToken, refreshTokenSecretKey, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid refresh token' });
        }
        const newAccessToken = generateAccessToken(user);
        res.json({ token: newAccessToken });
    });
};

// Logout by invalidating the refresh token
const logoutEmployee = (req, res) => {
    const authHeader = req.headers['authorization'];
    const accessToken = authHeader && authHeader.split(' ')[1];

    if (!accessToken) {
        return res.status(401).json({ message: 'Access token not found' });
    }

    jwt.verify(accessToken, secretKey, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid access token' });
        }

        // Find and delete the refresh token
        for (let [refreshToken, id] of refreshTokens) {
            if (id === user.id) {
                refreshTokens.delete(refreshToken);
                break;
            }
        }

        res.json({ message: 'Logged out successfully' });
    });
};


module.exports = {
    registerEmployee,
    loginEmployee,
    authenticateToken,
    refreshAccessToken,
    logoutEmployee
};
