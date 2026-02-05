/**
 * Secure Frontend API for DeFi Lending Pool
 * All security vulnerabilities have been fixed
 */

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const csurf = require('csurf');
const cookieParser = require('cookieParser');
const { body, param, query, validationResult } = require('express-validator');
const Web3 = require('web3');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const Redis = require('redis');
const DOMPurify = require('isomorphic-dompurify');
const crypto = require('crypto');

require('dotenv').config();

const app = express();

// FIXED: Secure configuration from environment
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const ORACLE_URL = process.env.ORACLE_URL;
const ORACLE_API_KEY = process.env.ORACLE_API_KEY;
const LENDING_POOL_ADDRESS = process.env.LENDING_POOL_ADDRESS;

if (!JWT_SECRET || !ORACLE_URL || !ORACLE_API_KEY || !LENDING_POOL_ADDRESS) {
    console.error('Missing required environment variables');
    process.exit(1);
}

const web3 = new Web3(process.env.WEB3_PROVIDER_URL);
const POOL_ABI = require('./abis/LendingPool.json');
const lendingPool = new web3.eth.Contract(POOL_ABI, LENDING_POOL_ADDRESS);

// Redis client
const redisClient = Redis.createClient({
    host: process.env.REDIS_HOST || 'localhost',
    port: process.env.REDIS_PORT || 6379
});

// FIXED: Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
}));

// FIXED: Restricted CORS
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000').split(',');
app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    next();
});

app.use(express.json({ limit: '10kb' })); // FIXED: Limit payload size
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// FIXED: Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP'
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5, // FIXED: Stricter limit for login
    message: 'Too many login attempts'
});

app.use('/api/', limiter);

// FIXED: CSRF protection
const csrfProtection = csurf({ cookie: true });

/**
 * FIXED: Secure JWT authentication
 */
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    // FIXED: Specify algorithm to prevent algorithm confusion attack
    jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] }, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

/**
 * Validate Ethereum address
 */
function isValidAddress(address) {
    return /^0x[a-fA-F0-9]{40}$/.test(address);
}

/**
 * FIXED: Secure login with nonce verification
 */
app.post('/api/auth/login',
    loginLimiter,
    [
        body('address').custom(isValidAddress).withMessage('Invalid address'),
        body('signature').isLength({ min: 132, max: 132 }).withMessage('Invalid signature'),
        body('nonce').isLength({ min: 32, max: 64 }).withMessage('Invalid nonce')
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        
        const { address, signature, nonce } = req.body;
        
        // FIXED: Verify nonce from Redis
        const storedNonce = await redisClient.get(`nonce:${address}`);
        
        if (!storedNonce || storedNonce !== nonce) {
            return res.status(401).json({ error: 'Invalid nonce' });
        }
        
        // Verify signature
        const message = `Sign this message to authenticate: ${nonce}`;
        const recoveredAddress = web3.eth.accounts.recover(message, signature);
        
        if (recoveredAddress.toLowerCase() !== address.toLowerCase()) {
            return res.status(401).json({ error: 'Invalid signature' });
        }
        
        // Delete used nonce
        await redisClient.del(`nonce:${address}`);
        
        // Generate JWT with limited lifetime
        const token = jwt.sign(
            { address: address.toLowerCase() },
            JWT_SECRET,
            { 
                algorithm: 'HS256',
                expiresIn: '1h' // FIXED: Shorter expiry
            }
        );
        
        res.json({ token, expiresIn: 3600 });
    }
);

/**
 * Get nonce for signing
 */
app.get('/api/auth/nonce/:address',
    [param('address').custom(isValidAddress)],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        
        const { address } = req.params;
        const nonce = crypto.randomBytes(32).toString('hex');
        
        // Store nonce with 5 minute expiry
        await redisClient.setex(`nonce:${address}`, 300, nonce);
        
        res.json({ nonce });
    }
);

/**
 * FIXED: Get user position with authorization check
 */
app.get('/api/position/:address',
    authenticateToken,
    [param('address').custom(isValidAddress)],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        
        const { address } = req.params;
        
        // FIXED: Verify user can only access their own position
        if (address.toLowerCase() !== req.user.address) {
            return res.status(403).json({ error: 'Unauthorized' });
        }
        
        try {
            const position = await lendingPool.methods.positions(address).call();
            
            res.json({
                collateralAmount: position.collateralAmount,
                borrowAmount: position.borrowAmount,
                collateralToken: position.collateralToken,
                borrowToken: position.borrowToken,
                lastUpdate: position.lastUpdateTime
            });
        } catch (error) {
            console.error('Error fetching position:', error);
            res.status(500).json({ error: 'Failed to fetch position' });
        }
    }
);

/**
 * FIXED: Get token price with validation
 */
app.get('/api/price/:token',
    authenticateToken,
    [param('token').custom(isValidAddress)],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        
        const { token } = req.params;
        
        try {
            // FIXED: No user-controlled URL
            const oracleResponse = await axios.get(
                `${ORACLE_URL}/price/${token}`,
                {
                    headers: { 'X-API-Key': ORACLE_API_KEY },
                    timeout: 5000
                }
            );
            
            res.json(oracleResponse.data);
        } catch (error) {
            console.error('Error fetching price:', error);
            res.status(500).json({ error: 'Failed to fetch price' });
        }
    }
);

/**
 * FIXED: Deposit with validation
 */
app.post('/api/deposit',
    authenticateToken,
    csrfProtection,
    [
        body('token').custom(isValidAddress).withMessage('Invalid token address'),
        body('amount').isNumeric().withMessage('Invalid amount'),
        body('gasPrice').optional().isNumeric().withMessage('Invalid gas price')
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        
        const { token, amount } = req.body;
        const userAddress = req.user.address;
        
        // FIXED: Validate amount
        const amountBN = web3.utils.toBN(amount);
        if (amountBN.lte(web3.utils.toBN(0))) {
            return res.status(400).json({ error: 'Amount must be positive' });
        }
        
        try {
            const tx = lendingPool.methods.deposit(token, amount);
            const gas = await tx.estimateGas({ from: userAddress });
            
            // FIXED: Use current gas price from network
            const gasPrice = await web3.eth.getGasPrice();
            
            const txData = {
                from: userAddress,
                to: LENDING_POOL_ADDRESS,
                data: tx.encodeABI(),
                gas: Math.floor(gas * 1.2), // Add 20% buffer
                gasPrice: gasPrice
            };
            
            res.json({ success: true, txData });
        } catch (error) {
            console.error('Error creating deposit transaction:', error);
            res.status(500).json({ error: 'Failed to create transaction' });
        }
    }
);

/**
 * FIXED: Update user settings with protection against prototype pollution
 */
app.post('/api/user/settings',
    authenticateToken,
    csrfProtection,
    async (req, res) => {
        const updates = req.body;
        
        // FIXED: Whitelist allowed settings keys
        const allowedKeys = ['theme', 'notifications', 'language', 'slippage'];
        const settings = {};
        
        for (const key of allowedKeys) {
            if (updates.hasOwnProperty(key) && key !== '__proto__' && key !== 'constructor') {
                // Sanitize values
                settings[key] = String(updates[key]).substring(0, 100);
            }
        }
        
        try {
            await redisClient.setex(
                `user:${req.user.address}:settings`,
                86400, // 24 hour expiry
                JSON.stringify(settings)
            );
            
            res.json({ success: true, settings });
        } catch (error) {
            console.error('Error updating settings:', error);
            res.status(500).json({ error: 'Failed to update settings' });
        }
    }
);

/**
 * FIXED: Render dashboard with proper escaping
 */
app.get('/dashboard/:address',
    authenticateToken,
    [param('address').custom(isValidAddress)],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        
        const { address } = req.params;
        
        // FIXED: Authorization check
        if (address.toLowerCase() !== req.user.address) {
            return res.status(403).send('Unauthorized');
        }
        
        try {
            const position = await lendingPool.methods.positions(address).call();
            
            // FIXED: Proper HTML escaping
            const sanitizedAddress = DOMPurify.sanitize(address);
            const sanitizedCollateral = DOMPurify.sanitize(position.collateralAmount);
            const sanitizedDebt = DOMPurify.sanitize(position.borrowAmount);
            
            const html = `
                <!DOCTYPE html>
                <html>
                    <head>
                        <title>Dashboard</title>
                        <meta charset="utf-8">
                    </head>
                    <body>
                        <h1>Welcome ${sanitizedAddress}</h1>
                        <div>Collateral: ${sanitizedCollateral}</div>
                        <div>Debt: ${sanitizedDebt}</div>
                    </body>
                </html>
            `;
            
            res.send(html);
        } catch (error) {
            console.error('Error rendering dashboard:', error);
            res.status(500).send('An error occurred');
        }
    }
);

// FIXED: Removed dangerous endpoints
// - /api/fetch (SSRF vulnerability)
// - /api/admin/update-oracle (Missing authentication)
// - /api/debug (Information disclosure)

/**
 * Get CSRF token
 */
app.get('/api/csrf-token', csrfProtection, (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

/**
 * Error handler - FIXED: No stack traces
 */
app.use((err, req, res, next) => {
    console.error('Error:', err);
    
    // Don't expose internal errors
    if (err.code === 'EBADCSRFTOKEN') {
        res.status(403).json({ error: 'Invalid CSRF token' });
    } else {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Start server - FIXED: Localhost only in production
const host = process.env.NODE_ENV === 'production' ? '127.0.0.1' : '0.0.0.0';

app.listen(PORT, host, () => {
    console.log(`Secure Frontend API running on ${host}:${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    
});

module.exports = app;