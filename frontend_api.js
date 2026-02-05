/**
 * Frontend API for DeFi Lending Pool
 * React/Node.js integration with Web3
 * Contains several security vulnerabilities for testing
 */

const express = require('express');
const cors = require('cors');
const Web3 = require('web3');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const Redis = require('redis');

const app = express();
const web3 = new Web3('https://mainnet.infura.io/v3/YOUR_INFURA_KEY');

// Configuration
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'my_jwt_secret_key';  // VULNERABILITY: Hardcoded JWT secret
const ORACLE_URL = 'http://localhost:5000/api';
const ORACLE_API_KEY = process.env.ORACLE_API_KEY || 'default_key_123';

// Contract addresses (from defi_lending_pool.sol)
const LENDING_POOL_ADDRESS = '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb';
const POOL_ABI = require('./abis/LendingPool.json');

// Redis client for caching
const redisClient = Redis.createClient();

// Middleware
app.use(cors());  // VULNERABILITY: CORS wide open
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Contract instance
const lendingPool = new web3.eth.Contract(POOL_ABI, LENDING_POOL_ADDRESS);


/**
 * Authentication middleware
 * VULNERABILITY: Weak JWT validation
 */
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    // VULNERABILITY: No algorithm specification in verify
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
}


/**
 * Login endpoint
 * VULNERABILITY: No rate limiting on login attempts
 */
app.post('/api/auth/login', async (req, res) => {
    const { address, signature } = req.body;
    
    // VULNERABILITY: No nonce validation
    // VULNERABILITY: No message verification
    
    const token = jwt.sign(
        { address: address },
        JWT_SECRET,
        { expiresIn: '24h' }
    );
    
    res.json({
        token: token,
        address: address
    });
});


/**
 * Get user position
 */
app.get('/api/position/:address', authenticateToken, async (req, res) => {
    const address = req.params.address;
    
    try {
        const position = await lendingPool.methods.positions(address).call();
        
        // VULNERABILITY: No validation that requested address matches authenticated user
        
        res.json({
            collateralAmount: position.collateralAmount,
            borrowAmount: position.borrowAmount,
            collateralToken: position.collateralToken,
            borrowToken: position.borrowToken,
            lastUpdate: position.lastUpdateTime
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


/**
 * Get token price from oracle
 */
app.get('/api/price/:token', async (req, res) => {
    const token = req.params.token;
    
    try {
        // VULNERABILITY: SSRF - user-controlled URL
        const oracleResponse = await axios.get(
            `${ORACLE_URL}/price/${token}`,
            {
                headers: { 'X-API-Key': ORACLE_API_KEY }
            }
        );
        
        res.json(oracleResponse.data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


/**
 * Deposit collateral
 */
app.post('/api/deposit', authenticateToken, async (req, res) => {
    const { token, amount, gasPrice } = req.body;
    const userAddress = req.user.address;
    
    // VULNERABILITY: No validation of amount
    // VULNERABILITY: User-controlled gas price
    
    try {
        const tx = lendingPool.methods.deposit(token, amount);
        const gas = await tx.estimateGas({ from: userAddress });
        
        const txData = {
            from: userAddress,
            to: LENDING_POOL_ADDRESS,
            data: tx.encodeABI(),
            gas: gas,
            gasPrice: gasPrice  // VULNERABILITY: User controls gas price
        };
        
        res.json({
            success: true,
            txData: txData
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


/**
 * Borrow tokens
 */
app.post('/api/borrow', authenticateToken, async (req, res) => {
    const { borrowToken, amount } = req.body;
    const userAddress = req.user.address;
    
    try {
        // Check user's collateral
        const position = await lendingPool.methods.positions(userAddress).call();
        const healthFactor = await lendingPool.methods.getHealthFactor(userAddress).call();
        
        // VULNERABILITY: Frontend validation only
        // No backend validation of borrow limits
        if (healthFactor < 150) {
            return res.status(400).json({ error: 'Insufficient collateral' });
        }
        
        const tx = lendingPool.methods.borrow(borrowToken, amount);
        const gas = await tx.estimateGas({ from: userAddress });
        
        res.json({
            success: true,
            txData: {
                from: userAddress,
                to: LENDING_POOL_ADDRESS,
                data: tx.encodeABI(),
                gas: gas
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


/**
 * Liquidate position
 */
app.post('/api/liquidate', authenticateToken, async (req, res) => {
    const { targetAddress } = req.body;
    const liquidatorAddress = req.user.address;
    
    try {
        // VULNERABILITY: No check if liquidation is profitable
        // VULNERABILITY: Front-running opportunity
        
        const tx = lendingPool.methods.liquidate(targetAddress);
        const gas = await tx.estimateGas({ from: liquidatorAddress });
        
        res.json({
            success: true,
            txData: {
                from: liquidatorAddress,
                to: LENDING_POOL_ADDRESS,
                data: tx.encodeABI(),
                gas: gas
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


/**
 * Get liquidation candidates
 */
app.get('/api/liquidations/candidates', async (req, res) => {
    try {
        // VULNERABILITY: Expensive operation without pagination
        // Could cause DoS
        
        const users = await getAllUsers();  // Hypothetical function
        const candidates = [];
        
        for (const user of users) {
            const healthFactor = await lendingPool.methods.getHealthFactor(user).call();
            
            if (healthFactor < 150) {
                const position = await lendingPool.methods.positions(user).call();
                candidates.push({
                    address: user,
                    healthFactor: healthFactor,
                    collateral: position.collateralAmount,
                    debt: position.borrowAmount
                });
            }
        }
        
        res.json({ candidates });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


/**
 * Update user settings
 * VULNERABILITY: Prototype pollution
 */
app.post('/api/user/settings', authenticateToken, async (req, res) => {
    const settings = {};
    const updates = req.body;
    
    // VULNERABILITY: No protection against __proto__ pollution
    for (let key in updates) {
        settings[key] = updates[key];
    }
    
    // Store in Redis
    await redisClient.set(
        `user:${req.user.address}:settings`,
        JSON.stringify(settings)
    );
    
    res.json({ success: true, settings });
});


/**
 * Search transactions
 * VULNERABILITY: NoSQL injection possibility
 */
app.get('/api/transactions/search', authenticateToken, async (req, res) => {
    const { query } = req.query;
    
    // VULNERABILITY: Direct query parameter usage
    const searchQuery = {
        $or: [
            { from: query },
            { to: query },
            { hash: query }
        ]
    };
    
    // Hypothetical MongoDB query
    // const results = await db.transactions.find(searchQuery);
    
    res.json({ results: [] });
});


/**
 * Render user dashboard
 * VULNERABILITY: XSS in template rendering
 */
app.get('/dashboard/:address', async (req, res) => {
    const address = req.params.address;
    
    try {
        const position = await lendingPool.methods.positions(address).call();
        
        // VULNERABILITY: Unescaped HTML rendering
        const html = `
            <html>
                <head><title>Dashboard</title></head>
                <body>
                    <h1>Welcome ${address}</h1>
                    <div>Collateral: ${position.collateralAmount}</div>
                    <div>Debt: ${position.borrowAmount}</div>
                </body>
            </html>
        `;
        
        res.send(html);
    } catch (error) {
        res.status(500).send(`<h1>Error: ${error.message}</h1>`);
    }
});


/**
 * Fetch external data
 * VULNERABILITY: SSRF
 */
app.post('/api/fetch', authenticateToken, async (req, res) => {
    const { url } = req.body;
    
    // VULNERABILITY: No URL validation
    try {
        const response = await axios.get(url);
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


/**
 * Admin endpoint
 * VULNERABILITY: Inadequate access control
 */
app.post('/api/admin/update-oracle', async (req, res) => {
    const { newOracleAddress } = req.body;
    
    // VULNERABILITY: No admin authentication
    // Anyone can change the oracle address
    
    try {
        const accounts = await web3.eth.getAccounts();
        const tx = await lendingPool.methods.updateOracle(newOracleAddress).send({
            from: accounts[0]
        });
        
        res.json({ success: true, tx: tx.transactionHash });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


/**
 * Cache management
 */
app.delete('/api/cache/:key', async (req, res) => {
    const key = req.params.key;
    
    // VULNERABILITY: No authentication on cache deletion
    await redisClient.del(key);
    
    res.json({ success: true });
});


/**
 * Debug endpoint
 * VULNERABILITY: Information disclosure
 */
app.get('/api/debug', (req, res) => {
    res.json({
        env: process.env,  // VULNERABILITY: Exposing environment variables
        jwt_secret: JWT_SECRET,  // VULNERABILITY: Exposing JWT secret
        oracle_key: ORACLE_API_KEY,
        contract_address: LENDING_POOL_ADDRESS
    });
});


// Hypothetical helper function
async function getAllUsers() {
    // This would query past events or an indexer
    return [
        '0x1234...5678',
        '0xabcd...ef00'
    ];
}


// Error handler
app.use((err, req, res, next) => {
    // VULNERABILITY: Detailed error messages in production
    console.error(err.stack);
    res.status(500).json({
        error: err.message,
        stack: err.stack
    });
});


// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Frontend API running on port ${PORT}`);
    console.log(`JWT Secret: ${JWT_SECRET}`);  // VULNERABILITY: Logging sensitive data
    console.log(`Oracle URL: ${ORACLE_URL}`);
});

module.exports = app;