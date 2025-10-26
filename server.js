require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');

// Security constants
const MAX_MESSAGES = 10000;
const MAX_USERS = 5000;
const MAX_MESSAGE_SIZE = 100000; // 100KB per message
const MAX_CHUNK_SIZE = 100000; // 100KB per chunk
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = 100; // per window

// Rate limiting storage
const rateLimitMap = new Map();

const app = express();
const PORT = process.env.PORT || 3000;

// Rate limiting middleware
const rateLimit = (req, res, next) => {
    const identifier = req.ip || 'unknown';
    const now = Date.now();
    
    if (!rateLimitMap.has(identifier)) {
        rateLimitMap.set(identifier, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
        return next();
    }
    
    const record = rateLimitMap.get(identifier);
    
    if (now > record.resetTime) {
        rateLimitMap.set(identifier, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
        return next();
    }
    
    if (record.count >= RATE_LIMIT_MAX_REQUESTS) {
        return res.status(429).json({ error: 'Too many requests. Please try again later.' });
    }
    
    record.count++;
    next();
};

// Clean up rate limit map periodically
setInterval(() => {
    const now = Date.now();
    for (const [key, value] of rateLimitMap.entries()) {
        if (now > value.resetTime) {
            rateLimitMap.delete(key);
        }
    }
}, RATE_LIMIT_WINDOW);

// Middleware
app.use(cors({
    origin: true, // Allow all origins for development
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '50mb' }));
app.use(rateLimit);

// In-memory storage
const messages = [];
const users = [];
const fileChunks = {};
let journalistPublicKey = null; // Store journalist's public key

// Data expiration (24 hours)
const EXPIRATION_TIME = 24 * 60 * 60 * 1000;

// Clean up expired data
setInterval(() => {
    const now = Date.now();
    const expiredMessages = messages.filter(msg => now - msg.timestamp > EXPIRATION_TIME);
    expiredMessages.forEach(msg => {
        const index = messages.indexOf(msg);
        if (index > -1) messages.splice(index, 1);
    });
}, 60 * 60 * 1000); // Check every hour

// API Routes

// Input validation helper
const validateHash = (hash) => {
    return hash && typeof hash === 'string' && hash.length === 32 && /^[a-f0-9]+$/.test(hash);
};

const validateMessageData = (data) => {
    return data && typeof data === 'string' && data.length <= MAX_MESSAGE_SIZE;
};

// Register user
app.post('/api/register-user', (req, res) => {
    const { hash } = req.body;
    
    if (!validateHash(hash)) {
        return res.status(400).json({ error: 'Invalid hash format' });
    }

    // Limit total users
    if (users.length >= MAX_USERS && !users.find(u => u.hash === hash)) {
        return res.status(503).json({ error: 'Server capacity reached' });
    }

    if (!users.find(u => u.hash === hash)) {
        users.push({ hash, lastActive: Date.now() });
    } else {
        // Update last active
        const user = users.find(u => u.hash === hash);
        user.lastActive = Date.now();
    }

    res.json({ 
        success: true,
        journalistPublicKey: journalistPublicKey
    });
});

// Register journalist (protected - only allow once or with secret)
app.post('/api/register-journalist', (req, res) => {
    const { publicKey, secret } = req.body;
    
    // Require secret if journalist key already exists
    if (journalistPublicKey && secret !== process.env.JOURNALIST_SECRET) {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    
    if (!publicKey || typeof publicKey !== 'string') {
        return res.status(400).json({ error: 'Invalid public key' });
    }
    
    journalistPublicKey = publicKey;
    res.json({ success: true });
});

// Send message (from user to journalist or vice versa)
app.post('/api/send-message', (req, res) => {
    const { from, to, encryptedData, timestamp, hasFiles, userPublicKey } = req.body;

    // Validate inputs
    if (!from || typeof from !== 'string') {
        return res.status(400).json({ error: 'Invalid sender' });
    }
    
    if (!validateMessageData(encryptedData)) {
        return res.status(400).json({ error: 'Invalid message data' });
    }
    
    // Limit total messages
    if (messages.length >= MAX_MESSAGES) {
        return res.status(503).json({ error: 'Server capacity reached' });
    }

    const message = {
        id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
        from,
        to: to || null,
        encryptedData,
        timestamp: timestamp || Date.now(),
        hasFiles: hasFiles || false,
        userPublicKey: userPublicKey || null
    };

    messages.push(message);

    res.json({ success: true, messageId: message.id });
});

// Send file chunk
app.post('/api/send-chunk', (req, res) => {
    const { from, chunkIndex, totalChunks, chunkData, fileName, fileType, fileSize } = req.body;

    // Validate inputs
    if (!from || typeof from !== 'string') {
        return res.status(400).json({ error: 'Invalid sender' });
    }
    
    if (typeof chunkIndex !== 'number' || typeof totalChunks !== 'number') {
        return res.status(400).json({ error: 'Invalid chunk metadata' });
    }
    
    if (!chunkData || typeof chunkData !== 'string' || chunkData.length > MAX_CHUNK_SIZE) {
        return res.status(400).json({ error: 'Invalid chunk data' });
    }
    
    if (!fileName || typeof fileName !== 'string' || fileName.length > 255) {
        return res.status(400).json({ error: 'Invalid filename' });
    }

    const chunkKey = `${from}_${fileName}`;
    
    if (!fileChunks[chunkKey]) {
        fileChunks[chunkKey] = {
            from,
            fileName,
            fileType,
            fileSize,
            totalChunks,
            chunks: {}
        };
    }

    fileChunks[chunkKey].chunks[chunkIndex] = chunkData;
    fileChunks[chunkKey].lastUpdate = Date.now();

    // Check if all chunks received
    const receivedChunks = Object.keys(fileChunks[chunkKey].chunks).length;
    if (receivedChunks === totalChunks) {
        // File is complete
        const messageId = Date.now().toString() + Math.random().toString(36).substr(2, 9);
        const message = {
            id: messageId,
            from,
            timestamp: Date.now(),
            hasFiles: true,
            fileData: fileChunks[chunkKey]
        };
        
        messages.push(message);
        
        // Clean up chunks after a delay
        setTimeout(() => {
            delete fileChunks[chunkKey];
        }, 60000);
    }

    res.json({ success: true, received: receivedChunks, total: totalChunks });
});

// Get messages
app.get('/api/get-messages/:userType', (req, res) => {
    const { userType } = req.params;

    if (userType === 'journalist') {
        // Return all messages for journalist
        res.json({ messages: messages });
    } else {
        // Return messages for specific user (includes messages TO that user)
        const { hash } = req.query;
        
        if (!validateHash(hash)) {
            return res.status(400).json({ error: 'Invalid user hash' });
        }

        // Messages from user AND to user
        const userMessages = messages.filter(msg => msg.from === hash || msg.to === hash);
        res.json({ messages: userMessages });
    }
});

// Nuke user data
app.post('/api/nuke-user', (req, res) => {
    const { hash } = req.body;
    
    if (!validateHash(hash)) {
        return res.status(400).json({ error: 'Invalid user hash' });
    }

    // Remove all messages from this user
    for (let i = messages.length - 1; i >= 0; i--) {
        if (messages[i].from === hash) {
            messages.splice(i, 1);
        }
    }

    // Remove user from registry
    const userIndex = users.findIndex(u => u.hash === hash);
    if (userIndex > -1) users.splice(userIndex, 1);

    // Clean up file chunks
    Object.keys(fileChunks).forEach(key => {
        if (key.startsWith(hash + '_')) {
            delete fileChunks[key];
        }
    });

    res.json({ success: true });
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: Date.now() });
});

// Start server
app.listen(PORT, () => {
    console.log(`The Line Server running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});
