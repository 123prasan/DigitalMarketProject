// services/websocket.js
const WebSocket = require('ws');

// These are now encapsulated within the service
const clients = new Map();
const messageHistory = {};

function initializeWebSocket(wss) {
    wss.on('connection', (ws) => {
        let userId;

        ws.on('message', (message) => {
            const data = JSON.parse(message);
            switch (data.type) {
                case 'register':
                    userId = data.userId;
                    clients.set(userId, ws);
                    console.log(`User ${userId} registered.`);
                    break;

                case 'private_message':
                    const { recipientId, text } = data;
                    const recipientSocket = clients.get(recipientId);
                    const roomKey = [userId, recipientId].sort().join('--');
                    if (!messageHistory[roomKey]) {
                        messageHistory[roomKey] = [];
                    }
                    const messageToSend = {
                        type: 'private_message',
                        senderId: userId,
                        recipientId,
                        text,
                        timestamp: new Date()
                    };
                    messageHistory[roomKey].push(messageToSend);
                    if (recipientSocket && recipientSocket.readyState === WebSocket.OPEN) {
                        recipientSocket.send(JSON.stringify(messageToSend));
                    }
                    break;
            }
        });

        ws.on('close', () => {
            if (userId) {
                clients.delete(userId);
                console.log(`User ${userId} disconnected.`);
            }
        });
    });
}

function getMessageHistory(roomKey) {
    return messageHistory[roomKey] || [];
}

module.exports = { initializeWebSocket, getMessageHistory };