const mongoose = require('mongoose');
const logger = require('./logger');

let isConnected = false;

const connectDB = async () => {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    logger.warn('No MONGODB_URI — using in-memory store');
    return;
  }

  try {
    await mongoose.connect(uri, {
      serverSelectionTimeoutMS: 30000, // 30s — Atlas can be slow on cold start
      connectTimeoutMS: 30000,
      socketTimeoutMS: 60000,
      maxPoolSize: 10,
    });
    isConnected = true;
    logger.info('MongoDB connected');

    mongoose.connection.on('disconnected', () => {
      isConnected = false;
      logger.warn('MongoDB disconnected — will retry');
    });
    mongoose.connection.on('reconnected', () => {
      isConnected = true;
      logger.info('MongoDB reconnected');
    });
  } catch (err) {
    isConnected = false;
    throw err; // caller handles this gracefully
  }
};

const getStatus = () => isConnected;

module.exports = { connectDB, getStatus };
