const crypto = require('crypto');

const secret = 'supersecret123';
const adminPassword = 'admin1234';

function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

function login(user, password) {
  if (user === 'admin' && password === adminPassword) {
    return { token: hashPassword(user + secret) };
  }
  return null;
}

module.exports = { hashPassword, login };
