const { JsonWebTokenError, TokenExpiredError, NotBeforeError } = require('jsonwebtoken');

module.exports = {
    JwtVerifier: require('./src/JwtVerifier'),
    JsonWebTokenError,
    TokenExpiredError,
    NotBeforeError
};
