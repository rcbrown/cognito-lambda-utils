const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
const requestPromise = require('request-promise');

// const console = console;
const console = { info: () => {}, error: () => {} };

module.exports = class JwtVerifier {

    constructor(userPoolId, request = requestPromise) {

        const region = userPoolId.split('_')[0]; // I hope region will always be a prefix of userPoolId

        this.userPoolUrl = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;

        const publicKeysUrl = `${this.userPoolUrl}/.well-known/jwks.json`;

        this.publicKeysPromise = this.retrievePublicKeys(publicKeysUrl, request);
    }

    decodeAndVerifyJwtToken(token) {

        console.info(`token = ${token}`);

        return this.publicKeysPromise
            .then(keyMap => this.decodeAndVerifyJwtTokenWithKeyMap(token, keyMap));
    }

    decodeJwtToken(token, options = { includeHeaders: false }) {

        console.info(`token = ${token}`);

        const decodedJwtToken = jwt.decode(token, { complete: options.includeHeaders });
        console.info(`decodedJwtToken = ${JSON.stringify(decodedJwtToken)}`);

        return decodedJwtToken;
    }

    decodeAndVerifyJwtTokenWithPem(token, pem) {

        console.info(`token = ${token}, pem = ${pem}`);

        const decodedJwtToken = this.decodeJwtToken(token);

        if (this.userPoolUrl !== decodedJwtToken.iss) throw new jwt.JsonWebTokenError(`User pool ${this.userPoolUrl} does not match issuer in claims: ${decodedJwtToken.iss}`);

        if ('id' !== decodedJwtToken.token_use) throw new jwt.JsonWebTokenError(`JWT token_use must be 'id', not ${decodedJwtToken.token_use}`);

        const claims = jwt.verify(token, pem, { algorithms: ['RS256'] });
        console.info(`claims = ${claims}`);

        return claims;
    }

    decodeAndVerifyJwtTokenWithKeyMap(token, keyMap) {

        console.info(`keyMap = ${keyMap}, token = ${token}`);

        const decodedJwtToken = this.decodeJwtToken(token, { includeHeaders: true });
        console.info(`decodedJwtToken = ${decodedJwtToken}`);

        const pem = keyMap[decodedJwtToken.header.kid];
        console.info(`pem = ${pem}`);

        return this.decodeAndVerifyJwtTokenWithPem(token, pem);
    }

    buildKeyMap(publicKeys) {

        console.info(`buildKeyMap(publicKeys = ${JSON.stringify(publicKeys)})`);

        const pems = {};
        publicKeys.keys.forEach(key => pems[key.kid] = jwkToPem(key));

        return pems;
    }

    retrievePublicKeys(url, request) {

        return request(url)
            .then(publicKeys => {
                console.info(`publicKeys = ${publicKeys}`);
                console.info(`parsed publicKeys = ${JSON.parse(publicKeys)} `)
                const parsedPublicKeys = JSON.parse(publicKeys);
                const keyMap = this.buildKeyMap(parsedPublicKeys);
                return keyMap;
            });

    }
}
