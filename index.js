const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
const request = require('request-promise');

const userPools = {};

module.exports = {

    decodeAndVerifyJwtToken: (userPoolId, token) => {

        const region = userPoolId.split('_')[0]; // I hope region will always be a prefix of userPoolId

        const publicKeysUrl = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}/.well-known/jwks.json`;



        return request(publicKeysUrl)
            .then(publicKeys => {
                console.info(`publicKeys = ${publicKeys}`);
                const keyMap = buildKeyMap(publicKeys);

                console.info(`keyMap = ${keyMap}`);
                const decodedJwtToken = jwt.decode(token, { complete: true });
                console.info(`decodedJwtToken = ${decodedJwtToken}`);
                const pem = keyMap[decodedJwtToken.header.kid];
                console.info(`pem = ${pem}`);
                const claims = jwt.verify(token, pem, { algorithms: ['RS256'] });
                console.info(`claims = ${claims}`);
                return claims;
            });
    }
};

function buildKeyMap(publicKeys) {

    console.info(`buildKeyMap(publicKeys = ${JSON.stringify(publicKeys)}`);

    const pems = {};
    publicKeys.keys.forEach(key => pems[key.kid] = jwkToPem(key));

    return pems;
}
