const fs = require('fs');
const assert = require('chai').assert;

const { sign, verify } = require('jsonwebtoken');
const { pem2jwk, jwk2pem } = require('pem-jwk');

const { JwtVerifier, TokenExpiredError, JsonWebTokenError } = require('../'); // Defaults to index.js

describe('JwtVerifier', () => {

    // Fixtures
    //
    // Files created with:
    //     ssh-keygen -t rsa -b 2048 -f test.pem
    //     openssl rsa -in test.key -pubout -outform PEM -out test.pub.pem

    const testPublicPem = fs.readFileSync('test/test.pub.pem', { encoding: 'utf8', flags: 'r' });
    const testPrivatePem = fs.readFileSync('test/test.pem', { encoding: 'utf8', flags: 'r' });
    const kid = 'test';

    // Test initialization

    let jwtVerifier;

    beforeEach('Initializing mock public key request', function() {
        jwtVerifier = new JwtVerifier('aUserPool', (url) => new Promise((resolve, reject) => {

            const mockPublicKeyResponse = JSON.stringify({
                keys: [pem2jwk(testPublicPem, { kid })]
            });

            resolve(mockPublicKeyResponse);
        }));

    });

    // Test suites

    describe('pem <-> jwk conversion', function() {

        [
            { privateDesc: 'original', publicDesc: 'original' },
            { privateDesc: 'reconstituted', publicDesc: 'original' },
            { privateDesc: 'original', publicDesc: 'reconstituted' },
            { privateDesc: 'reconstituted', publicDesc: 'reconstituted' }
        ].forEach(function(spec) {
            it(`${spec.publicDesc} public pem can verify what ${spec.privateDesc} private pem wrote`, function() {

                const mapPem = (desc, originalPem) => desc === 'original' ? originalPem : jwk2pem(pem2jwk(originalPem));

                const privatePem = mapPem(spec.privateDesc, testPrivatePem);
                const publicPem = mapPem(spec.publicDesc, testPublicPem);

                const token = sign({ foo: 'bar' }, privatePem, { algorithm: 'RS256', keyid: kid });
                const verified = verify(token, publicPem);

                assert.isOk(verified, `${spec.publicDesc} cannot decode token made with ${spec.privateDesc}`);
            });
        });
    });

    describe('instantiating', function() {

        it('instantiates and loads keymap from mock', function(done) {

            jwtVerifier.publicKeysPromise
                .then(keyMap => {
                    assert.property(keyMap, kid);
                    assert.propertyVal(keyMap, kid, testPublicPem);
                })
                .then(done, done); // Node 6, which AWS Lambda currently uses, doesn't support finally().
        });
    });

    describe('decoding', function() {

        it('decodes a token to a payload', function() {

            const token = sign({ foo: 'bar' }, testPrivatePem, { algorithm: 'RS256', keyid: kid });

            const payload = jwtVerifier.decodeJwtToken(token);
            assert.propertyVal(payload, 'foo', 'bar');
        });
    });

    describe('verifying', function() {

        it('success with nonexpiring jwt', function(done) {

            const token = sign({ foo: 'bar' }, testPrivatePem, { algorithm: 'RS256', keyid: kid });

            jwtVerifier.decodeAndVerifyJwtToken(token)
                .then(payload => assert.propertyVal(payload, 'foo', 'bar'))
                .then(done, done);
        });

        it('success with unexpired jwt', function(done) {

            // Expires 30s from now

            const token = sign({ foo: 'bar', exp: Date.now() / 1000 + 30 }, testPrivatePem, { algorithm: 'RS256', keyid: kid });

            jwtVerifier.decodeAndVerifyJwtToken(token)
                .then(payload => assert.propertyVal(payload, 'foo', 'bar'))
                .then(done, done);
        });

        it('error with expired jwt', function(done) {

            // Expired 24h ago

            const token = sign({ foo: 'bar', exp: Date.now() / 1000 - 60 * 60 * 24 }, testPrivatePem, { algorithm: 'RS256', keyid: kid });

            jwtVerifier.decodeAndVerifyJwtToken(token)
                .then((result) => {
                    done(Error('Should have thrown TokenExpiredError'));
                })
                .catch(e => assert.instanceOf(e, TokenExpiredError))
                .then(done, done);
        });

        it('error with invalid pem', function(done) {

            // Change one character of the private key so that the public key no longer matches it
            const wonkyPrivatePem = testPrivatePem.replace(/0/, '1');

            const token = sign({ foo: 'bar' }, wonkyPrivatePem, { algorithm: 'RS256', keyid: kid });

            jwtVerifier.decodeAndVerifyJwtToken(token)
                .then((result) => {
                    done(Error('Should have thrown JsonWebTokenError'));
                })
                .catch(e => assert.instanceOf(e, JsonWebTokenError))
                .then(done, done);
        });
    });
});
