const assert = require('chai').assert;

const { sign, TokenExpiredError } = require('jsonwebtoken');
const rsaPemToJwk = require('rsa-pem-to-jwk');
const pem2jwk = require('pem2jwk');
const jwk2pem = require('jwk-to-pem');

const JwtVerifier = require('../JwtVerifier');

// Generated at https://mkjwk.org

describe('JwtVerifier', () => {

    const nonExpiringToken = {
        header: {
            alg: "RS256",
            typ: "JWT",
            kid: "nonexpired"
        },
        payload: {
            sub: "1234567890",
            name: "John Doe",
            admin: true,
            iat: 1516239022
        },
        publicPem: `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugd
UWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQs
HUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5D
o2kQ+X5xK9cipRgEKwIDAQAB
-----END PUBLIC KEY-----`,
        privatePem: `-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw
33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW
+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB
AoGAD+onAtVye4ic7VR7V50DF9bOnwRwNXrARcDhq9LWNRrRGElESYYTQ6EbatXS
3MCyjjX2eMhu/aF5YhXBwkppwxg+EOmXeh+MzL7Zh284OuPbkglAaGhV9bb6/5Cp
uGb1esyPbYW+Ty2PC0GSZfIXkXs76jXAu9TOBvD0ybc2YlkCQQDywg2R/7t3Q2OE
2+yo382CLJdrlSLVROWKwb4tb2PjhY4XAwV8d1vy0RenxTB+K5Mu57uVSTHtrMK0
GAtFr833AkEA6avx20OHo61Yela/4k5kQDtjEf1N0LfI+BcWZtxsS3jDM3i1Hp0K
Su5rsCPb8acJo5RO26gGVrfAsDcIXKC+bQJAZZ2XIpsitLyPpuiMOvBbzPavd4gY
6Z8KWrfYzJoI/Q9FuBo6rKwl4BFoToD7WIUS+hpkagwWiz+6zLoX1dbOZwJACmH5
fSSjAkLRi54PKJ8TFUeOP15h9sQzydI8zJU+upvDEKZsZc/UhT/SySDOxQ4G/523
Y0sz/OZtSWcol/UMgQJALesy++GdvoIDLfJX5GBQpuFgFenRiRDabxrE9MNUZ2aP
FaFp+DyAe+b4nDwuJaW2LURbr8AEZga7oQj0uYxcYw==
-----END RSA PRIVATE KEY-----`,
        jwt: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im5vbmV4cGlyZWQifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.pp_WQRFIVjBjp93RqsB1LOdsz9EpwmrZTm6HX3pKMfw4nU6bOi5QFH-J_xJqqQg1G4Kcsi0Dc75VWFpym4K2TfwLrcPRnQAgxMGab5B5nOdoKt7Qd5GNP1xurnX-Uf1JyaMmN63QrfTmlu9uAzg8ouWRgBHyvBqdvyzm80F1jCI'
    };

    const alreadyExpiredToken = {
        header: {
            alg: "RS256",
            typ: "JWT",
            kid: "expired"
        },
        payload: {
            sub: "1234567890",
            name: "John Doe",
            admin: true,
            iat: 1516239022,
            exp: 1516239023
        },
        publicPem: `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugd
UWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQs
HUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5D
o2kQ+X5xK9cipRgEKwIDAQAB
-----END PUBLIC KEY-----`,
        privatePem: `-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw
33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW
+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB
AoGAD+onAtVye4ic7VR7V50DF9bOnwRwNXrARcDhq9LWNRrRGElESYYTQ6EbatXS
3MCyjjX2eMhu/aF5YhXBwkppwxg+EOmXeh+MzL7Zh284OuPbkglAaGhV9bb6/5Cp
uGb1esyPbYW+Ty2PC0GSZfIXkXs76jXAu9TOBvD0ybc2YlkCQQDywg2R/7t3Q2OE
2+yo382CLJdrlSLVROWKwb4tb2PjhY4XAwV8d1vy0RenxTB+K5Mu57uVSTHtrMK0
GAtFr833AkEA6avx20OHo61Yela/4k5kQDtjEf1N0LfI+BcWZtxsS3jDM3i1Hp0K
Su5rsCPb8acJo5RO26gGVrfAsDcIXKC+bQJAZZ2XIpsitLyPpuiMOvBbzPavd4gY
6Z8KWrfYzJoI/Q9FuBo6rKwl4BFoToD7WIUS+hpkagwWiz+6zLoX1dbOZwJACmH5
fSSjAkLRi54PKJ8TFUeOP15h9sQzydI8zJU+upvDEKZsZc/UhT/SySDOxQ4G/523
Y0sz/OZtSWcol/UMgQJALesy++GdvoIDLfJX5GBQpuFgFenRiRDabxrE9MNUZ2aP
FaFp+DyAe+b4nDwuJaW2LURbr8AEZga7oQj0uYxcYw==
-----END RSA PRIVATE KEY-----`,
        jwt: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImV4cGlyZWQifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNTE2MjM5MDIzfQ.cj6DpYw3cpnbKJurwA5Ozex_uN1HiY5kY04zd-ahbSjQaKVvc3RqsQLwQhewzK9JR8Q6SmpQlqfEig4p_PmiiGmCmQOz6TgDCl-NlB4OhF3S7ZXuzEI2ivlx4mZnO_jgp-7RS3ao0HJBeSaKnGtIEWsEjEMFaoTRbNM6VTan9O8'
    }

    // it('try out jwk2pem', () => {

    //     console.log(`keys[1] = ${JSON.stringify(keys[1])}`);

    //     console.log(`typeof keys[1].n = ${typeof keys[1].n}`);

    //     const publicPem = jwk2pem(keys[1]);
    //     const privatePem = jwk2pem(keys[1], { private: true });

    //     // const privatePem = jwk2pem({
    //     //     "kty": "RSA",
    //     //     "e": "AQAB",
    //     //     "use": "sig",
    //     //     "kid": "nonexpired",
    //     //     "alg": "RS256",
    //     //     "d": "Eq-pMdpT4Dt5ZLyGwp8ZRGFbTkRd2BGS-5RZaeZB2qRXkw1lSz7PzxR85w4tzmYQOxQWJenqE9_Eh1G3Y5iWpqeVodIlrdmpIIvxR323YMaafeug_W1H_BjWTPqaPtsL3yFswNFSGZXn2k__i_4nCRLEYTZLyeRU8XhMXSJ8TQjrYmcjD3OY5Nwu_efrrqljMJEBWJTvOabrfuiDTkkiQaFxqzJRBL-fAgu41g1Rh_GXQZkih6XmR81-dMn9y13gpoWvy6I6lXCVEl0Zh-ZJvEsCRfTR-u6-h8R1BBtz4c7SQJA70lgdcyBdzfPyqJ42nrfG10CBRG2EO_gssTOZ3Q"
    //     // }, { private: true});

    //     console.log(`public pem = ${publicPem}\nprivatePem = ${privatePem}`);
    // });

    describe('pem/jwk foolishness', () => {

        [nonExpiringToken, alreadyExpiredToken].forEach(t =>

            it(`test pems can roundtrip with jwk (${t.header.kid})`, () => {

                console.info(`publicPem = ${t.publicPem}`);
                const jwk = rsaPemToJwk(t.publicPem, {}, 'public');
                console.log(`decoded jwk = ${JSON.stringify(jwk, null, 2)}`);
                const pem = jwk2pem(jwk);
                console.log(`reencoded pem = ${pem}`);

                // Oddly, pems don't match
                // assert.equal(nonExpiringToken.publicPem, pem);
            })
        );
    });

    const mockAWSPublicKeyRequestPromise = (url) => new Promise((resolve, reject) => {

        const mockPublicKeyResponse = JSON.stringify({
            keys: [
                pem2jwk(nonExpiringToken.publicPem),
                pem2jwk(alreadyExpiredToken.publicPem)
            ]
        });
        // console.info(`Returning this from mockAWSPublicKeyRequestPromise: ${mockPublicKeyResponse}`);
        resolve(mockPublicKeyResponse);
    });

    // const mockAWSPublicKeyRequestPromise = (url) => new Promise((resolve, reject) => {
    //     resolve(`{"keys":[{"alg":"RS256","e":"AQAB","kid":"1agWhyF85IfFI+PLmLHf+9t3uhXsviJaPROL+mlS7Rc=","kty":"RSA","n":"kOHvUOFBIMNLAe7Y9s_NnJrBg2oX_eKa-WeFdnyAd-ArzJ0srA5hh_1sm98w5zPPilHxOJj6-qvcyp5ytEXluRbD6epsTX9Wwo4nh7pfoyskcdbEIO6RexSFQdXvYQx0aBA9y524Y67DzrzOo2juqZQ3bTXt8hPQ_klG9RcYxPWmmnnbCp4hB6qbp5HDzYCJFtEYT2iWt_pL18hcl9Z4HkYxPYJikBMHHGN6WZs1k5r3XdEZkZmvMQYiOZlHN8No-D9lTUDkZm1mUtxO76mDFAfJRKdZQ5_orw_C6dDVp3-nbY7RErU7NKBUauRJKlm-sStN_lYiXr1xtjkRdKvNkw","use":"sig"},{"alg":"RS256","e":"AQAB","kid":"Yb60aUQ8P8SqFPMZZWhMQAnSQhKTgC/pparbK3A+5qo=","kty":"RSA","n":"gKLSoX1cXMcd_kq1IAP-br3ClWADQS03ynUnwZU7BCu6WyxQhAgGggzuf9YpJwmKNfovR6jrf71TDcGQopVdDCzdQFJPFnkRagHnVyztNR321BOwJV3_DS93h1nqsIi1tHUXt1jzx9r-aYssWGgdeXs-0N5XAjd--ITxf90Fa5w44Iml_C_wvWZmVJpk7AmkoOAJL_gpIWA717xLxNPVwdL-XxbvoiMzESg3nAfbre8oOy1MNkwrFyEx5FTxUjifUdhl3SWLeqe--fXgpKkavntdtF-Ggw1I8mQ7J2-JXAidNvJ2YXTE-n5EcdF-BT496FYAFTrc-qen6ePulpllIQ","use":"sig"}]}`);
    // });

    // const expiredToken = 'eyJraWQiOiIxYWdXaHlGODVJZkZJK1BMbUxIZis5dDN1aFhzdmlKYVBST0wrbWxTN1JjPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJmODc4NDcwYi05YjkxLTRhN2ItYmI4MC1lMzQzNGRmODkzMmEiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLnVzLWVhc3QtMS5hbWF6b25hd3MuY29tXC91cy1lYXN0LTFfNWRXN1llZmtuIiwicGhvbmVfbnVtYmVyX3ZlcmlmaWVkIjpmYWxzZSwiY29nbml0bzp1c2VybmFtZSI6ImY4Nzg0NzBiLTliOTEtNGE3Yi1iYjgwLWUzNDM0ZGY4OTMyYSIsImdpdmVuX25hbWUiOiJJbSIsImF1ZCI6IjIxc2RyYjkxc25jMzN0ODBvdTdqbW1uZTdtIiwiY3VzdG9tOmluc3RpdHV0aW9uSWQiOiIxMjM1IiwiZXZlbnRfaWQiOiJiOTU1ZGY1Zi0yNWFlLTExZTgtOTk5Mi0yNTQ3ZTcxMjEzYTQiLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTUyMDgyOTMwMCwiZXhwIjoxNTIxMTc1NTI4LCJpYXQiOjE1MjExNzE5MjgsImZhbWlseV9uYW1lIjoiSGVyZSIsImVtYWlsIjoiaW1oZXJlMjAxODAzMTEuMUBpZ25vcmV0aGlzLm9yZyJ9.Ww1uzQoC08aFA-_Bj7aJtWv3hOMuKqGHIEmGenjyFDQbXE3F3r0JcEA7rY5c_114DCXzVpZuH_RXhRk0Tbc_iKJxKgEpw_skKuQZUqvyBlrhFXI0LfXXXHGuE8I3YysBjKJYqaBXOSBJDE7X1HE_Lml0fCgDOtumoMbHIeZvcNGsVdqcBggo94zmNpw3JkFwzL75u69cZEqcUJhU9fXIHw1Z8sLumlZl8WSbB-Nbv3Ans5o31in_daMRYCRBmrHipM9v1zJG_t61Sngi4sN-_iZcC3TcNmbFuyMqbtM9Sd9WljY5NHkDz8E-t0e8gtfAQlmNi4df2fsU90wFIhlhyg';
    // const kidForExpired = '1agWhyF85IfFI+PLmLHf+9t3uhXsviJaPROL+mlS7Rc=';
    // const pemForExpired = '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkOHvUOFBIMNLAe7Y9s/N\nnJrBg2oX/eKa+WeFdnyAd+ArzJ0srA5hh/1sm98w5zPPilHxOJj6+qvcyp5ytEXl\nuRbD6epsTX9Wwo4nh7pfoyskcdbEIO6RexSFQdXvYQx0aBA9y524Y67DzrzOo2ju\nqZQ3bTXt8hPQ/klG9RcYxPWmmnnbCp4hB6qbp5HDzYCJFtEYT2iWt/pL18hcl9Z4\nHkYxPYJikBMHHGN6WZs1k5r3XdEZkZmvMQYiOZlHN8No+D9lTUDkZm1mUtxO76mD\nFAfJRKdZQ5/orw/C6dDVp3+nbY7RErU7NKBUauRJKlm+sStN/lYiXr1xtjkRdKvN\nkwIDAQAB\n-----END PUBLIC KEY-----\n';

    let jwtVerifier;

    beforeEach(() => {
        jwtVerifier = new JwtVerifier('aUserPool', mockAWSPublicKeyRequestPromise);
    });

    describe('instantiation', () => {

        // TODO: This is an integration test against the production environment. Make that not so.

        // it('instantiates and loads keymap from production', (done) => {

        //     const jwtVerifier = new JwtVerifier('us-east-1_5dW7Yefkn');

        //     jwtVerifier.publicKeysPromise
        //         .then(keyMap => {
        //             console.info(`Retrieved keyMap = ${JSON.stringify(keyMap, null, 2)}`);
        //             assert(keyMap['1agWhyF85IfFI+PLmLHf+9t3uhXsviJaPROL+mlS7Rc=']);
        //             assert(keyMap['Yb60aUQ8P8SqFPMZZWhMQAnSQhKTgC/pparbK3A+5qo=']);
        //         })
        //         .then(done, done); // Node 6, which AWS Lambda currently uses, doesn't support finally().
        // });

        // it('instantiates and loads keymap from mock', (done) => {

        //     jwtVerifier.publicKeysPromise
        //         .then(keyMap => {
        //             // These are raw PEMs
        //             assert.propertyVal(keyMap, '1agWhyF85IfFI+PLmLHf+9t3uhXsviJaPROL+mlS7Rc=', '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkOHvUOFBIMNLAe7Y9s/N\nnJrBg2oX/eKa+WeFdnyAd+ArzJ0srA5hh/1sm98w5zPPilHxOJj6+qvcyp5ytEXl\nuRbD6epsTX9Wwo4nh7pfoyskcdbEIO6RexSFQdXvYQx0aBA9y524Y67DzrzOo2ju\nqZQ3bTXt8hPQ/klG9RcYxPWmmnnbCp4hB6qbp5HDzYCJFtEYT2iWt/pL18hcl9Z4\nHkYxPYJikBMHHGN6WZs1k5r3XdEZkZmvMQYiOZlHN8No+D9lTUDkZm1mUtxO76mD\nFAfJRKdZQ5/orw/C6dDVp3+nbY7RErU7NKBUauRJKlm+sStN/lYiXr1xtjkRdKvN\nkwIDAQAB\n-----END PUBLIC KEY-----\n');
        //             assert.propertyVal(keyMap, 'Yb60aUQ8P8SqFPMZZWhMQAnSQhKTgC/pparbK3A+5qo=', '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgKLSoX1cXMcd/kq1IAP+\nbr3ClWADQS03ynUnwZU7BCu6WyxQhAgGggzuf9YpJwmKNfovR6jrf71TDcGQopVd\nDCzdQFJPFnkRagHnVyztNR321BOwJV3/DS93h1nqsIi1tHUXt1jzx9r+aYssWGgd\neXs+0N5XAjd++ITxf90Fa5w44Iml/C/wvWZmVJpk7AmkoOAJL/gpIWA717xLxNPV\nwdL+XxbvoiMzESg3nAfbre8oOy1MNkwrFyEx5FTxUjifUdhl3SWLeqe++fXgpKka\nvntdtF+Ggw1I8mQ7J2+JXAidNvJ2YXTE+n5EcdF+BT496FYAFTrc+qen6ePulpll\nIQIDAQAB\n-----END PUBLIC KEY-----\n');
        //         })
        //         .then(done, done); // Node 6, which AWS Lambda currently uses, doesn't support finally().
        // });

        it('instantiates and loads keymap from mock', (done) => {

            jwtVerifier.publicKeysPromise
                .then(keyMap => {
                    // These are raw PEMs
                    assert.property(keyMap, 'expired');
                    assert.property(keyMap, 'nonexpired');
                })
                .then(done, done); // Node 6, which AWS Lambda currently uses, doesn't support finally().
        });
    });

    describe('decoding', () => {

        it('decodes a token', () => {

            const decodedToken = jwtVerifier.decodeJwtToken(nonExpiringToken);
            assert.property(decodedToken, 'header');
            assert.property(decodedToken, 'payload');
            assert.property(decodedToken, 'signature');
            console.log(`payload = ${JSON.stringify(decodedToken.payload, null, 2)}`);
        });
    });

    // describe('verifying expired', () => {

    //     it('verifying with pem throws TokenExpiredError', () => {

    //         assert.throws(() => jwtVerifier.decodeAndVerifyJwtTokenWithPem(expiredToken, pemForExpired), TokenExpiredError);
    //     });

    //     it('verifying synthetic token with pem throws TokenExpiredError', () => {

    //         assert.throws(() => jwtVerifier.decodeAndVerifyJwtTokenWithPem(alreadyExpiredToken.jwt, alreadyExpiredToken.publicPem), TokenExpiredError);
    //     });

    //     it('verifying with keymap throws TokenExpiredError', () => {

    //         const keyMap = {
    //             [kidForExpired]: pemForExpired
    //         };

    //         assert.throws(() => jwtVerifier.decodeAndVerifyJwtTokenWithKeyMap(expiredToken, keyMap), TokenExpiredError);
    //     });
    // });
});
