/* global InputField registerDynamicValueClass */

const r = require('./jsrsasign.js');

const has = Object.prototype.hasOwnProperty;

const algorithms = {
    MD5withRSA: 'RSA MD5',
    SHA1withRSA: 'RSA SHA1',
    SHA224withRSA: 'RSA SHA224',
    SHA256withRSA: 'RSA SHA256',
    SHA384withRSA: 'RSA SHA384',
    SHA512withRSA: 'RSA SHA512',
    RIPEMD160withRSA: 'RSA RIPEMD160',
    MD5withECDSA: 'ECDSA MD5',
    SHA1withECDSA: 'ECDSA SHA1',
    SHA224withECDSA: 'ECDSA SHA224',
    SHA256withECDSA: 'ECDSA SHA256',
    SHA384withECDSA: 'ECDSA SHA384',
    SHA512withECDSA: 'ECDSA SHA512',
    RIPEMD160withECDSA: 'ECDSA RIPEMD160',
};

class RsaSignatureDynamicValue {
    constructor() {
        const filter = body => {
            const res = body;

            Object.values(this.filters).forEach(f => {
                if (f[2] === true) {
                    delete res[f[0]];
                }
            });

            return res;
        };

        const queryStringify = (obj, prefix) => {
            const pairs = [];

            Object.keys(obj).forEach(key => {
                if (!has.call(obj, key)) {
                    return;
                }

                const value = obj[key];
                const enkey = encodeURIComponent(key);
                let pair;
                if (typeof value === 'object') {
                    pair = queryStringify(value, prefix ? `${prefix}[${enkey}]` : enkey);
                } else {
                    pair = `${prefix ? `${prefix}[${enkey}]` : enkey}=${encodeURIComponent(value)}`;
                }
                pairs.push(pair);
            });

            if (this.sort) {
                pairs.sort();
            }

            return pairs.join('&');
        };

        this.evaluate = context => {
            const request = context.getCurrentRequest();

            switch (this.source) {
                case 'body':
                    if (request.jsonBody) {
                        const body = request.jsonBody;
                        this.message = JSON.stringify(filter(body));
                    } else if (request.urlEncodedBody) {
                        const body = request.urlEncodedBody;
                        this.message = queryStringify(filter(body));
                    } else if (request.multipartBody) {
                        const body = request.multipartBody;
                        this.message = queryStringify(filter(body));
                    }
                    break;
                default:
                    break;
            }

            const sig = new r.Signature({ alg: this.algorithm });
            const privateKey = (this.keyEncoding === 'hex')? this.key : r.b64tohex(this.key);

            if (this.algorithm.endsWith('ECDSA')) {
                try {
                  if(this.keyFormat == 'pkcs8') {
                    let pkcs8PrivateKey = r.KEYUTIL.getKeyFromPlainPrivatePKCS8Hex(privateKey)
                    sig.init(pkcs8PrivateKey);
                  } else {
                    sig.init({ d: privateKey, curve: this.curve });
                  }
                } catch (ex) {
                  throw "Please make sure you selected the right algorithm. "+ex;
                }
            } else {
                if (!privateKey.startsWith('-----BEGIN RSA PRIVATE KEY-----')) {
                    privateKey = '-----BEGIN RSA PRIVATE KEY-----' + privateKey;
                }
                if (!privateKey.endsWith('-----END RSA PRIVATE KEY-----')) {
                    privateKey = privateKey + '-----END RSA PRIVATE KEY-----';
                }
                try {
                  sig.init(privateKey);
                } catch (ex) {
                  throw "Please make sure you selected the right algorithm. "+ex;
                }
            }

            sig.updateString(this.message);
            const signature = sig.sign();

            // If public key is given, run validation to see if the keys match
            if(this.publickey) {
              const publicKeyUncompressed = (this.keyEncoding === 'hex')? this.publickey : r.b64tohex(this.publickey);
              let publicKey = new r.KJUR.crypto.ECDSA({pub: publicKeyUncompressed, curve: this.curve})
              console.log("RsaSignature | Verifying key pair for message: '"+this.message+"'");
              let sigVerification = new r.Signature({ alg: this.algorithm });
              sigVerification.init(publicKey);
              sigVerification.updateString(this.message);
              let isValid = sigVerification.verify(signature);
              if(isValid) {
                console.log("RsaSignature | Signature is valid, keys are matching");
              } else {
                throw "The signature is invalid. Please make sure the keys match."
              }

            }

            if (this.encoding === 'hex') {
                return signature;
            }

            return r.hextob64(signature);
        };
        this.title = () => 'Signature';
        this.text = () => algorithms[this.algorithm];
        return this;
    }
}

RsaSignatureDynamicValue.identifier = 'me.7in0.PawExtensions.RsaSignatureDynamicValue';
RsaSignatureDynamicValue.title = 'RSA Signature';
RsaSignatureDynamicValue.inputs = [
    InputField('source', 'Source', 'Select', {
        choices: {
            body: 'Request Body',
            message: 'Message',
        },
        defaultValue: 'body',
    }),
    InputField('filters', 'Body Filters', 'KeyValueList', {
        keyName: 'Parameter Key',
        valueName: '(Check to ignore)',
    }),
    InputField('sort', 'Body Re-Sorting', 'Checkbox', { defaultValue: true }),
    InputField('message', 'Message', 'String'),
    InputField('key', 'Private Key', 'String'),
    InputField('publickey', 'Public Key', 'String'),
    InputField('algorithm', 'Algorithm', 'Select', {
        choices: algorithms,
        defaultValue: 'SHA256withRSA',
    }),
    InputField('curve', 'Curve', 'Select', {
        choices: {
            secp256r1: 'secp256r1 (= NIST P-256, P-256, prime256v1)',
            secp256k1: 'secp256k1',
            secp384r1: 'secp384r1 (= NIST P-384, P-384)',
        },
    }),
    InputField('keyEncoding', 'Key Encoding', 'Select', {
        choices: {
            hex: 'HEX',
            base64: 'BASE64',
        },
        defaultValue: 'base64',
    }),
    InputField('keyFormat', 'Key Format', 'Select', {
        choices: {
            pkcs8: 'PKCS8',
            other: 'Other',
        },
        defaultValue: 'other',
    }),
    InputField('encoding', 'Signature Encoding', 'Select', {
        choices: {
            hex: 'HEX',
            base64: 'BASE64',
        },
        defaultValue: 'hex',
    }),
];

registerDynamicValueClass(RsaSignatureDynamicValue);
