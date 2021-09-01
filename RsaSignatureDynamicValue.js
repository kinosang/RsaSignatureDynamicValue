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

            if (this.algorithm.endsWith('ECDSA')) {
                try {
                  sig.init({ d: this.key, curve: this.curve });
                } catch (ex) {
                  throw "Please make sure you selected the right Algorithm. "+ex;
                }
            } else {
                if (!this.key.startsWith('-----BEGIN RSA PRIVATE KEY-----')) {
                    this.key = '-----BEGIN RSA PRIVATE KEY-----' + this.key;
                }
                if (!this.key.endsWith('-----END RSA PRIVATE KEY-----')) {
                    this.key = this.key + '-----END RSA PRIVATE KEY-----';
                }
                try {
                  sig.init(this.key);
                } catch (ex) {
                  throw "Please make sure you selected the right Algorithm. "+ex;
                }
            }

            sig.updateString(this.message);
            const signature = sig.sign();
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

RsaSignatureDynamicValue.identifier = 'net.tripletwenty.PawExtensions.RsaSignatureDynamicValue';
RsaSignatureDynamicValue.title = 'RSA-Signature';
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
    InputField('encoding', 'Encoding', 'Select', {
        choices: {
            hex: 'HEX',
            base64: 'BASE64',
        },
        defaultValue: 'hex',
    }),
];

registerDynamicValueClass(RsaSignatureDynamicValue);
