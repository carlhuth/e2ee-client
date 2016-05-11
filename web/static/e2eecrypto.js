/* Crypton Client, Copyright 2013 SpiderOak, Inc.
 *
 * This file is part of Crypton Client.
 *
 * Crypton Client is free software: you can redistribute it and/or modify it
 * under the terms of the Affero GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Crypton Client is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the Affero GNU General Public
 * License for more details.
 *
 * You should have received a copy of the Affero GNU General Public License
 * along with Crypton Client.  If not, see <http://www.gnu.org/licenses/>.
 */
var crypton = {};

(function() {

    'use strict';

    var MISMATCH_ERR = 'Server and client version mismatch';

    /**!
     * ### version
     * Holds framework version for potential future backward compatibility.
     * '0.0.4' string is replaced with the version from package.json
     * at build time
     */
    crypton.version = '0.0.4';

    /**!
     * ### MIN_PBKDF2_ROUNDS
     * Minimum number of PBKDF2 rounds
     */
    crypton.MIN_PBKDF2_ROUNDS = 1000;

    /**!
     * ### clientVersionMismatch
     * Holds cleint <-> server version mismatch status
     */
    crypton.clientVersionMismatch = undefined;

    crypton.bearer = function(request) {
        request.set('Authorization', 'Bearer ' + crypton.token);
    };

    crypton.openSession = function(username, passphrase) {
        var url = crypton.url() + '/accountexists';
        superagent.get(url)
            .use(crypton.bearer)
            .end(function(err, res) {
            	if (err != null) {
		        	$('.notification').html('cannot connect to server <br>(the reason might be a self signed certificate, in this case you can open E2EE server address in a browser and resolve a privacy error)')
            	}
                if (res.body.exists) {
                    crypton.authorize(username, passphrase, function(err, session) {
                        if (err) {
                            if (window.console && window.console.log) {
                                console.info(err)
                            }
                        } else {
                            e2ee.UI.open(username, session)
                        }
                    })
                } else {
                    crypton.generateAccount(username, passphrase, function done(err, account) {
                        if (err) {
                            if (window.console && window.console.log) {
                                console.info(err)
                            }
                        } else {
                            if (window.console && window.console.log) {
                                console.info('account created')
                            }
                            crypton.authorize(username, passphrase, function(err, session) {
                                if (err) {
                                    if (window.console && window.console.log) {
                                        console.info(err)
                                    }
                                } else {
                                    e2ee.UI.open(username, session)
                                }
                            })
                        }
                    })
                }
            });
    };

    crypton.versionCheck = function(skip, callback) {
        if (skip) {
            return callback(null);
        }

        var url = crypton.url() + '/versioncheck?' + 'v=' + crypton.version;
        superagent.get(url)
            .use(crypton.bearer)
            .end(function(err, res) {

                if (res.body.success !== true && res.body.error !== undefined) {
                    crypton.clientVersionMismatch = true;
                    return callback(res.body.error);
                }
                callback(null);
            });
    };

    /**!
     * ### host
     * Holds location of Crypton server
     */
    crypton.host = "127.0.0.1";

    /**!
     * ### port
     * Holds port of Crypton server
     */
    crypton.port = 8080;

    /**!
     * ### cipherOptions
     * Sets AES mode to CCM to enable fast (based on ArrayBuffers) encryption/decryption
     */
    crypton.cipherOptions = {
        mode: 'ccm'
    };

    /**!
     * ### paranoia
     * Tells SJCL how strict to be about PRNG readiness
     */
    crypton.paranoia = 6;

    /**!
     * ### trustedPeers
     * Internal name for trusted peer (contacts list)
     */
    crypton.trustedPeers = '_trusted_peers';

    /**!
     * ### collectorsStarted
     * Internal flag to know if startCollectors has been called
     */
    crypton.collectorsStarted = false;

    /**!
     * ### startCollectors
     * Start sjcl.random listeners for adding to entropy pool
     */
    crypton.startCollectors = function() {
        sjcl.random.startCollectors();
        crypton.collectorsStarted = true;
    };

    /**!
     * ### url()
     * Generate URLs for server calls
     *
     * @return {String} url
     */
    crypton.url = function() {
        //return 'https://' + crypton.host + ':' + crypton.port;
        //testing:
        //return 'http://localhost:8080';
        return document.getElementById("e2eeServerUrl").value
    };

    /**!
     * ### randomBytes(nbytes)
     * Generate `nbytes` bytes of random data
     *
     * @param {Number} nbytes
     * @return {Array} bitArray
     */
    function randomBytes(nbytes) {
        if (!nbytes) {
            throw new Error('randomBytes requires input');
        }

        if (parseInt(nbytes, 10) !== nbytes) {
            throw new Error('randomBytes requires integer input');
        }

        if (nbytes < 4) {
            throw new Error('randomBytes cannot return less than 4 bytes');
        }

        if (nbytes % 4 !== 0) {
            throw new Error('randomBytes requires input as multiple of 4');
        }

        // sjcl's words are 4 bytes (32 bits)
        var nwords = nbytes / 4;
        return sjcl.random.randomWords(nwords);
    }
    crypton.randomBytes = randomBytes;

    /**!
     * ### constEqual()
     * Compare two strings in constant time.
     *
     * @param {String} str1
     * @param {String} str2
     * @return {bool} equal
     */
    function constEqual(str1, str2) {
        // We only support string comparison, we could support Arrays but
        // they would need to be single char elements or compare multichar
        // elements constantly. Going for simplicity for now.
        // TODO: Consider this ^
        if (typeof str1 !== 'string' || typeof str2 !== 'string') {
            return false;
        }

        var mismatch = str1.length ^ str2.length;
        var len = Math.min(str1.length, str2.length);

        for (var i = 0; i < len; i++) {
            mismatch |= str1.charCodeAt(i) ^ str2.charCodeAt(i);
        }

        return mismatch === 0;
    }
    crypton.constEqual = constEqual;

    crypton.sessionId = null;

    /**!
     * ### randomBits(nbits)
     * Generate `nbits` bits of random data
     *
     * @param {Number} nbits
     * @return {Array} bitArray
     */
    crypton.randomBits = function(nbits) {
        if (!nbits) {
            throw new Error('randomBits requires input');
        }

        if (parseInt(nbits, 10) !== nbits) {
            throw new Error('randomBits requires integer input');
        }

        if (nbits < 32) {
            throw new Error('randomBits cannot return less than 32 bits');
        }

        if (nbits % 32 !== 0) {
            throw new Error('randomBits requires input as multiple of 32');
        }

        var nbytes = nbits / 8;
        return crypton.randomBytes(nbytes);
    };

    /**!
     * ### mac(key, data)
     * Generate an HMAC using `key` for `data`.
     *
     * @param {String} key
     * @param {String} data
     * @return {String} hmacHex
     */
    crypton.hmac = function(key, data) {
        var mac = new sjcl.misc.hmac(key);
        return sjcl.codec.hex.fromBits(mac.mac(data));
    }

    /**!
     * ### macAndCompare(key, data, otherMac)
     * Generate an HMAC using `key` for `data` and compare it in
     * constant time to `otherMac`.
     *
     * @param {String} key
     * @param {String} data
     * @param {String} otherMac
     * @return {Bool} compare succeeded
     */
    crypton.hmacAndCompare = function(key, data, otherMac) {
        var ourMac = crypton.hmac(key, data);
        return crypton.constEqual(ourMac, otherMac);
    };

    /**!
     * ### fingerprint(pubKey, signKeyPub)
     * Generate a fingerprint for an account or peer.
     *
     * @param {PublicKey} pubKey
     * @param {PublicKey} signKeyPub
     * @return {String} hash
     */
    // TODO check inputs
    crypton.fingerprint = function(pubKey, signKeyPub) {
        var pubKeys = sjcl.bitArray.concat(
            pubKey._point.toBits(),
            signKeyPub._point.toBits()
        );

        return crypton.hmac('', pubKeys);
    };

    /**!
     * ### generateAccount(username, passphrase, callback, options)
     * Generate salts and keys necessary for an account
     *
     * Saves account to server unless `options.save` is falsey
     *
     * Calls back with account and without error if successful
     *
     * Calls back with error if unsuccessful
     *
     * @param {String} username
     * @param {String} passphrase
     * @param {Function} callback
     * @param {Object} options
     */

    // TODO consider moving non-callback arguments to single object
    crypton.generateAccount = function(username, passphrase, callback, options) {
        if (crypton.clientVersionMismatch) {
            return callback(MISMATCH_ERR);
        }

        options = options || {};
        var save = typeof options.save !== 'undefined' ? options.save : true;

        crypton.versionCheck(!save, function(err) {
            if (err) {
                return callback(MISMATCH_ERR);
            } else {

                if (!passphrase) {
                    return callback('Must supply passphrase');
                }

                if (!crypton.collectorsStarted) {
                    crypton.startCollectors();
                }

                var SIGN_KEY_BIT_LENGTH = 384;
                var keypairCurve = options.keypairCurve || 384;
                var numRounds = crypton.MIN_PBKDF2_ROUNDS;

                var account = new crypton.Account();
                var hmacKey = randomBytes(32);
                var keypairSalt = randomBytes(32);
                var keypairMacSalt = randomBytes(32);
                var signKeyPrivateMacSalt = randomBytes(32);
                var containerNameHmacKey = randomBytes(32);
                var keypairKey = sjcl.misc.pbkdf2(passphrase, keypairSalt, numRounds);
                var keypairMacKey = sjcl.misc.pbkdf2(passphrase, keypairMacSalt, numRounds);
                var signKeyPrivateMacKey = sjcl.misc.pbkdf2(passphrase, signKeyPrivateMacSalt, numRounds);
                var keypair = sjcl.ecc.elGamal.generateKeys(keypairCurve, crypton.paranoia);
                var signingKeys = sjcl.ecc.ecdsa.generateKeys(SIGN_KEY_BIT_LENGTH, crypton.paranoia);

                account.username = username;
                account.keypairSalt = JSON.stringify(keypairSalt);
                account.keypairMacSalt = JSON.stringify(keypairMacSalt);
                account.signKeyPrivateMacSalt = JSON.stringify(signKeyPrivateMacSalt);

                // pubkeys
                account.pubKey = JSON.stringify(keypair.pub.serialize());
                account.signKeyPub = JSON.stringify(signingKeys.pub.serialize());

                var sessionIdentifier = 'dummySession';
                var session = new crypton.Session(sessionIdentifier);
                session.account = account;
                session.account.signKeyPrivate = signingKeys.sec;

                var selfPeer = new crypton.Peer({
                    session: session,
                    pubKey: keypair.pub,
                    signKeyPub: signingKeys.pub
                });
                selfPeer.trusted = true;

                // hmac keys
                var encryptedHmacKey = selfPeer.encryptAndSign(JSON.stringify(hmacKey));
                if (encryptedHmacKey.error) {
                    callback(encryptedHmacKey.error, null);
                    return;
                }

                account.hmacKeyCiphertext = JSON.stringify(encryptedHmacKey);

                var encryptedContainerNameHmacKey = selfPeer.encryptAndSign(JSON.stringify(containerNameHmacKey));
                if (encryptedContainerNameHmacKey.error) {
                    callback(encryptedContainerNameHmacKey.error, null);
                    return;
                }

                account.containerNameHmacKeyCiphertext = JSON.stringify(encryptedContainerNameHmacKey);

                // private keys
                // TODO: Check data auth with hmac
                var keypairCiphertext = sjcl.encrypt(keypairKey, JSON.stringify(keypair.sec.serialize()), crypton.cipherOptions);

                account.keypairCiphertext = keypairCiphertext;
                account.keypairMac = crypton.hmac(keypairMacKey, account.keypairCiphertext);
                account.signKeyPrivateCiphertext = sjcl.encrypt(keypairKey, JSON.stringify(signingKeys.sec.serialize()), crypton.cipherOptions);
                account.signKeyPrivateMac = crypton.hmac(signKeyPrivateMacKey, account.signKeyPrivateCiphertext);

                if (save) {
                    account.save(function(err) {
                        callback(err, account);
                    });
                    return;
                }

                callback(null, account);
            }
        });
    };

    /**!
     * ### authorize(username, passphrase, callback)
     * Perform zero-knowledge authorization with given `username`
     * and `passphrase`, generating a session if successful
     *
     * Calls back with session and without error if successful
     *
     * Calls back with error if unsuccessful
     *
     * @param {String} username
     * @param {String} passphrase
     * @param {Function} callback
     * @param {Object} options
     */
    crypton.authorize = function(username, passphrase, callback, options) {
        if (crypton.clientVersionMismatch) {
            return callback(MISMATCH_ERR);
        }

        options = options || {};
        var check = typeof options.check !== 'undefined' ? options.check : true;

        crypton.versionCheck(!check, function(err) {
            if (err) {
                return callback(MISMATCH_ERR);
            } else {

                if (!passphrase) {
                    return callback('Must supply passphrase');
                }

                if (!crypton.collectorsStarted) {
                    crypton.startCollectors();
                }

                var options = {
                    //username: username,
                    passphrase: passphrase
                };

                superagent.get(crypton.url() + '/account')
                    //.withCredentials()
                    //.send(response)
                    .use(crypton.bearer)
                    .end(function(err, res) {
                        if (!res.body || res.body.success !== true) {
                            return callback(res.body.error);
                        }

                        var session = new crypton.Session(crypton.sessionId);
                        session.account = new crypton.Account();
                        session.account.username = username;
                        session.account.passphrase = passphrase;
                        session.account.containerNameHmacKeyCiphertext = JSON.parse(res.body.account.containerNameHmacKeyCiphertext);
                        session.account.hmacKeyCiphertext = JSON.parse(res.body.account.hmacKeyCiphertext);
                        session.account.keypairCiphertext = res.body.account.keypairCiphertext;
                        session.account.keypairMac = res.body.account.keypairMac;
                        session.account.pubKey = JSON.parse(res.body.account.pubKey);
                        session.account.keypairSalt = JSON.parse(res.body.account.keypairSalt);
                        session.account.keypairMacSalt = JSON.parse(res.body.account.keypairMacSalt);
                        session.account.signKeyPub = sjcl.ecc.deserialize(JSON.parse(res.body.account.signKeyPub));
                        session.account.signKeyPrivateCiphertext = res.body.account.signKeyPrivateCiphertext;
                        session.account.signKeyPrivateMacSalt = JSON.parse(res.body.account.signKeyPrivateMacSalt);
                        session.account.signKeyPrivateMac = res.body.account.signKeyPrivateMac;
                        session.account.unravel(function(err) {
                            if (err) {
                                return callback(err);
                            }

                            session.load(crypton.trustedPeers, function(err, container) {
                                console.info('loading trusted peers')
                                if (err) {
                                    if (window.console && window.console.log) {
                                        console.info(err)
                                        console.info('trustedPeers container does not exist - this is expected when user logins for the first time')
                                    }

                                    session.create(crypton.trustedPeers, function(err, peersContainer) {
                                        e2ee.session.peersContainer = peersContainer
                                        peersContainer.add('peers', function() {
                                            peersContainer.save(function(err) {
                                                if (err) {
                                                    if (window.console && window.console.log) {
                                                        console.error('peers container could not be saved')
                                                    }
                                                } else {
                                                    callback(null, session);
                                                }
                                            })
                                        })
                                    })
                                } else {
                                    e2ee.session.peersContainer = container
                                    callback(null, session);
                                }
                            })
                        });
                    });
            }
        });
    };
})();
/* Crypton Client, Copyright 2013 SpiderOak, Inc.
 *
 * This file is part of Crypton Client.
 *
 * Crypton Client is free software: you can redistribute it and/or modify it
 * under the terms of the Affero GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Crypton Client is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the Affero GNU General Public
 * License for more details.
 *
 * You should have received a copy of the Affero GNU General Public License
 * along with Crypton Client.  If not, see <http://www.gnu.org/licenses/>.
 */

(function() {

    'use strict';

    /**!
     * # Account()
     *
     * ````
     * var account = new crypton.Account();
     * ````
     */
    var Account = crypton.Account = function Account() {};

    /**!
     * ### save(callback)
     * Send the current account to the server to be saved
     *
     * Calls back without error if successful
     *
     * Calls back with error if unsuccessful
     *
     * @param {Function} callback
     */
    Account.prototype.save = function(callback) {
        superagent.post(crypton.url() + '/account')
            //.withCredentials()
            .use(crypton.bearer)
            .send(this.serialize())
            //.send({"name":"New Account"})
            .end(function(err, res) {
                if (res.body.success !== true) {
                    callback(res.body.error);
                } else {
                    callback();
                }
            });
    };

    /**!
     * ### unravel(callback)
     * Decrypt raw account object from server after successful authentication
     *
     * Calls back without error if successful
     *
     * __Throws__ if unsuccessful
     *
     * @param {Function} callback
     */
    Account.prototype.unravel = function(callback) {
        var that = this;
        crypton.work.unravelAccount(this, function(err, data) {
            if (err) {
                return callback(err);
            }

            that.regenerateKeys(data, function(err) {
                callback(err);
            });
        });
    };

    /**!
     * ### regenerateKeys(callback)
     * Reconstruct keys from unraveled data
     *
     * Calls back without error if successful
     *
     * __Throws__ if unsuccessful
     *
     * @param {Function} callback
     */
    Account.prototype.regenerateKeys = function(data, callback) {
        // reconstruct secret key
        this.secretKey = sjcl.ecc.deserialize(data.secret);

        // reconstruct public key
        this.pubKey = sjcl.ecc.deserialize(this.pubKey);

        // assign the hmac keys to the account
        this.hmacKey = data.hmacKey;
        this.containerNameHmacKey = data.containerNameHmacKey;

        // reconstruct the public signing key - already reconstructed in authorize

        // reconstruct the secret signing key
        this.signKeyPrivate = sjcl.ecc.deserialize(data.signKeySecret);

        // calculate fingerprint for public key
        this.fingerprint = crypton.fingerprint(this.pubKey, this.signKeyPub);

        // recalculate the public points from secret exponents
        // and verify that they match what the server sent us
        var cP = this.secretKey._curve.G.mult(this.secretKey._exponent); // calculated point 
        var dP = this.pubKey.get(); // deserialized point

        if (!sjcl.bitArray.equal(cP.x.toBits(), dP.x) || !sjcl.bitArray.equal(cP.y.toBits(), dP.y)) {
            return callback('Server provided incorrect public key');
        }

        cP = this.signKeyPrivate._curve.G.mult(this.signKeyPrivate._exponent);
        dP = this.signKeyPub.get();
        if (!sjcl.bitArray.equal(cP.x.toBits(), dP.x) || !sjcl.bitArray.equal(cP.y.toBits(), dP.y)) {
            return callback('Server provided incorrect public signing key');
        }

        // sometimes the account object is used as a peer
        // to make the code simpler. verifyAndDecrypt checks
        // that the peer it is passed is trusted, or returns
        // an error. if we've gotten this far, we can be sure
        // that the public keys are trustable.
        this.trusted = true;

        callback(null);
    };

    /**!
     * ### serialize()
     * Package and return a JSON representation of the current account
     *
     * @return {Object}
     */
    // TODO rename to toJSON
    Account.prototype.serialize = function() {
        return {
            containerNameHmacKeyCiphertext: this.containerNameHmacKeyCiphertext,
            hmacKeyCiphertext: this.hmacKeyCiphertext,
            keypairCiphertext: this.keypairCiphertext,
            keypairMac: this.keypairMac,
            pubKey: this.pubKey,
            keypairSalt: this.keypairSalt,
            keypairMacSalt: this.keypairMacSalt,
            signKeyPrivateMacSalt: this.signKeyPrivateMacSalt,
            username: this.username,
            signKeyPub: this.signKeyPub,
            signKeyPrivateCiphertext: this.signKeyPrivateCiphertext,
            signKeyPrivateMac: this.signKeyPrivateMac
        };
    };

    /**!
     * ### verifyAndDecrypt()
     * Convienence function to verify and decrypt public key encrypted & signed data
     *
     * @return {Object}
     */
    Account.prototype.verifyAndDecrypt = function(signedCiphertext, peer) {
        if (!peer.trusted) {
            return {
                error: 'Peer is untrusted'
            }
        }

        // hash the ciphertext
        var ciphertextString = JSON.stringify(signedCiphertext.ciphertext);
        var hash = sjcl.hash.sha256.hash(ciphertextString);
        // verify the signature
        var verified = false;
        try {
            verified = peer.signKeyPub.verify(hash, signedCiphertext.signature);
        } catch (ex) {
            console.error(ex);
            console.error(ex.stack);
        }
        // try to decrypt regardless of verification failure
        try {
            var message = sjcl.decrypt(this.secretKey, ciphertextString, crypton.cipherOptions);
            if (verified) {
                return {
                    plaintext: message,
                    verified: verified,
                    error: null
                };
            } else {
                return {
                    plaintext: null,
                    verified: false,
                    error: 'Cannot verify ciphertext'
                };
            }
        } catch (ex) {
            console.error(ex);
            console.error(ex.stack);
            return {
                plaintext: null,
                verified: false,
                error: 'Cannot verify ciphertext'
            };
        }
    };

    /**!
     * ### changePassphrase()
     * Convienence function to change the user's passphrase
     *
     * @param {String} currentPassphrase
     * @param {String} newPassphrase
     * @param {Function} callback
     * callback will be handed arguments err, isComplete
     * Upon completion of a passphrase change, the client will be logged out
     * This callback should handle getting the user logged back in
     * programmatically or via the UI
     * @param {Function} keygenProgressCallback [optional]
     * @param {Boolean} skipCheck [optional]
     * @return void
     */
    Account.prototype.changePassphrase =
        function(currentPassphrase, newPassphrase,
            callback, keygenProgressCallback, skipCheck) {
            if (skipCheck) {
                if (currentPassphrase == newPassphrase) {
                    var err = 'New passphrase cannot be the same as current password';
                    return callback(err);
                }
            }

            if (keygenProgressCallback) {
                if (typeof keygenProgressCallback == 'function') {
                    keygenProgressCallback();
                }
            }

            var MIN_PBKDF2_ROUNDS = crypton.MIN_PBKDF2_ROUNDS;
            var that = this;
            var username = this.username;
            // authorize to make sure the user knows the correct passphrase
            crypton.authorize(username, currentPassphrase, function(err, newSession) {
                if (err) {
                    console.error(err);
                    return callback(err);
                }
                // We have authorized, time to create the new keyring parts we
                // need to update the database

                var currentAccount = newSession.account;

                // Replace all salts with new ones
                var keypairSalt = crypton.randomBytes(32);
                var keypairMacSalt = crypton.randomBytes(32);
                var signKeyPrivateMacSalt = crypton.randomBytes(32);

                var keypairKey =
                    sjcl.misc.pbkdf2(newPassphrase, keypairSalt, MIN_PBKDF2_ROUNDS);

                var keypairMacKey =
                    sjcl.misc.pbkdf2(newPassphrase, keypairMacSalt, MIN_PBKDF2_ROUNDS);

                var signKeyPrivateMacKey =
                    sjcl.misc.pbkdf2(newPassphrase, signKeyPrivateMacSalt, MIN_PBKDF2_ROUNDS);

                var privateKeys = {
                    // 'privateKey/HMAC result name': serializedKey or string HMAC input data
                    containerNameHmacKeyCiphertext: currentAccount.containerNameHmacKey,
                    hmacKeyCiphertext: currentAccount.hmacKey,
                    signKeyPrivateCiphertext: currentAccount.signKeyPrivate.serialize(),
                    keypairCiphertext: currentAccount.secretKey.serialize(),
                    keypairMacKey: keypairMacKey,
                    signKeyPrivateMacKey: signKeyPrivateMacKey
                };

                var newKeyring;

                try {
                    newKeyring = that.wrapAllKeys(keypairKey, privateKeys, newSession);
                } catch (ex) {
                    console.error(ex);
                    console.error(ex.stack);
                    return callback('Fatal: cannot wrap keys, see error console for more information');
                }

                // Set other new properties before we save
                newKeyring.keypairSalt = JSON.stringify(keypairSalt);
                newKeyring.keypairMacSalt = JSON.stringify(keypairMacSalt);
                newKeyring.signKeyPrivateMacSalt = JSON.stringify(signKeyPrivateMacSalt);
                newKeyring.srpVerifier = srpVerifier;
                newKeyring.srpSalt = srpSalt;
                var url = crypton.url() + '/account/' + that.username + '/keyring?sid=' + crypton.sessionId;
                superagent.post(url)
                    .withCredentials()
                    .send(newKeyring)
                    .end(function(res) {
                        if (res.body.success !== true) {
                            console.error('error: ', res.body.error);
                            callback(res.body.error);
                        } else {
                            // XXX TODO: Invalidate all other client sessions before doing:
                            newSession = null; // Force new login after passphrase change
                            callback(null, true); // Do not hand the new session to the callback
                        }
                    });

            }, null);
        };

    /**!
     * ### wrapKey()
     * Helper function to wrap keys
     *
     * @param {String} selfPeer
     * @param {String} serializedPrivateKey
     * @return {Object} wrappedKey
     */
    Account.prototype.wrapKey = function(selfPeer, serializedPrivateKey) {
        if (!selfPeer || !serializedPrivateKey) {
            throw new Error('selfPeer and serializedPrivateKey are required');
        }
        var serializedKey;
        if (typeof serializedPrivateKey != 'string') {
            serializedKey = JSON.stringify(serializedPrivateKey);
        } else {
            serializedKey = serializedPrivateKey;
        }
        var wrappedKey = selfPeer.encryptAndSign(serializedKey);
        if (wrappedKey.error) {
            return null;
        }
        return wrappedKey;
    };

    /**!
     * ### wrapAllKeys()
     * Helper function to wrap all keys when changing passphrase, etc
     *
     * @param {String} wrappingKey
     * @param {Object} privateKeys
     * @param {Object} Session
     * @return {Object} wrappedKey
     */
    Account.prototype.wrapAllKeys = function(wrappingKey, privateKeys, session) {
        // Using the *labels* of the future wrapped objects here
        var requiredKeys = [
            'containerNameHmacKeyCiphertext',
            'hmacKeyCiphertext',
            'signKeyPrivateCiphertext',
            'keypairCiphertext', // main encryption private key
            'keypairMacKey',
            'signKeyPrivateMacKey'
        ];

        var privateKeysLength = Object.keys(privateKeys).length;
        var privateKeyNames = Object.keys(privateKeys);

        for (var i = 0; i < privateKeysLength; i++) {
            var keyName = privateKeyNames[i];
            if (requiredKeys.indexOf(keyName) == -1) {
                throw new Error('Missing private key: ' + keyName);
            }
        }
        // Check that the length of privateKeys is correct
        if (privateKeysLength != requiredKeys.length) {
            throw new Error('privateKeys length does not match requiredKeys length');
        }

        var selfPeer = new crypton.Peer({
            session: session,
            pubKey: session.account.pubKey,
            signKeyPub: session.account.signKeyPub
        });
        selfPeer.trusted = true;

        var result = {};

        var hmacKeyCiphertext = this.wrapKey(selfPeer,
            privateKeys.hmacKeyCiphertext);
        if (hmacKeyCiphertext.error) {
            result.hmacKeyCiphertext = null;
        } else {
            result.hmacKeyCiphertext = JSON.stringify(hmacKeyCiphertext);
        }

        var containerNameHmacKeyCiphertext =
            this.wrapKey(selfPeer,
                privateKeys.containerNameHmacKeyCiphertext);

        if (containerNameHmacKeyCiphertext.error) {
            result.containerNameHmacKeyCiphertext = null;
        } else {
            result.containerNameHmacKeyCiphertext = JSON.stringify(containerNameHmacKeyCiphertext);
        }

        // Private Keys
        var keypairCiphertext =
            sjcl.encrypt(wrappingKey,
                JSON.stringify(privateKeys.keypairCiphertext),
                crypton.cipherOptions);

        if (keypairCiphertext.error) {
            console.error(keypairCiphertext.error);
            keypairCiphertext = null;
        }
        result.keypairCiphertext = keypairCiphertext;

        var signKeyPrivateCiphertext =
            sjcl.encrypt(wrappingKey, JSON.stringify(privateKeys.signKeyPrivateCiphertext),
                crypton.cipherOptions);

        if (signKeyPrivateCiphertext.error) {
            console.error(signKeyPrivateCiphertext.error);
            signKeyPrivateCiphertext = null;
        }
        result.signKeyPrivateCiphertext = signKeyPrivateCiphertext;

        // HMACs
        result.keypairMac =
            crypton.hmac(privateKeys.keypairMacKey, result.keypairCiphertext);

        result.signKeyPrivateMac = crypton.hmac(privateKeys.signKeyPrivateMacKey,
            result.signKeyPrivateCiphertext);
        for (var keyName in result) {
            if (!result[keyName]) {
                throw new Error('Fatal: ' + keyName + ' is null');
            }
        }
        return result;
    };

})();
/* Crypton Client, Copyright 2013 SpiderOak, Inc.
 *
 * This file is part of Crypton Client.
 *
 * Crypton Client is free software: you can redistribute it and/or modify it
 * under the terms of the Affero GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Crypton Client is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the Affero GNU General Public
 * License for more details.
 *
 * You should have received a copy of the Affero GNU General Public License
 * along with Crypton Client.  If not, see <http://www.gnu.org/licenses/>.
 */

(function() {

    'use strict';

    var ERRS;

    /**!
     * # Session(id)
     *
     * ````
     * var session = new crypton.Session(id);
     * ````
     *
     * @param {Number} id
     */
    var Session = crypton.Session = function(id) {
        ERRS = crypton.errors;
        this.id = id;
        this.peers = {};
        this.events = {};
        this.containers = [];
        this.items = {};
        /*var arrX = [216641276, 1692448605, -1924501857, 1827387796, 779748572, 843150245, 1099493403, 
 	 1059976798, -180817969, -67584009, -1813773813, -191652818];
  var arrY = [563868699, -138412012, 966188095, -1677562130, 804621771, 907353981, -803448850, 
 	 -214138144, 1386665954, -1492810573, 1174706855, -995587158];
  var curve = sjcl.ecc.curves['c384'];
  var pubkey_x = new curve.field(sjcl.bn.fromBits(arrX));
  var pubkey_y = new curve.field(sjcl.bn.fromBits(arrY));
  var point = new sjcl.ecc.point(curve, pubkey_x, pubkey_y);
  this.serverPubSignatureKey = new sjcl.ecc.ecdsa.publicKey(curve, point);
  */

        var curve = sjcl.ecc.curves['c384'];
        var point = [216641276, 1692448605, -1924501857, 1827387796, 779748572, 843150245, 1099493403, 1059976798, -180817969, -67584009, -1813773813, -191652818, 563868699, -138412012, 966188095, -1677562130, 804621771, 907353981, -803448850, -214138144, 1386665954, -1492810573, 1174706855, -995587158];
        this.serverPubSignatureKey = new sjcl.ecc.ecdsa.publicKey(curve, point);

        var that = this;

        /*
        var joinServerParameters = { token: crypton.sessionId };
        this.socket = io.connect(crypton.url(),
                                 { query: 'joinServerParameters='
                                        + JSON.stringify(joinServerParameters),
                                   reconnection: true,
                                   reconnectionDelay: 5000
                                 });

        // watch for incoming Inbox messages
        this.socket.on('message', function (data) {
          that.inbox.get(data.messageId, function (err, message) {
            that.emit('message', message);
          });
        });

        // watch for container update notifications
        this.socket.on('containerUpdate', function (containerNameHmac) {
          // if any of the cached containers match the HMAC
          // in the notification, sync the container and
          // call the listener if one has been set
          for (var i = 0; i < that.containers.length; i++) {
            var container = that.containers[i];
            var temporaryHmac = container.containerNameHmac || container.getPublicName();

            if (crypton.constEqual(temporaryHmac, containerNameHmac)) {
              container.sync(function (err) {
                if (container._listener) {
                  container._listener();
                }
              });

              break;
            }
          }
        });

        // watch for Item update notifications
        this.socket.on('itemUpdate', function (itemObj) {
          if (!itemObj.itemNameHmac || !itemObj.creator || !itemObj.toUsername) {
            console.error(ERRS.ARG_MISSING);
            throw new Error(ERRS.ARG_MISSING);
          }
          console.log('Item updated!', itemObj);
          // if any of the cached items match the HMAC
          // in the notification, sync the items and
          // call the listener if one has been set
          if (that.items[itemObj.itemNameHmac]) {

            that.items[itemObj.itemNameHmac].sync(function (err) {
              if (err) {
                return console.error(err);
              }

              try {
                that.events.onSharedItemSync(that.items[itemObj.itemNameHmac]);
              } catch (ex) {
                console.warn(ex);
              }

              if (that.items[itemObj.itemNameHmac]._listener) {
                that.items[itemObj.itemNameHmac]._listener(err);
              }
            });
          } else {
            console.log('Loading the item as it is not cached');
            // load item!
            // get the peer first:
            that.getPeer(itemObj.creator, function (err, peer) {
              if (err) {
                console.error(err);
                console.error('Cannot load item: creator peer cannot be found');
                return;
              }
              // XXXddahl: Make sure you trust this peer before loading the item
              //           Perhaps we check this inside the Item constructor?
              var itemCallback = function _itemCallback (err, item) {
                if (err) {
                  console.error(err);
                  return;
                }
                that.items[itemObj.itemNameHmac] = item;
                try {
                  that.events.onSharedItemSync(item);
                } catch (ex) {
                  console.warn(ex);
                }
              };

              var item =
                new crypton.Item(null, null, that, peer,
                                 itemCallback, itemObj.itemNameHmac);

            });
          }
        });
        */
    };

    /**!
     * ### removeItem(itemNameHmac, callback)
     * Remove/delete Item with given 'itemNameHmac',
     * both from local cache & server
     *
     * Calls back with success boolean and without error if successful
     *
     * Calls back with error if unsuccessful
     *
     * @param {String} itemNameHmac
     * @param {Function} callback
     */
    Session.prototype.removeItem = function removeItem(itemNameHmac, callback) {
        var that = this;
        for (var name in this.items) {
            if (this.items[name].nameHmac == itemNameHmac) {
                this.items[name].remove(function(err) {
                    if (err) {
                        console.error(err);
                        callback(err);
                        return;
                    }
                    if (that.items[name].deleted) {
                        delete that.items[name];
                        callback(null);
                    }
                });
            }
        }
    };

    /**!
     * ### getOrCreateItem(itemName, callback)
     * Create or Retrieve Item with given platintext `itemName`,
     * either from local cache or server
     *
     * This method is for use by the creator of the item.
     * Use 'session.getSharedItem' for items shared by the creator
     *
     * Calls back with Item and without error if successful
     *
     * Calls back with error if unsuccessful
     *
     * @param {String} itemName
     * @param {Function} callback
     */
    Session.prototype.getOrCreateItem =
        function getOrCreateItem(itemName, callback) {

            if (!itemName) {
                return callback('itemName is required');
            }
            if (!callback) {
                throw new Error('Missing required callback argument');
            }
            // Get cached item if exists
            // XXXddahl: check server for more recent item?
            // We need another server API like /itemupdated/<itemHmacName> which returns
            // the timestamp of the last update
            if (this.items[itemName]) {
                callback(null, this.items[itemName]);
                return;
            }

            var creator = this.createSelfPeer();
            var item =
                new crypton.Item(itemName, null, this, creator, function getItemCallback(err, item) {
                    if (err) {
                        console.error(err);
                        return callback(err);
                    }
                    callback(null, item);
                });
        };

    /**!
     * ### getSharedItem(itemNameHmac, peer, callback)
     * Retrieve shared Item with given itemNameHmac,
     * either from local cache or server
     *
     * Calls back with Item and without error if successful
     *
     * Calls back with error if unsuccessful
     *
     * @param {String} itemNameHmac
     * @param {Object} peer
     * @param {Function} callback
     */
    Session.prototype.getSharedItem =
        function getSharedItem(itemNameHmac, peer, callback) {
            // TODO:  Does not check for cached item or server having a fresher Item
            if (!itemNameHmac) {
                return callback(ERRS.ARG_MISSING);
            }
            if (!callback) {
                throw new Error(ERRS.ARG_MISSING_CALLBACK);
            }

            function getItemCallback(err, item) {
                if (err) {
                    console.error(err);
                    return callback(err);
                }
                callback(null, item);
            }

            new crypton.Item(null, null, this, peer, getItemCallback, itemNameHmac);
        };

    /**!
     * ### createSelfPeer()
     * returns a 'selfPeer' object which is needed for any kind of
     * self-signing, encryption or verification
     *
     */
    Session.prototype.createSelfPeer = function() {
        var selfPeer = new crypton.Peer({
            session: this,
            pubKey: this.account.pubKey,
            signKeyPub: this.account.signKeyPub,
            signKeyPrivate: this.account.signKeyPrivate,
            username: this.account.username
        });
        selfPeer.trusted = true;
        return selfPeer;
    };

    /**!
     * ### load(containerName, callback)
     * Retieve container with given platintext `containerName`,
     * either from local cache or server
     *
     * Calls back with container and without error if successful
     *
     * Calls back with error if unsuccessful
     *
     * @param {String} containerName
     * @param {Function} callback
     */
    Session.prototype.load = function(containerName, callback) {
        // check for a locally stored container
        for (var i = 0; i < this.containers.length; i++) {
            if (crypton.constEqual(this.containers[i].name, containerName)) {
                callback(null, this.containers[i]);
                return;
            }
        }

        // check for a container on the server
        var that = this;
        this.getContainer(containerName, function(err, container) {
            if (err) {
                callback(err);
                return;
            }

            that.containers.push(container);
            callback(null, container);
        });
    };

    /**!
     * ### loadWithHmac(containerNameHmac, callback)
     * Retieve container with given `containerNameHmac`,
     * either from local cache or server
     *
     * Calls back with container and without error if successful
     *
     * Calls back with error if unsuccessful
     *
     * @param {String} containerNameHmac
     * @param {Function} callback
     */
    Session.prototype.loadWithHmac = function(containerNameHmac, peer, callback) {
        // check for a locally stored container
        for (var i = 0; i < this.containers.length; i++) {
            if (crypton.constEqual(this.containers[i].nameHmac, containerNameHmac)) {
                callback(null, this.containers[i]);
                return;
            }
        }

        // check for a container on the server
        var that = this;
        this.getContainerWithHmac(containerNameHmac, peer, function(err, container) {
            if (err) {
                callback(err);
                return;
            }

            that.containers.push(container);
            callback(null, container);
        });
    };

    /**!
     * ### create(containerName, callback)
     * Create container with given platintext `containerName`,
     * save it to server
     *
     * Calls back with container and without error if successful
     *
     * Calls back with error if unsuccessful
     *
     * @param {String} containerName
     * @param {Function} callback
     */
    Session.prototype.create = function(containerName, callback) {
        for (var i in this.containers) {
            if (crypton.constEqual(this.containers[i].name, containerName)) {
                callback('Container already exists');
                return;
            }
        }

        var selfPeer = new crypton.Peer({
            session: this,
            pubKey: this.account.pubKey,
            signKeyPub: this.account.signKeyPub
        });
        selfPeer.trusted = true;

        var sessionKey = crypton.randomBytes(32);
        var sessionKeyCiphertext = selfPeer.encryptAndSign(sessionKey);

        if (sessionKeyCiphertext.error) {
            return callback(sessionKeyCiphertext.error);
        }

        delete sessionKeyCiphertext.error;

        // TODO is signing the sessionKey even necessary if we're
        // signing the sessionKeyShare? what could the container
        // creator attack by wrapping a different sessionKey?
        var containerNameHmac = new sjcl.misc.hmac(this.account.containerNameHmacKey);
        containerNameHmac = sjcl.codec.hex.fromBits(containerNameHmac.encrypt(containerName));

        var chunk = {
            toAccount: this.account.username,
            sessionKeyCiphertext: JSON.stringify(sessionKeyCiphertext),
        };

        var url = crypton.url() + '/container/' + containerNameHmac;
        var that = this;
        superagent.put(url)
            //.withCredentials()
            .send(chunk)
            .use(crypton.bearer)
            .end(function(err, res) {
                if (!res.body || res.body.success !== true) {
                    callback(res.body.error);
                    return;
                }

                var container = new crypton.Container(that);
                container.name = containerName;
                container.sessionKey = sessionKey;
                that.containers.push(container);
                callback(null, container);
            });
    };

    /**!
     * ### deleteContainer(containerName, callback)
     * Request the server to delete all records and keys
     * belonging to `containerName`
     *
     * Calls back without error if successful
     *
     * Calls back with error if unsuccessful
     *
     * @param {String} containerName
     * @param {Function} callback
     */
    Session.prototype.deleteContainer = function(containerName, callback) {
        var that = this;
        var containerNameHmac = new sjcl.misc.hmac(this.account.containerNameHmacKey);
        containerNameHmac = sjcl.codec.hex.fromBits(containerNameHmac.encrypt(containerName));
        var url = crypton.url() + '/container/' + containerNameHmac;
        superagent.del(url)
            .use(crypton.bearer)
            .end(function(err, res) {
                if (res.body.success !== true && res.body.error !== undefined) {
                    return callback(res.body.error);
                }
                // remove from cache
                for (var i = 0; i < that.containers.length; i++) {
                    if (crypton.constEqual(that.containers[i].name, containerName)) {
                        that.containers.splice(i, 1);
                        break;
                    }
                }

                callback(null);
            });
    };

    /**!
     * ### getContainer(containerName, callback)
     * Retrieve container with given platintext `containerName`
     * specifically from the server
     *
     * Calls back with container and without error if successful
     *
     * Calls back with error if unsuccessful
     *
     * @param {String} containerName
     * @param {Function} callback
     */
    Session.prototype.getContainer = function(containerName, callback) {
        var container = new crypton.Container(this);
        container.name = containerName;
        container.sync(function(err) {
            callback(err, container);
        });
    };

    /**!
     * ### getContainerWithHmac(containerNameHmac, callback)
     * Retrieve container with given `containerNameHmac`
     * specifically from the server
     *
     * Calls back with container and without error if successful
     *
     * Calls back with error if unsuccessful
     *
     * @param {String} containerNameHmac
     * @param {Function} callback
     */
    Session.prototype.getContainerWithHmac = function(containerNameHmac, peer, callback) {
        var container = new crypton.Container(this);
        container.nameHmac = containerNameHmac;
        container.peer = peer;
        container.sync(function(err) {
            callback(err, container);
        });
    };

    /**!
     * ### getPeer(containerName, callback)
     * Retrieve a peer object from the database for given `username`
     *
     * Calls back with peer and without error if successful
     *
     * Calls back with error if unsuccessful
     *
     * @param {String} username
     * @param {Function} callback
     */
    Session.prototype.getPeer = function(username, callback) {
        if (this.peers[username]) {
            return callback(null, this.peers[username]);
        }

        var that = this;
        var peer = new crypton.Peer();
        peer.username = username;
        peer.session = this;

        peer.fetch(function(err, peer) {
        	if (peer === undefined) {
                return callback("peer not registered");
        	}
            if (err) {
                return callback(err);
            }

            e2ee.session.peersContainer.get('peers', function(err, peers) {
                if (err) {
                    if (window.console && window.console.log) {
                        console.info(err)
                        console.info('peers from peersContainer could not be retrieved')
                    }
                    callback(err)
                } else {
                    if (!peers[username]) {
                        peer.trusted = false;
                    } else {
                        var savedFingerprint = peers[username].fingerprint;
                        if (!crypton.constEqual(savedFingerprint, peer.fingerprint)) {
                            return callback('Server has provided malformed peer', peer);
                        }
                        peer.trusted = true;
                    }

                    that.peers[username] = peer;
                    callback(null, peer);
                }
            })
        });
    };

    Session.prototype.getMessages = function(callback) {
        var that = this;
        var url = crypton.url() + '/messages';
        var messages = {}
        superagent.get(url)
            .send(this.encrypted)
            .use(crypton.bearer)
            //.withCredentials()
            .end(function(err, res) {
                if (!res.body || res.body.success !== true) {
                    callback(res.body.error);
                    return;
                }

                //callback(null, res.body.messages);
                async.each(res.body.messages, function(rawMessage, callback) {
                        var message = new crypton.Message(that, rawMessage);
                        message.decrypt(function(err) {
                            messages[message.messageId] = message; // messagId actually not set
                            callback();
                        });
                    },
                    function(err) {
                        if (callback) {
                            callback(null, messages);
                        }
                    })
            });
    };

    Session.prototype.deleteMessages = function(callback) {
        var that = this;
        var url = crypton.url() + '/messages';
        var messages = {}
        superagent.del(url)
            .send(this.encrypted)
            .use(crypton.bearer)
            //.withCredentials()
            .end(function(err, res) {
                if (!res.body || res.body.success !== true) {
                    callback(res.body.error);
                    return;
                }

                callback(null);
            });
    };


    /**!
     * ### on(eventName, listener)
     * Set `listener` to be called anytime `eventName` is emitted
     *
     * @param {String} eventName
     * @param {Function} listener
     */
    // TODO allow multiple listeners
    Session.prototype.on = function(eventName, listener) {
        this.events[eventName] = listener;
    };

    /**!
     * ### emit(eventName, data)
     * Call listener for `eventName`, passing it `data` as an argument
     *
     * @param {String} eventName
     * @param {Object} data
     */
    // TODO allow multiple listeners
    Session.prototype.emit = function(eventName, data) {
        this.events[eventName] && this.events[eventName](data);
    };

})();
/* Crypton Client, Copyright 2013 SpiderOak, Inc.
 *
 * This file is part of Crypton Client.
 *
 * Crypton Client is free software: you can redistribute it and/or modify it
 * under the terms of the Affero GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Crypton Client is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the Affero GNU General Public
 * License for more details.
 *
 * You should have received a copy of the Affero GNU General Public License
 * along with Crypton Client.  If not, see <http://www.gnu.org/licenses/>.
 */

(function() {

    'use strict';

    /**!
     * # Container(session)
     *
     * ````
     * var container = new crypton.Container(session);
     * ````
     *
     * @param {Object} session
     */
    var Container = crypton.Container = function(session) {
        this.keys = {};
        this.session = session;
        this.recordCount = 1;
        this.recordIndex = 0;
        this.versions = {};
        //this.version = +new Date();
        this.version = 0;
        this.name = null;
    };

    /**!
     * ### add(key, callback)
     * Add given `key` to the container
     *
     * Calls back without error if successful
     *
     * Calls back with error if unsuccessful
     *
     * @param {String} key
     * @param {Function} callback
     */
    Container.prototype.add = function(key, callback) {
        if (this.keys[key]) {
            callback('Key already exists');
            return;
        }

        this.keys[key] = {};
        callback();
    };

    /**!
     * ### get(key, callback)
     * Retrieve value for given `key`
     *
     * Calls back with `value` and without error if successful
     *
     * Calls back with error if unsuccessful
     *
     * @param {String} key
     * @param {Function} callback
     */
    Container.prototype.get = function(key, callback) {
        if (!this.keys[key]) {
            callback('Key does not exist');
            return;
        }

        callback(null, this.keys[key]);
    };

    /**!
     * ### save(callback, options)
     * Get difference of container since last save (a record),
     * encrypt the record, and send it to the server to be saved
     *
     * Calls back without error if successful
     *
     * Calls back with error if unsuccessful
     *
     * @param {Function} callback
     * @param {Object} options (optional)
     */
    Container.prototype.save = function(callback, options) {
        var that = this;

        this.getDiff(function(err, diff) {
            if (!diff) {
                callback('Container has not changed');
                return;
            }

            var payload = {
                recordIndex: that.recordCount,
                delta: diff
            };

            var now = +new Date();
            var copiedObject = $.extend(true, {}, that.keys) // instead of: JSON.parse(JSON.stringify(that.keys))
            that.versions[now] = copiedObject;
            that.version = now;
            that.recordCount++;

            window.performance.mark('start');

            var rawPayloadCiphertext;
            var encryptAsArrayBuffer = false;
            if (payload.delta.chunks) {
                encryptAsArrayBuffer = true;
                // todo: check decryption
                for (key in payload.delta.chunks[0]) {
                    if (payload.delta.chunks[0].hasOwnProperty(key)) {
                        var value = payload.delta.chunks[0][key];
                        if (!(value instanceof Uint8Array)) {
                            // when the whole file is encrypted, payload.delta contains ArrayBuffer,
                            // however for futher changes payload.delta does not contain ArrayBuffer
                            encryptAsArrayBuffer = false;
                        }
                        break;
                    }
                }
            }
            if (encryptAsArrayBuffer) {
                // flatten the Uint8Array that was retrieved in chunks from file
                var chunksNum = Object.keys(payload.delta.chunks[0]).length
                var size = 0;
                for (var key in payload.delta.chunks[0]) {
                    var value = payload.delta.chunks[0][key];
                    size += value.length;
                }
                
                // Not the whole container is converted into Uint8Array - 
                // only chunks and metadata at the moment.
                // Note that metadata could be added to another container,
                // but than when sharing this container would be needed 
                // to be shared too ...
                var meta = JSON.stringify(payload.delta.metadata[0]);
                var buf = new ArrayBuffer(meta.length);
  				var bufView = new Uint8Array(buf);
  				for (var i=0; i<meta.length; i++) {
    				bufView[i] = meta.charCodeAt(i);
  				}
  				var separationOffset = 10
  				size += meta.length;
  				size += separationOffset;
                
                var newArray = new Uint8Array(size);
                Object.keys(payload.delta.chunks[0]).forEach(function(key) { // keys are data positions
                    newArray.set(payload.delta.chunks[0][key], parseInt(key));
                });
                
                var tmpLen = newArray.length;
                newArray.set(bufView, size-meta.length);
                 
                rawPayloadCiphertext = sjcl.encrypt(that.sessionKey, newArray.buffer, crypton.cipherOptions);
            } else {
                rawPayloadCiphertext = sjcl.encrypt(that.sessionKey, JSON.stringify(payload), crypton.cipherOptions);
            }

            window.performance.mark('end')

            window.performance.mark('start conversion')
            var bytes = [];
            var str = JSON.stringify(rawPayloadCiphertext);
            for (var i = 0; i < str.length; ++i) {
                bytes.push(str.charCodeAt(i));
            }
            window.performance.mark('end conversion')

            window.performance.mark('start hash')
                // hashing is really slow for large ciphertexts
            var b = new BLAKE2s(32);
            b.update(bytes);
            var payloadCiphertextHash = b.hexDigest();

            //var payloadCiphertextHash = sjcl.hash.sha256.hash(JSON.stringify(rawPayloadCiphertext));
            window.performance.mark('end hash')
            var payloadSignature = that.session.account.signKeyPrivate.sign(payloadCiphertextHash, crypton.paranoia);

            window.performance.measure('encryption', 'start', 'end')
            window.performance.measure('conversion', 'start conversion', 'end conversion')
            window.performance.measure('hashing', 'start hash', 'end hash')
            var items = window.performance.getEntriesByType('measure')
            var all = 0;
            for (var i = 0; i < items.length; ++i) {
                var req = items[i]
                console.log(req.name + ' took ' + req.duration + 'ms')
                all += req.duration;
            }
            console.log('all took ' + all + 'ms')
            window.performance.clearMarks()
            window.performance.clearMeasures()


            var payloadCiphertext = {
                ciphertext: rawPayloadCiphertext,
                signature: payloadSignature
            };

            var chunk = {
                containerNameHmac: that.getPublicName(),
                payloadCiphertext: JSON.stringify(payloadCiphertext)
            };

            // if we aren't saving it, we're probably testing
            // to see if the transaction chunk was generated correctly
            if (options && options.save == false) {
                callback(null, chunk);
                return;
            }

            var url = crypton.url() + '/container/record';
            superagent.post(url)
                //.withCredentials()
                .send(chunk)
                .use(crypton.bearer)
                .end(function(err, res) {
                    if (!res.body || res.body.success !== true) {
                        callback(res.body.error);
                        return;
                    }
                    callback(null);
                });
        });
    };

    /**!
     * ### getDiff(callback, options)
     * Compute difference of container since last save
     *
     * Calls back with diff object and without error if successful
     *
     * Calls back with error if unsuccessful
     *
     * @param {Function} callback
     */
    Container.prototype.getDiff = function(callback) {
        var last = this.latestVersion();
        var old = this.versions[last] || {};
        callback(null, crypton.diff.create(old, this.keys));
    };

    /**!
     * ### getVersions()
     * Return a list of known save point timestamps
     *
     * @return {Array} timestamps
     */
    Container.prototype.getVersions = function() {
        return Object.keys(this.versions);
    };

    /**!
     * ### getVersion(version)
     * Return full state of container at given `timestamp`
     *
     * @param {Number} timestamp
     * @return {Object} version
     */
    Container.prototype.getVersion = function(timestamp) {
        return this.versions[timestamp];
    };

    /**!
     * ### getVersion()
     * Return last known save point timestamp
     *
     * @return {Number} version
     */
    Container.prototype.latestVersion = function() {
        var versions = this.getVersions();

        if (!versions.length) {
            return this.version;
        } else {
            return Math.max.apply(Math, versions);
        }
    };

    /**!
     * ### getPublicName()
     * Compute the HMAC for the given name of the container
     *
     * @return {String} hmac
     */
    Container.prototype.getPublicName = function() {
        if (this.nameHmac) {
            return this.nameHmac;
        }

        var hmac = new sjcl.misc.hmac(this.session.account.containerNameHmacKey);
        var containerNameHmac = hmac.encrypt(this.name);
        this.nameHmac = sjcl.codec.hex.fromBits(containerNameHmac);
        return this.nameHmac;
    };

    /**!
     * ### getHistory()
     * Ask the server for all state records
     *
     * Calls back with diff object and without error if successful
     *
     * Calls back with error if unsuccessful
     *
     * @param {Function} callback
     */
    Container.prototype.getHistory = function(callback) {
        var that = this;
        var containerNameHmac = this.getPublicName();
        var currentVersion = this.latestVersion();

        var nonce = sjcl.codec.hex.fromBits(crypton.randomBytes(32));
        var url = crypton.url() + '/container/' + containerNameHmac + '?after=' + (currentVersion + 1) + '&nonce=' + nonce;

        console.log('getHistory', url);
        superagent.get(url)
            //.withCredentials()
            // .set('X-Session-ID', crypton.sessionId)
            .use(crypton.bearer)
            .end(function(err, res) {
                if (!res.body || res.body.success !== true) {
                    callback(res.body.error);
                    return;
                }

                callback(null, res.body.records);
            });
    };

    /**!
     * ### parseHistory(records, callback)
     * Loop through given `records`, decrypt them,
     * and build object state from decrypted diff objects
     *
     * Calls back with full container state,
     * history versions, last record index,
     * and without error if successful
     *
     * Calls back with error if unsuccessful
     *
     * @param {Array} records
     * @param {Function} callback
     */
    Container.prototype.parseHistory = function(records, callback) {
        var that = this;
        var keys = that.keys || {};
        var versions = that.versions || {};

        var recordIndex = that.recordIndex + 1;

        async.eachSeries(records, function(rawRecord, callback) {
            that.decryptRecord(recordIndex, rawRecord, function(err, record) {
                if (err) {
                    return callback(err);
                }

                // TODO put in worker
                keys = crypton.diff.apply(record.delta, keys);

                var copiedObject = $.extend(true, {}, keys) // instead of: JSON.parse(JSON.stringify(keys))
                versions[record.time] = copiedObject;

                callback(null);
            });
        }, function(err) {
            if (err) {
                console.log('Hit error parsing container history');
                console.log(that);
                console.log(err);

                return callback(err);
            }

            that.recordIndex = recordIndex;
            callback(null, keys, versions, recordIndex);
        });
    };

    /**!
     * ### decryptRecord(recordIndex, record, callback)
     * Decrypt record ciphertext with session key,
     * verify record index
     *
     * Calls back with object containing timestamp and delta
     * and without error if successful
     *
     * Calls back with error if unsuccessful
     *
     * @param {Object} recordIndex
     * @param {Object} record
     * @param {Object} callback
     */
    Container.prototype.decryptRecord = function(recordIndex, record, callback) {
        if (!this.sessionKey) {
            this.decryptKey(record);
        }

        var parsedRecord;
        try {
            parsedRecord = JSON.parse(record.payloadCiphertext);
        } catch (e) {}

        if (!parsedRecord) {
            return callback('Could not parse record JSON');
        }

        var options = {
            sessionKey: this.sessionKey,
            expectedRecordIndex: recordIndex,
            record: record.payloadCiphertext,
            creationTime: record.CreatedAt, // started with upper case because default gorm.Model is used on server side
            // we can't just send the peer object or its signKeyPub
            // here because of circular JSON when dealing with workers.
            // we'll have to reconstruct the signkey on the other end.
            // better to be explicit anyway!
            peerSignKeyPubSerialized: (
                this.peer && this.peer.signKeyPub || this.session.account.signKeyPub
            ).serialize()
        };

        crypton.work.decryptRecord(options, callback);
    };

    /**!
     * ### decryptKey(record)
     * Extract and decrypt the container's keys from a given record
     *
     * @param {Object} record
     */
    Container.prototype.decryptKey = function(record) {
        var peer = this.peer || this.session.account;
        var sessionKeyRaw = this.session.account.verifyAndDecrypt(JSON.parse(record.sessionKeyCiphertext), peer);

        if (sessionKeyRaw.error) {
            throw new Error(sessionKeyRaw.error);
        }

        if (!sessionKeyRaw.verified) {
            throw new Error('Container session key signature mismatch');
        }

        this.sessionKey = JSON.parse(sessionKeyRaw.plaintext);
    };

    /**!
     * ### sync(callback)
     * Retrieve history, decrypt it, and update
     * container object with new state
     *
     * Calls back without error if successful
     *
     * Calls back with error if unsuccessful
     *
     * @param {Function} callback
     */
    Container.prototype.sync = function(callback) {
        var that = this;
        this.getHistory(function(err, records) {
            if (err) {
                callback(err);
                return;
            }

            that.parseHistory(records, function(err, keys, versions, recordIndexAfter) {
                that.keys = keys;
                that.versions = versions;
                that.version = Math.max.apply(Math, Object.keys(versions));
                // versions.count is not defined:
                //that.recordCount = that.recordCount + versions.count;
                that.recordCount = Object.keys(versions).length;

                // TODO verify recordIndexAfter == recordCount?

                callback(err);
            });
        });
    };

    /**!
     * ### share(peer, callback)
     * Encrypt the container's sessionKey with peer's
     * public key, commit new addContainerSessionKey chunk,
     * and send a message to the peer informing them
     *
     * Calls back without error if successful
     *
     * Calls back with error if unsuccessful
     *
     * @param {Function} callback
     */
    Container.prototype.share = function(peer, callback) {
        if (!this.sessionKey) {
            return callback('Container must be initialized to share');
        }

        var containerNameHmac = this.getPublicName();
        if (containerNameHmac !== this.nameHmac) {
            callback("Only the creator of file can share it");
            return;
        }

        // encrypt sessionKey to peer's pubKey
        var sessionKeyCiphertext = peer.encryptAndSign(this.sessionKey);

        if (sessionKeyCiphertext.error) {
            return callback(sessionKeyCiphertext.error);
        }

        delete sessionKeyCiphertext.error;

        // create new addContainerSessionKeyShare chunk
        var that = this;

        var chunk = {
            toAccountId: peer.accountId,
            containerNameHmac: containerNameHmac,
            sessionKeyCiphertext: JSON.stringify(sessionKeyCiphertext),
        };

        var url = crypton.url() + '/container/share';
        superagent.post(url)
            //.withCredentials()
            .send(chunk)
            .use(crypton.bearer)
            .end(function(err, res) {
                if (!res.body || res.body.success !== true) {
                    callback(res.body.error);
                    return;
                }

                callback(null);
            });
    };

    Container.prototype.unshare = function(peer, callback) {
        if (!this.sessionKey) {
            return callback('Container must be initialized to share');
        }

        var containerNameHmac = this.getPublicName();
        if (containerNameHmac !== this.nameHmac) {
            callback("Only the creator of file can unshare it");
            return;
        }

        var that = this;
        var chunk = {
            toAccountId: peer.accountId,
            containerNameHmac: containerNameHmac,
        };

        var url = crypton.url() + '/container/unshare';
        superagent.post(url)
            //.withCredentials()
            .send(chunk)
            .use(crypton.bearer)
            .end(function(err, res) {
                if (!res.body || res.body.success !== true) {
                    callback(res.body.error);
                    return;
                }

                callback(null);
            });
    };

    /**!
     * ### watch(listener)
     * Attach a listener to the container
     * which is called if it is written to by a peer
     *
     * This is called after the container is synced
     *
     * @param {Function} callback
     */
    /*
    Container.prototype.watch = function (listener) {
      this._listener = listener;
    };
    */

    /**!
     * ### unwatch()
     * Remove an attached listener
     */
    Container.prototype.unwatch = function() {
        delete this._listener;
    };

})();
/* Crypton Client, Copyright 2013 SpiderOak, Inc.
 *
 * This file is part of Crypton Client.
 *
 * Crypton Client is free software: you can redistribute it and/or modify it
 * under the terms of the Affero GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Crypton Client is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the Affero GNU General Public
 * License for more details.
 *
 * You should have received a copy of the Affero GNU General Public License
 * along with Crypton Client.  If not, see <http://www.gnu.org/licenses/>.
 */

(function() {

    'use strict';

    /**!
     * # Peer(options)
     *
     * ````
     * var options = {
     *   username: 'friend' // required
     * };
     *
     * var peer = new crypton.Peer(options);
     * ````
     *
     * @param {Object} options
     */
    var Peer = crypton.Peer = function(options) {
        options = options || {};

        this.accountId = options.id;
        this.session = options.session;
        this.username = options.username;
        this.pubKey = options.pubKey;
        this.signKeyPub = options.signKeyPub;
    };

    /**!
     * ### fetch(callback)
     * Retrieve peer data from server, applying it to parent object
     *
     * Calls back with peer data and without error if successful
     *
     * Calls back with error if unsuccessful
     *
     * @param {Function} callback
     */
    Peer.prototype.fetch = function(callback) {
        if (!this.username) {
            callback('Must supply peer username');
            return;
        }

        if (!this.session) {
            callback('Must supply session to peer object');
            return;
        }

        var that = this;
        var url = crypton.url() + '/peer/' + this.username;
        superagent.get(url)
            .withCredentials()
            .use(crypton.bearer)
            .end(function(err, res) {
                if (!res.body || res.body.success !== true) {
                    callback(res.body.error);
                    return;
                }

                var peer = res.body.peer;
                that.accountId = peer.accountId;
                that.username = peer.username;
                that.pubKey = sjcl.ecc.deserialize(JSON.parse(peer.pubKey));
                that.signKeyPub = sjcl.ecc.deserialize(JSON.parse(peer.signKeyPub));

                // calculate fingerprint for public key
                that.fingerprint = crypton.fingerprint(that.pubKey, that.signKeyPub);

                callback(null, that);
            });
    };

    /**!
     * ### encrypt(payload)
     * Encrypt `message` with peer's public key
     *
     * @param {Object} payload
     * @return {Object} ciphertext
     */
    Peer.prototype.encrypt = function(payload) {
        if (!this.trusted) {
            return {
                error: 'Peer is untrusted'
            }
        }

        // should this be async to callback with an error if there is no pubkey?
        var ciphertext = sjcl.encrypt(this.pubKey, JSON.stringify(payload), crypton.cipherOptions);
        return ciphertext;
    };

    /**!
     * ### encryptAndSign(payload)
     * Encrypt `message` with peer's public key, sign the message with own signing key
     *
     * @param {Object} payload
     * @return {Object}
     */
    Peer.prototype.encryptAndSign = function(payload) {
        if (!this.trusted) {
            return {
                error: 'Peer is untrusted'
            }
        }

        try {
            var ciphertext = sjcl.encrypt(this.pubKey, JSON.stringify(payload), crypton.cipherOptions);
            // hash the ciphertext and sign the hash:
            var hash = sjcl.hash.sha256.hash(ciphertext);
            var signature = this.session.account.signKeyPrivate.sign(hash, crypton.paranoia);
            return {
                ciphertext: JSON.parse(ciphertext),
                signature: signature,
                error: null
            };
        } catch (ex) {
            console.error(ex);
            console.error(ex.stack);
            var err = "Error: Could not complete encryptAndSign: " + ex;
            return {
                ciphertext: null,
                signature: null,
                error: err
            };
        }
    };

    /**!
     * ### sendMessage(headers, payload, callback)
     * Encrypt `headers` and `payload` and send them to peer in one logical `message`
     *
     * Calls back with message id and without error if successful
     *
     * Calls back with error if unsuccessful
     *
     * @param {Object} headers
     * @param {Object} payload
     */
    Peer.prototype.sendMessage = function(headers, payload, callback) {
        if (!this.session) {
            callback('Must supply session to peer object');
            return;
        }

        var message = new crypton.Message(this.session);
        message.headers = headers;
        message.payload = payload;
        message.fromAccount = this.session.accountId;
        message.toAccount = this.accountId;
        message.encrypt(this);
        message.send(callback);
    };

    /**!
     * ### trust(callback)
     * Add peer's fingerprint to internal trusted peers Item
     *
     * Calls back without error if successful
     *
     * Calls back with error if unsuccessful
     *
     * @param {Function} callback
     */
    Peer.prototype.trust = function(callback) {
        var that = this;
        var container = e2ee.session.peersContainer
        container.get('peers', function(err, peers) {
            if (err) {
                if (window.console && window.console.log) {
                    console.info(err)
                    console.info('peers from peersContainer could not be retrieved')
                }
                callback(err)
            } else {
                peers[that.username] = {
                    trustedAt: +new Date(),
                    fingerprint: that.fingerprint
                };
                container.save(function(err) {
                    if (err) {
                        return callback(err);
                    }
                    that.trusted = true;
                    callback(null);
                });
            }
        })
    };

    Peer.prototype.untrust = function(callback) {
        var that = this;
        var container = e2ee.session.peersContainer
        container.get('peers', function(err, peers) {
            if (err) {
                if (window.console && window.console.log) {
                    console.info(err)
                    console.info('peers from peersContainer could not be retrieved')
                }
                callback(err)
            } else {
                delete peers[that.username]
                container.save(function(err) {
                    if (err) {
                        return callback(err);
                    }
                    that.trusted = true;
                    callback(null);
                });
            }
        })
    };

})();
/* Crypton Client, Copyright 2013 SpiderOak, Inc.
 *
 * This file is part of Crypton Client.
 *
 * Crypton Client is free software: you can redistribute it and/or modify it
 * under the terms of the Affero GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Crypton Client is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the Affero GNU General Public
 * License for more details.
 *
 * You should have received a copy of the Affero GNU General Public License
 * along with Crypton Client.  If not, see <http://www.gnu.org/licenses/>.
 */

(function() {

    'use strict';

    var Message = crypton.Message = function Message(session, raw) {
        this.session = session;
        this.headers = {};
        this.payload = {};

        raw = raw || {};
        for (var i in raw) {
            this[i] = raw[i];
        }
    };

    Message.prototype.encrypt = function(peer, callback) {
        var headersCiphertext = peer.encryptAndSign(this.headers);
        var payloadCiphertext = peer.encryptAndSign(this.payload);

        if (headersCiphertext.error || payloadCiphertext.error) {
            callback('Error encrypting headers or payload in Message.encrypt()');
            return;
        }

        this.encrypted = {
            headersCiphertext: JSON.stringify(headersCiphertext),
            payloadCiphertext: JSON.stringify(payloadCiphertext),
            fromUsername: this.session.account.username,
            toAccountId: peer.accountId
        };

        callback && callback(null);
    };

    Message.prototype.decrypt = function(callback) {
        var that = this;
        var headersCiphertext = JSON.parse(this.headersCiphertext);
        var payloadCiphertext = JSON.parse(this.payloadCiphertext);

        this.session.getPeer(this.fromUsername, function(err, peer) {
            if (err) {
                callback(err);
                return;
            }

            var headers = that.session.account.verifyAndDecrypt(headersCiphertext, peer);
            var payload = that.session.account.verifyAndDecrypt(payloadCiphertext, peer);
            if (!headers.verified || !payload.verified) {
                callback('Cannot verify headers or payload ciphertext in Message.decrypt()');
                return;
            } else if (headers.error || payload.error) {
                callback('Cannot decrypt headers or payload in Message.decrypt');
                return;
            }

            that.headers = JSON.parse(headers.plaintext);
            that.payload = JSON.parse(payload.plaintext);
            that.created = new Date(that.CreatedAt); // started with upper case because default gorm.Model is used on server side

            callback(null, that);
        });
    };

    Message.prototype.send = function(callback) {
        if (!this.encrypted) {
            return callback('You must encrypt the message to a peer before sending!');
        }

        var url = crypton.url() + '/peer';
        superagent.post(url)
            .send(this.encrypted)
            .use(crypton.bearer)
            //.withCredentials()
            .end(function(err, res) {
                if (!res.body || res.body.success !== true) {
                    callback(res.body.error);
                    return;
                }

                callback(null, res.body.messageId);
            });
    };

})();
/* Crypton Client, Copyright 2013 SpiderOak, Inc.
 *
 * This file is part of Crypton Client.
 *
 * Crypton Client is free software: you can redistribute it and/or modify it
 * under the terms of the Affero GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Crypton Client is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the Affero GNU General Public
 * License for more details.
 *
 * You should have received a copy of the Affero GNU General Public License
 * along with Crypton Client.  If not, see <http://www.gnu.org/licenses/>.
 */

(function() {

    'use strict';

    var Diff = crypton.diff = {};

    /**!
     * ### create(old, current)
     * Generate an object representing the difference between two inputs
     *
     * @param {Object} old
     * @param {Object} current
     * @return {Object} delta
     */
    Diff.create = function(old, current) {
        var delta = jsondiffpatch.diff(old, current);
        return delta;
    };

    /**!
     * ### apply(delta, old)
     * Apply `delta` to `old` object to build `current` object
     *
     * @param {Object} delta
     * @param {Object} old
     * @return {Object} current
     */
    // TODO should we switch the order of these arguments?
    Diff.apply = function(delta, old) {
        var current = JSON.parse(JSON.stringify(old)); // don't use $.extend(true, {}, old) here
        jsondiffpatch.patch(current, delta);
        return current;
    };

})();

/* Crypton Client, Copyright 2013 SpiderOak, Inc.
 *
 * This file is part of Crypton Client.
 *
 * Crypton Client is free software: you can redistribute it and/or modify it
 * under the terms of the Affero GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Crypton Client is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the Affero GNU General Public
 * License for more details.
 *
 * You should have received a copy of the Affero GNU General Public License
 * along with Crypton Client.  If not, see <http://www.gnu.org/licenses/>.
 */

(function() {

    'use strict';

    /*
     * if the browser supports web workers,
     * we "isomerize" crypton.work to transparently
     * put its methods in a worker and replace them
     * with a bridge API to said worker
     */
    !self.worker && window.addEventListener('load', function() {
        return;
        var scriptEls = document.getElementsByTagName('script');
        var path;

        for (var i in scriptEls) {
            if (scriptEls[i].src && ~scriptEls[i].src.indexOf('crypton.js')) {
                path = scriptEls[i].src;
            }
        }

        isomerize(crypton.work, path)
    }, false);

    var work = crypton.work = {};

    /**!
     * ### unravelAccount(account, callback)
     * Decrypt account keys, and pass them back
     * in a serialized form for reconstruction
     *
     * Calls back with key object and without error if successful
     *
     * Calls back with error if unsuccessful
     *
     * @param {Object} account
     * @param {Function} callback
     */
    work.unravelAccount = function(account, callback) {
        var ret = {};

        var numRounds = crypton.MIN_PBKDF2_ROUNDS;
        // regenerate keypair key from password
        var keypairKey = sjcl.misc.pbkdf2(account.passphrase, account.keypairSalt, numRounds);
        var keypairMacKey = sjcl.misc.pbkdf2(account.passphrase, account.keypairMacSalt, numRounds);
        var signKeyPrivateMacKey = sjcl.misc.pbkdf2(account.passphrase, account.signKeyPrivateMacSalt, numRounds);

        var macOk = false;

        // decrypt secret key
        try {
            //var ciphertextString = JSON.stringify(account.keypairCiphertext);
            var ciphertextString = account.keypairCiphertext;
            macOk = crypton.hmacAndCompare(keypairMacKey, ciphertextString, account.keypairMac);
            ret.secret = JSON.parse(sjcl.decrypt(keypairKey, ciphertextString, crypton.cipherOptions));
        } catch (e) {}

        if (!macOk || !ret.secret) {
            // TODO could be decryption or parse error - should we specify?
            return callback('Could not parse secret key');
        }

        macOk = false;

        // decrypt signing key
        try {
            //var ciphertextString = JSON.stringify(account.signKeyPrivateCiphertext);
            var ciphertextString = account.signKeyPrivateCiphertext;
            macOk = crypton.hmacAndCompare(signKeyPrivateMacKey, ciphertextString, account.signKeyPrivateMac);
            ret.signKeySecret = JSON.parse(sjcl.decrypt(keypairKey, ciphertextString, crypton.cipherOptions));
        } catch (e) {}

        if (!macOk || !ret.signKeySecret) {
            return callback('Could not parse signKeySecret');
        }

        var secretKey = sjcl.ecc.deserialize(ret.secret);

        account.secretKey = secretKey;

        var session = {};
        session.account = account;
        session.account.signKeyPrivate = ret.signKeySecret;

        var selfPeer = new crypton.Peer({
            session: session,
            pubKey: account.pubKey,
            signKeyPub: account.signKeyPub
        });
        selfPeer.trusted = true;

        var selfAccount = new crypton.Account();
        selfAccount.secretKey = secretKey;

        // decrypt hmac keys
        var containerNameHmacKey;
        try {
            containerNameHmacKey = selfAccount.verifyAndDecrypt(account.containerNameHmacKeyCiphertext, selfPeer);
            ret.containerNameHmacKey = JSON.parse(containerNameHmacKey.plaintext);
        } catch (e) {}

        if (!containerNameHmacKey.verified) {
            // TODO could be decryption or parse error - should we specify?
            return callback('Could not parse containerNameHmacKey');
        }

        var hmacKey;
        try {
            hmacKey = selfAccount.verifyAndDecrypt(account.hmacKeyCiphertext, selfPeer);
            ret.hmacKey = JSON.parse(hmacKey.plaintext);
        } catch (e) {}

        if (!hmacKey.verified) {
            // TODO could be decryption or parse error - should we specify?
            return callback('Could not parse hmacKey');
        }

        callback(null, ret);
    };

    /**!
     * ### decryptRecord(options, callback)
     * Decrypt a single record after checking its signature
     *
     * Calls back with decrypted record and without error if successful
     *
     * Calls back with error if unsuccessful
     *
     * @param {Object} options
     * @param {Function} callback
     */
    work.decryptRecord = function(options, callback) {
        var sessionKey = options.sessionKey;
        var creationTime = options.creationTime;
        var expectedRecordIndex = options.expectedRecordIndex;
        var peerSignKeyPubSerialized = options.peerSignKeyPubSerialized;

        if (!sessionKey ||
            !creationTime ||
            !expectedRecordIndex ||
            !peerSignKeyPubSerialized
        ) {
            return callback('Must supply all options to work.decryptRecord');
        }

        var record;
        try {
            record = JSON.parse(options.record);
        } catch (e) {}

        if (!record) {
            return callback('Could not parse record');
        }

        // reconstruct the peer's public signing key
        // the key itself typically has circular references which
        // we can't pass around with JSON to/from a worker
        var peerSignKeyPub = sjcl.ecc.deserialize(peerSignKeyPubSerialized);

        var verified = false;

        window.performance.mark('start conversion');
        var bytes = [];
        var str = JSON.stringify(record.ciphertext);
        for (var i = 0; i < str.length; ++i) {
            bytes.push(str.charCodeAt(i));
        }
        window.performance.mark('end conversion');
        window.performance.mark('start hash');
        var b = new BLAKE2s(32);
        b.update(bytes);
        var payloadCiphertextHash = b.hexDigest();
        window.performance.mark('end hash');

        //var payloadCiphertextHash = sjcl.hash.sha256.hash(JSON.stringify(record.ciphertext));

        try {
            verified = peerSignKeyPub.verify(payloadCiphertextHash, record.signature);
        } catch (e) {
            console.error(e);
        }

        if (!verified) {
            return callback('Record signature does not match expected signature');
        }

        var payload = {};
        //var payload;
        try {
            var dec = sjcl.decrypt(sessionKey, record.ciphertext, crypton.cipherOptions);
            window.performance.mark('start decrypt');
            if (typeof(dec) === "string") {
                payload = JSON.parse(dec);
            } else { // ArrayBuffer (when encrypted with CCM and as ArrayBuffer)
                payload.delta = {};
                payload.delta.chunks = [];
                var o = {};

				var separationOffset = 10;
                var metadataStart;
                var newArray = new Uint8Array(dec);
                for (var j = newArray.length; j >= 0; j--) {
                	if (newArray[j] == 0) {
						var separator = newArray.slice(j-separationOffset+1, j+1)
						if (separator.join() === new Uint8Array(separationOffset).join()) {
							metadataStart = j + 1;
							break;	
						}
                	}
				}
				payload.delta.metadata = [];
				var metaString = String.fromCharCode.apply(null, newArray.slice(metadataStart));
				var metaObj = JSON.parse(metaString);
				payload.delta.metadata.push(metaObj);
                
                var chunksDec = dec.slice(0, metadataStart - separationOffset);
                var chunksNum = parseInt(chunksDec.byteLength / e2ee.crypto.chunkSize) + 1;
                var startChunk = 0;
                for (var i = 0; i < chunksNum; i++) {
                    var min = Math.min(startChunk + e2ee.crypto.chunkSize, chunksDec.byteLength);
                    var chunk = new Uint8Array(chunksDec.slice(startChunk, min));
                    o[startChunk] = chunk;
                    startChunk += e2ee.crypto.chunkSize;
                }
                payload.delta.chunks.push(o);
            }
            window.performance.mark('end decrypt');

            window.performance.measure('decrypt', 'start decrypt', 'end decrypt')
            window.performance.measure('conversion', 'start conversion', 'end conversion')
            window.performance.measure('hashing', 'start hash', 'end hash')
            var items = window.performance.getEntriesByType('measure')
            for (var i = 0; i < items.length; ++i) {
                var req = items[i]
                console.log(req.name + ' took ' + req.duration + 'ms')
            }
            window.performance.clearMarks()
            window.performance.clearMeasures()
        } catch (e) {
            if (window.console && window.console.log) {
                console.info(e)
            }
        }

        if (!payload) {
            return callback('Could not parse record payload');
        }

        if (payload.recordIndex !== expectedRecordIndex) {
            // TODO revisit
            // XXX ecto 3/4/14 I ran into a problem with this quite a while
            // ago where recordIndexes would never match even if they obviously
            // should. It smelled like an off-by-one or state error.
            // Now that record decryption is abstracted outside container instances,
            // we will have to do it in a different way anyway
            // (there was formerly a this.recordIndex++ here)

            // return callback('Record index mismatch');
        }

        callback(null, {
            time: +new Date(creationTime),
            delta: payload.delta
        });
    };

})();

/* Crypton Client, Copyright 2014 SpiderOak, Inc.
 *
 * This file is part of Crypton Client.
 *
 * Crypton Client is free software: you can redistribute it and/or modify it
 * under the terms of the Affero GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Crypton Client is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the Affero GNU General Public
 * License for more details.
 *
 * You should have received a copy of the Affero GNU General Public License
 * along with Crypton Client.  If not, see <http://www.gnu.org/licenses/>.
 */

(function() {

    'use strict';

    /**!
     * # Card
     *
     * ````
     * var  = new crypton.Card();
     * ````
     */
    var Card = crypton.Card = function Card() {};

    /**!
     * ### createIdCard(fingerprint, username, appname, domId)
     *
     * returns canvas element
     *
     * @param {String} fingerprint
     * @param {String} username
     * @param {String} appname
     * @param {String} url [optional]
     *                 The application homepage
     * @param {String} domId [optional]
     */
    Card.prototype.createIdCard =
        function(fingerprint, username, appname, url, domId) {
            if (!domId) {
                domId = 'id-card';
            }
            if (!url) {
                url = '';
            }

            var fingerArr = this.createFingerprintArr(fingerprint);
            var colorArr = this.createColorArr(fingerArr);

            var canvas = document.createElement('canvas');
            canvas.width = 420;
            canvas.height = 420;
            canvas.setAttribute('id', domId);

            var ctx = canvas.getContext("2d");
            var x = 5;
            var y = 5;
            var w = 50;
            var h = 50;

            ctx.fillStyle = "white";
            ctx.fillRect(0, 0, 420, 420);
            ctx.fillStyle = "black";
            y = y + 20;
            ctx.font = "bold 24px sans-serif";
            ctx.fillText(username, x, y);

            y = y + 30;
            ctx.font = "bold 18px sans-serif";
            ctx.fillText(appname, x, y);

            y = y + 30;
            ctx.font = "bold 24px sans-serif";
            ctx.fillText('FINGERPRINT', x, y);
            ctx.font = "24px sans-serif";

            var i = 0;
            var line = '';

            for (var j = 0; j < fingerArr.length; j++) {
                if (i == 3) {
                    line = line + fingerArr[j];
                    y = (y + 25);
                    ctx.fillText(line, x, y);
                    i = 0;
                    line = '';
                } else {
                    line = line + fingerArr[j] + ' ';
                    i++;
                }
            }

            y = y + 20;

            var identigridCanvas = this.createIdentigrid(colorArr);
            ctx.drawImage(identigridCanvas, x, y);

            var qrCodeCanvas = this.createQRCode(fingerArr, username, appname, url);
            ctx.drawImage(qrCodeCanvas, 210, 205);

            return canvas;
        };

    /**!
     * ### createQRCode(fingerprint, username, appname, url)
     *
     * returns canvas element
     *
     * @param {Array} fingerArr
     * @param {String} username
     * @param {String} appname
     * @param {String} url
     */
    Card.prototype.createQRCode = function(fingerArr, username, appname, url) {

        // generate QRCode
        var qrData = this.generateQRCodeInput(fingerArr.join(" "), username, appname, url);
        var qrCanvas = document.createElement('canvas');
        qrCanvas.width = 200;
        qrCanvas.height = 200;

        new QRCode(qrCanvas, {
            text: qrData,
            width: 200,
            height: 200,
            colorDark: "#000000",
            colorLight: "#ffffff",
            correctLevel: QRCode.CorrectLevel.H
        });
        // XXXddahl: QRCode wraps the canvas in another one
        return qrCanvas.childNodes[0];
    };

    /**!
     * ### createIdentigrid(fingerprint, username, appname)
     *
     * returns canvas element
     *
     * @param {Array} colorArr
     */
    Card.prototype.createIdentigrid = function(colorArr) {
        var canvas = document.createElement('canvas');
        canvas.width = 200;
        canvas.height = 200;
        var ctx = canvas.getContext('2d');
        var x = 0;
        var y = 0;
        var w = 50;
        var h = 50;

        for (var idx in colorArr) {
            ctx.fillStyle = colorArr[idx];
            ctx.fillRect(x, y, w, h);
            x = (x + 50);
            if (x == 200) {
                x = 0;
                y = (y + 50);
            }
        }

        return canvas;
    };

    /**!
     * ### createColorArr(fingerprint)
     *
     * returns Array
     *
     * @param {String} fingerArr
     */
    Card.prototype.createColorArr = function(fingerArr) {
        // pad the value out to 6 digits:
        var count = 0;
        var paddingData = fingerArr.join('');
        var colorArr = [];
        var REQUIRED_LENGTH = 6;
        for (var idx in fingerArr) {
            var pad = (REQUIRED_LENGTH - fingerArr[idx].length);
            if (pad == 0) {
                colorArr.push('#' + fingerArr[idx]);
            } else {
                var color = '#' + fingerArr[idx];
                for (var i = 0; i < pad; i++) {
                    color = color + paddingData[count];
                    count++;
                }
                colorArr.push(color);
            }
        }
        return colorArr;
    };

    /**!
     * ### createFingerprintArr(fingerprint)
     *
     * returns Array
     *
     * @param {String} fingerprint
     */
    Card.prototype.createFingerprintArr = function(fingerprint) {
        if (fingerprint.length != 64) {
            var err = 'Fingerprint has incorrect length';
            console.error(err);
            throw new Error(err);
        }
        fingerprint = fingerprint.toUpperCase();
        var fingerArr = [];
        var i = 0;
        var segment = '';
        for (var chr in fingerprint) {
            segment = segment + fingerprint[chr];
            i++;
            if (i == 4) {
                fingerArr.push(segment);
                i = 0;
                segment = '';
                continue;
            }
        }
        return fingerArr;
    };

    /**!
     * ### generateQRCodeInput(fingerprint, username, application, url)
     *
     * returns Array
     *
     * @param {String} fingerprint
     */
    Card.prototype.generateQRCodeInput = function(fingerprint, username, application, url) {
        if (!url) {
            url = '';
        }
        var json = JSON.stringify({
            fingerprint: fingerprint,
            username: username,
            application: application,
            url: url
        });
        return json;
    };

}());
/* Crypton Client, Copyright 2015 SpiderOak, Inc.
 *
 * This file is part of Crypton Client.
 *
 * Crypton Client is free software: you can redistribute it and/or modify it
 * under the terms of the Affero GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Crypton Client is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the Affero GNU General Public
 * License for more details.
 *
 * You should have received a copy of the Affero GNU General Public License
 * along with Crypton Client.  If not, see <http://www.gnu.org/licenses/>.
 */

(function() {

    'use strict';

    function Errors() {};

    Errors.prototype = {
        // Crypton system error strings
        ARG_MISSING_CALLBACK: 'Callback argument is required',
        ARG_MISSING_STRING: 'String argument is required',
        ARG_MISSING_OBJECT: 'Object argument is required',
        ARG_MISSING: 'Missing required argument',
        PROPERTY_MISSING: 'Missing object property',
        UNWRAP_KEY_ERROR: 'Cannot unwrap session key',
        DECRYPT_CIPHERTEXT_ERROR: 'Cannot decrypt ciphertext',
        UPDATE_PERMISSION_ERROR: 'Update permission denied',
        LOCAL_ITEM_MISSING: 'Cannot delete local Item, not currently cached',
        PEER_MESSAGE_SEND_FAILED: 'Cannot send message to peer'
    };

    crypton.errors = new Errors();

})();
/*global setImmediate: false, setTimeout: false, console: false */
(function() {

    var async = {};

    // global on the server, window in the browser
    var root, previous_async;

    root = this;
    if (root != null) {
        previous_async = root.async;
    }

    async.noConflict = function() {
        root.async = previous_async;
        return async;
    };

    function only_once(fn) {
        var called = false;
        return function() {
            if (called) throw new Error("Callback was already called.");
            called = true;
            fn.apply(root, arguments);
        }
    }

    //// cross-browser compatiblity functions ////

    var _each = function(arr, iterator) {
        if (arr.forEach) {
            return arr.forEach(iterator);
        }
        for (var i = 0; i < arr.length; i += 1) {
            iterator(arr[i], i, arr);
        }
    };

    var _map = function(arr, iterator) {
        if (arr.map) {
            return arr.map(iterator);
        }
        var results = [];
        _each(arr, function(x, i, a) {
            results.push(iterator(x, i, a));
        });
        return results;
    };

    var _reduce = function(arr, iterator, memo) {
        if (arr.reduce) {
            return arr.reduce(iterator, memo);
        }
        _each(arr, function(x, i, a) {
            memo = iterator(memo, x, i, a);
        });
        return memo;
    };

    var _keys = function(obj) {
        if (Object.keys) {
            return Object.keys(obj);
        }
        var keys = [];
        for (var k in obj) {
            if (obj.hasOwnProperty(k)) {
                keys.push(k);
            }
        }
        return keys;
    };

    //// exported async module functions ////

    //// nextTick implementation with browser-compatible fallback ////
    if (typeof process === 'undefined' || !(process.nextTick)) {
        if (typeof setImmediate === 'function') {
            async.nextTick = function(fn) {
                // not a direct alias for IE10 compatibility
                setImmediate(fn);
            };
            async.setImmediate = async.nextTick;
        } else {
            async.nextTick = function(fn) {
                setTimeout(fn, 0);
            };
            async.setImmediate = async.nextTick;
        }
    } else {
        async.nextTick = process.nextTick;
        if (typeof setImmediate !== 'undefined') {
            async.setImmediate = setImmediate;
        } else {
            async.setImmediate = async.nextTick;
        }
    }

    async.each = function(arr, iterator, callback) {
        callback = callback || function() {};
        if (!arr.length) {
            return callback();
        }
        var completed = 0;
        _each(arr, function(x) {
            iterator(x, only_once(function(err) {
                if (err) {
                    callback(err);
                    callback = function() {};
                } else {
                    completed += 1;
                    if (completed >= arr.length) {
                        callback(null);
                    }
                }
            }));
        });
    };
    async.forEach = async.each;

    async.eachSeries = function(arr, iterator, callback) {
        callback = callback || function() {};
        if (!arr.length) {
            return callback();
        }
        var completed = 0;
        var iterate = function() {
            iterator(arr[completed], function(err) {
                if (err) {
                    callback(err);
                    callback = function() {};
                } else {
                    completed += 1;
                    if (completed >= arr.length) {
                        callback(null);
                    } else {
                        iterate();
                    }
                }
            });
        };
        iterate();
    };
    async.forEachSeries = async.eachSeries;

    async.eachLimit = function(arr, limit, iterator, callback) {
        var fn = _eachLimit(limit);
        fn.apply(null, [arr, iterator, callback]);
    };
    async.forEachLimit = async.eachLimit;

    var _eachLimit = function(limit) {

        return function(arr, iterator, callback) {
            callback = callback || function() {};
            if (!arr.length || limit <= 0) {
                return callback();
            }
            var completed = 0;
            var started = 0;
            var running = 0;

            (function replenish() {
                if (completed >= arr.length) {
                    return callback();
                }

                while (running < limit && started < arr.length) {
                    started += 1;
                    running += 1;
                    iterator(arr[started - 1], function(err) {
                        if (err) {
                            callback(err);
                            callback = function() {};
                        } else {
                            completed += 1;
                            running -= 1;
                            if (completed >= arr.length) {
                                callback();
                            } else {
                                replenish();
                            }
                        }
                    });
                }
            })();
        };
    };


    var doParallel = function(fn) {
        return function() {
            var args = Array.prototype.slice.call(arguments);
            return fn.apply(null, [async.each].concat(args));
        };
    };
    var doParallelLimit = function(limit, fn) {
        return function() {
            var args = Array.prototype.slice.call(arguments);
            return fn.apply(null, [_eachLimit(limit)].concat(args));
        };
    };
    var doSeries = function(fn) {
        return function() {
            var args = Array.prototype.slice.call(arguments);
            return fn.apply(null, [async.eachSeries].concat(args));
        };
    };


    var _asyncMap = function(eachfn, arr, iterator, callback) {
        var results = [];
        arr = _map(arr, function(x, i) {
            return {
                index: i,
                value: x
            };
        });
        eachfn(arr, function(x, callback) {
            iterator(x.value, function(err, v) {
                results[x.index] = v;
                callback(err);
            });
        }, function(err) {
            callback(err, results);
        });
    };
    async.map = doParallel(_asyncMap);
    async.mapSeries = doSeries(_asyncMap);
    async.mapLimit = function(arr, limit, iterator, callback) {
        return _mapLimit(limit)(arr, iterator, callback);
    };

    var _mapLimit = function(limit) {
        return doParallelLimit(limit, _asyncMap);
    };

    // reduce only has a series version, as doing reduce in parallel won't
    // work in many situations.
    async.reduce = function(arr, memo, iterator, callback) {
        async.eachSeries(arr, function(x, callback) {
            iterator(memo, x, function(err, v) {
                memo = v;
                callback(err);
            });
        }, function(err) {
            callback(err, memo);
        });
    };
    // inject alias
    async.inject = async.reduce;
    // foldl alias
    async.foldl = async.reduce;

    async.reduceRight = function(arr, memo, iterator, callback) {
        var reversed = _map(arr, function(x) {
            return x;
        }).reverse();
        async.reduce(reversed, memo, iterator, callback);
    };
    // foldr alias
    async.foldr = async.reduceRight;

    var _filter = function(eachfn, arr, iterator, callback) {
        var results = [];
        arr = _map(arr, function(x, i) {
            return {
                index: i,
                value: x
            };
        });
        eachfn(arr, function(x, callback) {
            iterator(x.value, function(v) {
                if (v) {
                    results.push(x);
                }
                callback();
            });
        }, function(err) {
            callback(_map(results.sort(function(a, b) {
                return a.index - b.index;
            }), function(x) {
                return x.value;
            }));
        });
    };
    async.filter = doParallel(_filter);
    async.filterSeries = doSeries(_filter);
    // select alias
    async.select = async.filter;
    async.selectSeries = async.filterSeries;

    var _reject = function(eachfn, arr, iterator, callback) {
        var results = [];
        arr = _map(arr, function(x, i) {
            return {
                index: i,
                value: x
            };
        });
        eachfn(arr, function(x, callback) {
            iterator(x.value, function(v) {
                if (!v) {
                    results.push(x);
                }
                callback();
            });
        }, function(err) {
            callback(_map(results.sort(function(a, b) {
                return a.index - b.index;
            }), function(x) {
                return x.value;
            }));
        });
    };
    async.reject = doParallel(_reject);
    async.rejectSeries = doSeries(_reject);

    var _detect = function(eachfn, arr, iterator, main_callback) {
        eachfn(arr, function(x, callback) {
            iterator(x, function(result) {
                if (result) {
                    main_callback(x);
                    main_callback = function() {};
                } else {
                    callback();
                }
            });
        }, function(err) {
            main_callback();
        });
    };
    async.detect = doParallel(_detect);
    async.detectSeries = doSeries(_detect);

    async.some = function(arr, iterator, main_callback) {
        async.each(arr, function(x, callback) {
            iterator(x, function(v) {
                if (v) {
                    main_callback(true);
                    main_callback = function() {};
                }
                callback();
            });
        }, function(err) {
            main_callback(false);
        });
    };
    // any alias
    async.any = async.some;

    async.every = function(arr, iterator, main_callback) {
        async.each(arr, function(x, callback) {
            iterator(x, function(v) {
                if (!v) {
                    main_callback(false);
                    main_callback = function() {};
                }
                callback();
            });
        }, function(err) {
            main_callback(true);
        });
    };
    // all alias
    async.all = async.every;

    async.sortBy = function(arr, iterator, callback) {
        async.map(arr, function(x, callback) {
            iterator(x, function(err, criteria) {
                if (err) {
                    callback(err);
                } else {
                    callback(null, {
                        value: x,
                        criteria: criteria
                    });
                }
            });
        }, function(err, results) {
            if (err) {
                return callback(err);
            } else {
                var fn = function(left, right) {
                    var a = left.criteria,
                        b = right.criteria;
                    return a < b ? -1 : a > b ? 1 : 0;
                };
                callback(null, _map(results.sort(fn), function(x) {
                    return x.value;
                }));
            }
        });
    };

    async.auto = function(tasks, callback) {
        callback = callback || function() {};
        var keys = _keys(tasks);
        if (!keys.length) {
            return callback(null);
        }

        var results = {};

        var listeners = [];
        var addListener = function(fn) {
            listeners.unshift(fn);
        };
        var removeListener = function(fn) {
            for (var i = 0; i < listeners.length; i += 1) {
                if (listeners[i] === fn) {
                    listeners.splice(i, 1);
                    return;
                }
            }
        };
        var taskComplete = function() {
            _each(listeners.slice(0), function(fn) {
                fn();
            });
        };

        addListener(function() {
            if (_keys(results).length === keys.length) {
                callback(null, results);
                callback = function() {};
            }
        });

        _each(keys, function(k) {
            var task = (tasks[k] instanceof Function) ? [tasks[k]] : tasks[k];
            var taskCallback = function(err) {
                var args = Array.prototype.slice.call(arguments, 1);
                if (args.length <= 1) {
                    args = args[0];
                }
                if (err) {
                    var safeResults = {};
                    _each(_keys(results), function(rkey) {
                        safeResults[rkey] = results[rkey];
                    });
                    safeResults[k] = args;
                    callback(err, safeResults);
                    // stop subsequent errors hitting callback multiple times
                    callback = function() {};
                } else {
                    results[k] = args;
                    async.setImmediate(taskComplete);
                }
            };
            var requires = task.slice(0, Math.abs(task.length - 1)) || [];
            var ready = function() {
                return _reduce(requires, function(a, x) {
                    return (a && results.hasOwnProperty(x));
                }, true) && !results.hasOwnProperty(k);
            };
            if (ready()) {
                task[task.length - 1](taskCallback, results);
            } else {
                var listener = function() {
                    if (ready()) {
                        removeListener(listener);
                        task[task.length - 1](taskCallback, results);
                    }
                };
                addListener(listener);
            }
        });
    };

    async.waterfall = function(tasks, callback) {
        callback = callback || function() {};
        if (tasks.constructor !== Array) {
            var err = new Error('First argument to waterfall must be an array of functions');
            return callback(err);
        }
        if (!tasks.length) {
            return callback();
        }
        var wrapIterator = function(iterator) {
            return function(err) {
                if (err) {
                    callback.apply(null, arguments);
                    callback = function() {};
                } else {
                    var args = Array.prototype.slice.call(arguments, 1);
                    var next = iterator.next();
                    if (next) {
                        args.push(wrapIterator(next));
                    } else {
                        args.push(callback);
                    }
                    async.setImmediate(function() {
                        iterator.apply(null, args);
                    });
                }
            };
        };
        wrapIterator(async.iterator(tasks))();
    };

    var _parallel = function(eachfn, tasks, callback) {
        callback = callback || function() {};
        if (tasks.constructor === Array) {
            eachfn.map(tasks, function(fn, callback) {
                if (fn) {
                    fn(function(err) {
                        var args = Array.prototype.slice.call(arguments, 1);
                        if (args.length <= 1) {
                            args = args[0];
                        }
                        callback.call(null, err, args);
                    });
                }
            }, callback);
        } else {
            var results = {};
            eachfn.each(_keys(tasks), function(k, callback) {
                tasks[k](function(err) {
                    var args = Array.prototype.slice.call(arguments, 1);
                    if (args.length <= 1) {
                        args = args[0];
                    }
                    results[k] = args;
                    callback(err);
                });
            }, function(err) {
                callback(err, results);
            });
        }
    };

    async.parallel = function(tasks, callback) {
        _parallel({
            map: async.map,
            each: async.each
        }, tasks, callback);
    };

    async.parallelLimit = function(tasks, limit, callback) {
        _parallel({
            map: _mapLimit(limit),
            each: _eachLimit(limit)
        }, tasks, callback);
    };

    async.series = function(tasks, callback) {
        callback = callback || function() {};
        if (tasks.constructor === Array) {
            async.mapSeries(tasks, function(fn, callback) {
                if (fn) {
                    fn(function(err) {
                        var args = Array.prototype.slice.call(arguments, 1);
                        if (args.length <= 1) {
                            args = args[0];
                        }
                        callback.call(null, err, args);
                    });
                }
            }, callback);
        } else {
            var results = {};
            async.eachSeries(_keys(tasks), function(k, callback) {
                tasks[k](function(err) {
                    var args = Array.prototype.slice.call(arguments, 1);
                    if (args.length <= 1) {
                        args = args[0];
                    }
                    results[k] = args;
                    callback(err);
                });
            }, function(err) {
                callback(err, results);
            });
        }
    };

    async.iterator = function(tasks) {
        var makeCallback = function(index) {
            var fn = function() {
                if (tasks.length) {
                    tasks[index].apply(null, arguments);
                }
                return fn.next();
            };
            fn.next = function() {
                return (index < tasks.length - 1) ? makeCallback(index + 1) : null;
            };
            return fn;
        };
        return makeCallback(0);
    };

    async.apply = function(fn) {
        var args = Array.prototype.slice.call(arguments, 1);
        return function() {
            return fn.apply(
                null, args.concat(Array.prototype.slice.call(arguments))
            );
        };
    };

    var _concat = function(eachfn, arr, fn, callback) {
        var r = [];
        eachfn(arr, function(x, cb) {
            fn(x, function(err, y) {
                r = r.concat(y || []);
                cb(err);
            });
        }, function(err) {
            callback(err, r);
        });
    };
    async.concat = doParallel(_concat);
    async.concatSeries = doSeries(_concat);

    async.whilst = function(test, iterator, callback) {
        if (test()) {
            iterator(function(err) {
                if (err) {
                    return callback(err);
                }
                async.whilst(test, iterator, callback);
            });
        } else {
            callback();
        }
    };

    async.doWhilst = function(iterator, test, callback) {
        iterator(function(err) {
            if (err) {
                return callback(err);
            }
            if (test()) {
                async.doWhilst(iterator, test, callback);
            } else {
                callback();
            }
        });
    };

    async.until = function(test, iterator, callback) {
        if (!test()) {
            iterator(function(err) {
                if (err) {
                    return callback(err);
                }
                async.until(test, iterator, callback);
            });
        } else {
            callback();
        }
    };

    async.doUntil = function(iterator, test, callback) {
        iterator(function(err) {
            if (err) {
                return callback(err);
            }
            if (!test()) {
                async.doUntil(iterator, test, callback);
            } else {
                callback();
            }
        });
    };

    async.queue = function(worker, concurrency) {
        if (concurrency === undefined) {
            concurrency = 1;
        }

        function _insert(q, data, pos, callback) {
            if (data.constructor !== Array) {
                data = [data];
            }
            _each(data, function(task) {
                var item = {
                    data: task,
                    callback: typeof callback === 'function' ? callback : null
                };

                if (pos) {
                    q.tasks.unshift(item);
                } else {
                    q.tasks.push(item);
                }

                if (q.saturated && q.tasks.length === concurrency) {
                    q.saturated();
                }
                async.setImmediate(q.process);
            });
        }

        var workers = 0;
        var q = {
            tasks: [],
            concurrency: concurrency,
            saturated: null,
            empty: null,
            drain: null,
            push: function(data, callback) {
                _insert(q, data, false, callback);
            },
            unshift: function(data, callback) {
                _insert(q, data, true, callback);
            },
            process: function() {
                if (workers < q.concurrency && q.tasks.length) {
                    var task = q.tasks.shift();
                    if (q.empty && q.tasks.length === 0) {
                        q.empty();
                    }
                    workers += 1;
                    var next = function() {
                        workers -= 1;
                        if (task.callback) {
                            task.callback.apply(task, arguments);
                        }
                        if (q.drain && q.tasks.length + workers === 0) {
                            q.drain();
                        }
                        q.process();
                    };
                    var cb = only_once(next);
                    worker(task.data, cb);
                }
            },
            length: function() {
                return q.tasks.length;
            },
            running: function() {
                return workers;
            }
        };
        return q;
    };

    async.cargo = function(worker, payload) {
        var working = false,
            tasks = [];

        var cargo = {
            tasks: tasks,
            payload: payload,
            saturated: null,
            empty: null,
            drain: null,
            push: function(data, callback) {
                if (data.constructor !== Array) {
                    data = [data];
                }
                _each(data, function(task) {
                    tasks.push({
                        data: task,
                        callback: typeof callback === 'function' ? callback : null
                    });
                    if (cargo.saturated && tasks.length === payload) {
                        cargo.saturated();
                    }
                });
                async.setImmediate(cargo.process);
            },
            process: function process() {
                if (working) return;
                if (tasks.length === 0) {
                    if (cargo.drain) cargo.drain();
                    return;
                }

                var ts = typeof payload === 'number' ? tasks.splice(0, payload) : tasks.splice(0);

                var ds = _map(ts, function(task) {
                    return task.data;
                });

                if (cargo.empty) cargo.empty();
                working = true;
                worker(ds, function() {
                    working = false;

                    var args = arguments;
                    _each(ts, function(data) {
                        if (data.callback) {
                            data.callback.apply(null, args);
                        }
                    });

                    process();
                });
            },
            length: function() {
                return tasks.length;
            },
            running: function() {
                return working;
            }
        };
        return cargo;
    };

    var _console_fn = function(name) {
        return function(fn) {
            var args = Array.prototype.slice.call(arguments, 1);
            fn.apply(null, args.concat([function(err) {
                var args = Array.prototype.slice.call(arguments, 1);
                if (typeof console !== 'undefined') {
                    if (err) {
                        if (console.error) {
                            console.error(err);
                        }
                    } else if (console[name]) {
                        _each(args, function(x) {
                            console[name](x);
                        });
                    }
                }
            }]));
        };
    };
    async.log = _console_fn('log');
    async.dir = _console_fn('dir');
    /*async.info = _console_fn('info');
    async.warn = _console_fn('warn');
    async.error = _console_fn('error');*/

    async.memoize = function(fn, hasher) {
        var memo = {};
        var queues = {};
        hasher = hasher || function(x) {
            return x;
        };
        var memoized = function() {
            var args = Array.prototype.slice.call(arguments);
            var callback = args.pop();
            var key = hasher.apply(null, args);
            if (key in memo) {
                callback.apply(null, memo[key]);
            } else if (key in queues) {
                queues[key].push(callback);
            } else {
                queues[key] = [callback];
                fn.apply(null, args.concat([function() {
                    memo[key] = arguments;
                    var q = queues[key];
                    delete queues[key];
                    for (var i = 0, l = q.length; i < l; i++) {
                        q[i].apply(null, arguments);
                    }
                }]));
            }
        };
        memoized.memo = memo;
        memoized.unmemoized = fn;
        return memoized;
    };

    async.unmemoize = function(fn) {
        return function() {
            return (fn.unmemoized || fn).apply(null, arguments);
        };
    };

    async.times = function(count, iterator, callback) {
        var counter = [];
        for (var i = 0; i < count; i++) {
            counter.push(i);
        }
        return async.map(counter, iterator, callback);
    };

    async.timesSeries = function(count, iterator, callback) {
        var counter = [];
        for (var i = 0; i < count; i++) {
            counter.push(i);
        }
        return async.mapSeries(counter, iterator, callback);
    };

    async.compose = function( /* functions... */ ) {
        var fns = Array.prototype.reverse.call(arguments);
        return function() {
            var that = this;
            var args = Array.prototype.slice.call(arguments);
            var callback = args.pop();
            async.reduce(fns, args, function(newargs, fn, cb) {
                    fn.apply(that, newargs.concat([function() {
                        var err = arguments[0];
                        var nextargs = Array.prototype.slice.call(arguments, 1);
                        cb(err, nextargs);
                    }]))
                },
                function(err, results) {
                    callback.apply(that, [err].concat(results));
                });
        };
    };

    var _applyEach = function(eachfn, fns /*args...*/ ) {
        var go = function() {
            var that = this;
            var args = Array.prototype.slice.call(arguments);
            var callback = args.pop();
            return eachfn(fns, function(fn, cb) {
                    fn.apply(that, args.concat([cb]));
                },
                callback);
        };
        if (arguments.length > 2) {
            var args = Array.prototype.slice.call(arguments, 2);
            return go.apply(this, args);
        } else {
            return go;
        }
    };
    async.applyEach = doParallel(_applyEach);
    async.applyEachSeries = doSeries(_applyEach);

    async.forever = function(fn, callback) {
        function next(err) {
            if (err) {
                if (callback) {
                    return callback(err);
                }
                throw err;
            }
            fn(next);
        }
        next();
    };

    // AMD / RequireJS
    if (typeof define !== 'undefined' && define.amd) {
        define([], function() {
            return async;
        });
    }
    // Node.js
    else if (typeof module !== 'undefined' && module.exports) {
        module.exports = async;
    }
    // included directly via <script> tag
    else {
        root.async = async;
    }

}());
/*
 Copyright (c) 2012 Nevins Bartolomeo <nevins.bartolomeo@gmail.com>
 Copyright (c) 2012 Shane Girish <shaneGirish@gmail.com>
 Copyright (c) 2013 Daniel Wirtz <dcode@dcode.io>

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 1. Redistributions of source code must retain the above copyright
 notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
 notice, this list of conditions and the following disclaimer in the
 documentation and/or other materials provided with the distribution.
 3. The name of the author may not be used to endorse or promote products
 derived from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @license bcrypt.js (c) 2013 Daniel Wirtz <dcode@dcode.io>
 * Released under the Apache License, Version 2.0
 * see: https://github.com/dcodeIO/bcrypt.js for details
 */
(function(global) {

    /**
     * @type {Array.<string>}
     * @const
     * @private
     **/
    var BASE64_CODE = ['.', '/', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
        'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
        'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
        'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8',
        '9'
    ];

    /**
     * @type {Array.<number>}
     * @const
     * @private
     **/
    var BASE64_INDEX = [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 1,
        54, 55, 56, 57, 58, 59, 60, 61, 62, 63, -1, -1, -1, -1, -1, -1, -1,
        2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        21, 22, 23, 24, 25, 26, 27, -1, -1, -1, -1, -1, -1, 28, 29, 30, 31,
        32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
        49, 50, 51, 52, 53, -1, -1, -1, -1, -1
    ];

    /**
     * Length-delimited base64 encoder and decoder.
     * @type {Object.<string,function(string, number)>}
     * @private
     */
    var base64 = {};

    /**
     * Encodes a byte array to base64 with up to len bytes of input.
     * @param {Array.<number>} b Byte array
     * @param {number} len Maximum input length
     * @returns {string}
     * @private
     */
    base64.encode = function(b, len) {
        var off = 0;
        var rs = [];
        var c1;
        var c2;
        if (len <= 0 || len > b.length) {
            throw (new Error("Invalid 'len': " + len));
        }
        while (off < len) {
            c1 = b[off++] & 0xff;
            rs.push(BASE64_CODE[(c1 >> 2) & 0x3f]);
            c1 = (c1 & 0x03) << 4;
            if (off >= len) {
                rs.push(BASE64_CODE[c1 & 0x3f]);
                break;
            }
            c2 = b[off++] & 0xff;
            c1 |= (c2 >> 4) & 0x0f;
            rs.push(BASE64_CODE[c1 & 0x3f]);
            c1 = (c2 & 0x0f) << 2;
            if (off >= len) {
                rs.push(BASE64_CODE[c1 & 0x3f]);
                break;
            }
            c2 = b[off++] & 0xff;
            c1 |= (c2 >> 6) & 0x03;
            rs.push(BASE64_CODE[c1 & 0x3f]);
            rs.push(BASE64_CODE[c2 & 0x3f]);
        }
        return rs.join('');
    };

    /**
     * Decodes a base64 encoded string to up to len bytes of output.
     * @param {string} s String to decode
     * @param {number} len Maximum output length
     * @returns {Array.<number>}
     * @private
     */
    base64.decode = function(s, len) {
        var off = 0;
        var slen = s.length;
        var olen = 0;
        var rs = [];
        var c1, c2, c3, c4, o, code;
        if (len <= 0) throw (new Error("Illegal 'len': " + len));
        while (off < slen - 1 && olen < len) {
            code = s.charCodeAt(off++);
            c1 = code < BASE64_INDEX.length ? BASE64_INDEX[code] : -1;
            code = s.charCodeAt(off++);
            c2 = code < BASE64_INDEX.length ? BASE64_INDEX[code] : -1;
            if (c1 == -1 || c2 == -1) {
                break;
            }
            o = (c1 << 2) >>> 0;
            o |= (c2 & 0x30) >> 4;
            rs.push(String.fromCharCode(o));
            if (++olen >= len || off >= slen) {
                break;
            }
            code = s.charCodeAt(off++);
            c3 = code < BASE64_INDEX.length ? BASE64_INDEX[code] : -1;
            if (c3 == -1) {
                break;
            }
            o = ((c2 & 0x0f) << 4) >>> 0;
            o |= (c3 & 0x3c) >> 2;
            rs.push(String.fromCharCode(o));
            if (++olen >= len || off >= slen) {
                break;
            }
            code = s.charCodeAt(off++);
            c4 = code < BASE64_INDEX.length ? BASE64_INDEX[code] : -1;
            o = ((c3 & 0x03) << 6) >>> 0;
            o |= c4;
            rs.push(String.fromCharCode(o));
            ++olen;
        }
        var res = [];
        for (off = 0; off < olen; off++) {
            res.push(rs[off].charCodeAt(0));
        }
        return res;
    };
    /**
     * bcrypt namespace.
     * @type {Object.<string,*>}
     */
    var bcrypt = {};

    /**
     * @type {number}
     * @const
     * @private
     */
    var BCRYPT_SALT_LEN = 16;

    /**
     * @type {number}
     * @const
     * @private
     */
    var GENSALT_DEFAULT_LOG2_ROUNDS = 10;

    /**
     * @type {number}
     * @const
     * @private
     */
    var BLOWFISH_NUM_ROUNDS = 16;

    /**
     * @type {number}
     * @const
     * @private
     */
    var MAX_EXECUTION_TIME = 100;

    /**
     * @type {Array.<number>}
     * @const
     * @private
     */
    var P_ORIG = [
        0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822,
        0x299f31d0, 0x082efa98, 0xec4e6c89, 0x452821e6, 0x38d01377,
        0xbe5466cf, 0x34e90c6c, 0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5,
        0xb5470917, 0x9216d5d9, 0x8979fb1b
    ];

    /**
     * @type {Array.<number>}
     * @const
     * @private
     */
    var S_ORIG = [
        0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7, 0xb8e1afed,
        0x6a267e96, 0xba7c9045, 0xf12c7f99, 0x24a19947, 0xb3916cf7,
        0x0801f2e2, 0x858efc16, 0x636920d8, 0x71574e69, 0xa458fea3,
        0xf4933d7e, 0x0d95748f, 0x728eb658, 0x718bcd58, 0x82154aee,
        0x7b54a41d, 0xc25a59b5, 0x9c30d539, 0x2af26013, 0xc5d1b023,
        0x286085f0, 0xca417918, 0xb8db38ef, 0x8e79dcb0, 0x603a180e,
        0x6c9e0e8b, 0xb01e8a3e, 0xd71577c1, 0xbd314b27, 0x78af2fda,
        0x55605c60, 0xe65525f3, 0xaa55ab94, 0x57489862, 0x63e81440,
        0x55ca396a, 0x2aab10b6, 0xb4cc5c34, 0x1141e8ce, 0xa15486af,
        0x7c72e993, 0xb3ee1411, 0x636fbc2a, 0x2ba9c55d, 0x741831f6,
        0xce5c3e16, 0x9b87931e, 0xafd6ba33, 0x6c24cf5c, 0x7a325381,
        0x28958677, 0x3b8f4898, 0x6b4bb9af, 0xc4bfe81b, 0x66282193,
        0x61d809cc, 0xfb21a991, 0x487cac60, 0x5dec8032, 0xef845d5d,
        0xe98575b1, 0xdc262302, 0xeb651b88, 0x23893e81, 0xd396acc5,
        0x0f6d6ff3, 0x83f44239, 0x2e0b4482, 0xa4842004, 0x69c8f04a,
        0x9e1f9b5e, 0x21c66842, 0xf6e96c9a, 0x670c9c61, 0xabd388f0,
        0x6a51a0d2, 0xd8542f68, 0x960fa728, 0xab5133a3, 0x6eef0b6c,
        0x137a3be4, 0xba3bf050, 0x7efb2a98, 0xa1f1651d, 0x39af0176,
        0x66ca593e, 0x82430e88, 0x8cee8619, 0x456f9fb4, 0x7d84a5c3,
        0x3b8b5ebe, 0xe06f75d8, 0x85c12073, 0x401a449f, 0x56c16aa6,
        0x4ed3aa62, 0x363f7706, 0x1bfedf72, 0x429b023d, 0x37d0d724,
        0xd00a1248, 0xdb0fead3, 0x49f1c09b, 0x075372c9, 0x80991b7b,
        0x25d479d8, 0xf6e8def7, 0xe3fe501a, 0xb6794c3b, 0x976ce0bd,
        0x04c006ba, 0xc1a94fb6, 0x409f60c4, 0x5e5c9ec2, 0x196a2463,
        0x68fb6faf, 0x3e6c53b5, 0x1339b2eb, 0x3b52ec6f, 0x6dfc511f,
        0x9b30952c, 0xcc814544, 0xaf5ebd09, 0xbee3d004, 0xde334afd,
        0x660f2807, 0x192e4bb3, 0xc0cba857, 0x45c8740f, 0xd20b5f39,
        0xb9d3fbdb, 0x5579c0bd, 0x1a60320a, 0xd6a100c6, 0x402c7279,
        0x679f25fe, 0xfb1fa3cc, 0x8ea5e9f8, 0xdb3222f8, 0x3c7516df,
        0xfd616b15, 0x2f501ec8, 0xad0552ab, 0x323db5fa, 0xfd238760,
        0x53317b48, 0x3e00df82, 0x9e5c57bb, 0xca6f8ca0, 0x1a87562e,
        0xdf1769db, 0xd542a8f6, 0x287effc3, 0xac6732c6, 0x8c4f5573,
        0x695b27b0, 0xbbca58c8, 0xe1ffa35d, 0xb8f011a0, 0x10fa3d98,
        0xfd2183b8, 0x4afcb56c, 0x2dd1d35b, 0x9a53e479, 0xb6f84565,
        0xd28e49bc, 0x4bfb9790, 0xe1ddf2da, 0xa4cb7e33, 0x62fb1341,
        0xcee4c6e8, 0xef20cada, 0x36774c01, 0xd07e9efe, 0x2bf11fb4,
        0x95dbda4d, 0xae909198, 0xeaad8e71, 0x6b93d5a0, 0xd08ed1d0,
        0xafc725e0, 0x8e3c5b2f, 0x8e7594b7, 0x8ff6e2fb, 0xf2122b64,
        0x8888b812, 0x900df01c, 0x4fad5ea0, 0x688fc31c, 0xd1cff191,
        0xb3a8c1ad, 0x2f2f2218, 0xbe0e1777, 0xea752dfe, 0x8b021fa1,
        0xe5a0cc0f, 0xb56f74e8, 0x18acf3d6, 0xce89e299, 0xb4a84fe0,
        0xfd13e0b7, 0x7cc43b81, 0xd2ada8d9, 0x165fa266, 0x80957705,
        0x93cc7314, 0x211a1477, 0xe6ad2065, 0x77b5fa86, 0xc75442f5,
        0xfb9d35cf, 0xebcdaf0c, 0x7b3e89a0, 0xd6411bd3, 0xae1e7e49,
        0x00250e2d, 0x2071b35e, 0x226800bb, 0x57b8e0af, 0x2464369b,
        0xf009b91e, 0x5563911d, 0x59dfa6aa, 0x78c14389, 0xd95a537f,
        0x207d5ba2, 0x02e5b9c5, 0x83260376, 0x6295cfa9, 0x11c81968,
        0x4e734a41, 0xb3472dca, 0x7b14a94a, 0x1b510052, 0x9a532915,
        0xd60f573f, 0xbc9bc6e4, 0x2b60a476, 0x81e67400, 0x08ba6fb5,
        0x571be91f, 0xf296ec6b, 0x2a0dd915, 0xb6636521, 0xe7b9f9b6,
        0xff34052e, 0xc5855664, 0x53b02d5d, 0xa99f8fa1, 0x08ba4799,
        0x6e85076a, 0x4b7a70e9, 0xb5b32944, 0xdb75092e, 0xc4192623,
        0xad6ea6b0, 0x49a7df7d, 0x9cee60b8, 0x8fedb266, 0xecaa8c71,
        0x699a17ff, 0x5664526c, 0xc2b19ee1, 0x193602a5, 0x75094c29,
        0xa0591340, 0xe4183a3e, 0x3f54989a, 0x5b429d65, 0x6b8fe4d6,
        0x99f73fd6, 0xa1d29c07, 0xefe830f5, 0x4d2d38e6, 0xf0255dc1,
        0x4cdd2086, 0x8470eb26, 0x6382e9c6, 0x021ecc5e, 0x09686b3f,
        0x3ebaefc9, 0x3c971814, 0x6b6a70a1, 0x687f3584, 0x52a0e286,
        0xb79c5305, 0xaa500737, 0x3e07841c, 0x7fdeae5c, 0x8e7d44ec,
        0x5716f2b8, 0xb03ada37, 0xf0500c0d, 0xf01c1f04, 0x0200b3ff,
        0xae0cf51a, 0x3cb574b2, 0x25837a58, 0xdc0921bd, 0xd19113f9,
        0x7ca92ff6, 0x94324773, 0x22f54701, 0x3ae5e581, 0x37c2dadc,
        0xc8b57634, 0x9af3dda7, 0xa9446146, 0x0fd0030e, 0xecc8c73e,
        0xa4751e41, 0xe238cd99, 0x3bea0e2f, 0x3280bba1, 0x183eb331,
        0x4e548b38, 0x4f6db908, 0x6f420d03, 0xf60a04bf, 0x2cb81290,
        0x24977c79, 0x5679b072, 0xbcaf89af, 0xde9a771f, 0xd9930810,
        0xb38bae12, 0xdccf3f2e, 0x5512721f, 0x2e6b7124, 0x501adde6,
        0x9f84cd87, 0x7a584718, 0x7408da17, 0xbc9f9abc, 0xe94b7d8c,
        0xec7aec3a, 0xdb851dfa, 0x63094366, 0xc464c3d2, 0xef1c1847,
        0x3215d908, 0xdd433b37, 0x24c2ba16, 0x12a14d43, 0x2a65c451,
        0x50940002, 0x133ae4dd, 0x71dff89e, 0x10314e55, 0x81ac77d6,
        0x5f11199b, 0x043556f1, 0xd7a3c76b, 0x3c11183b, 0x5924a509,
        0xf28fe6ed, 0x97f1fbfa, 0x9ebabf2c, 0x1e153c6e, 0x86e34570,
        0xeae96fb1, 0x860e5e0a, 0x5a3e2ab3, 0x771fe71c, 0x4e3d06fa,
        0x2965dcb9, 0x99e71d0f, 0x803e89d6, 0x5266c825, 0x2e4cc978,
        0x9c10b36a, 0xc6150eba, 0x94e2ea78, 0xa5fc3c53, 0x1e0a2df4,
        0xf2f74ea7, 0x361d2b3d, 0x1939260f, 0x19c27960, 0x5223a708,
        0xf71312b6, 0xebadfe6e, 0xeac31f66, 0xe3bc4595, 0xa67bc883,
        0xb17f37d1, 0x018cff28, 0xc332ddef, 0xbe6c5aa5, 0x65582185,
        0x68ab9802, 0xeecea50f, 0xdb2f953b, 0x2aef7dad, 0x5b6e2f84,
        0x1521b628, 0x29076170, 0xecdd4775, 0x619f1510, 0x13cca830,
        0xeb61bd96, 0x0334fe1e, 0xaa0363cf, 0xb5735c90, 0x4c70a239,
        0xd59e9e0b, 0xcbaade14, 0xeecc86bc, 0x60622ca7, 0x9cab5cab,
        0xb2f3846e, 0x648b1eaf, 0x19bdf0ca, 0xa02369b9, 0x655abb50,
        0x40685a32, 0x3c2ab4b3, 0x319ee9d5, 0xc021b8f7, 0x9b540b19,
        0x875fa099, 0x95f7997e, 0x623d7da8, 0xf837889a, 0x97e32d77,
        0x11ed935f, 0x16681281, 0x0e358829, 0xc7e61fd6, 0x96dedfa1,
        0x7858ba99, 0x57f584a5, 0x1b227263, 0x9b83c3ff, 0x1ac24696,
        0xcdb30aeb, 0x532e3054, 0x8fd948e4, 0x6dbc3128, 0x58ebf2ef,
        0x34c6ffea, 0xfe28ed61, 0xee7c3c73, 0x5d4a14d9, 0xe864b7e3,
        0x42105d14, 0x203e13e0, 0x45eee2b6, 0xa3aaabea, 0xdb6c4f15,
        0xfacb4fd0, 0xc742f442, 0xef6abbb5, 0x654f3b1d, 0x41cd2105,
        0xd81e799e, 0x86854dc7, 0xe44b476a, 0x3d816250, 0xcf62a1f2,
        0x5b8d2646, 0xfc8883a0, 0xc1c7b6a3, 0x7f1524c3, 0x69cb7492,
        0x47848a0b, 0x5692b285, 0x095bbf00, 0xad19489d, 0x1462b174,
        0x23820e00, 0x58428d2a, 0x0c55f5ea, 0x1dadf43e, 0x233f7061,
        0x3372f092, 0x8d937e41, 0xd65fecf1, 0x6c223bdb, 0x7cde3759,
        0xcbee7460, 0x4085f2a7, 0xce77326e, 0xa6078084, 0x19f8509e,
        0xe8efd855, 0x61d99735, 0xa969a7aa, 0xc50c06c2, 0x5a04abfc,
        0x800bcadc, 0x9e447a2e, 0xc3453484, 0xfdd56705, 0x0e1e9ec9,
        0xdb73dbd3, 0x105588cd, 0x675fda79, 0xe3674340, 0xc5c43465,
        0x713e38d8, 0x3d28f89e, 0xf16dff20, 0x153e21e7, 0x8fb03d4a,
        0xe6e39f2b, 0xdb83adf7, 0xe93d5a68, 0x948140f7, 0xf64c261c,
        0x94692934, 0x411520f7, 0x7602d4f7, 0xbcf46b2e, 0xd4a20068,
        0xd4082471, 0x3320f46a, 0x43b7d4b7, 0x500061af, 0x1e39f62e,
        0x97244546, 0x14214f74, 0xbf8b8840, 0x4d95fc1d, 0x96b591af,
        0x70f4ddd3, 0x66a02f45, 0xbfbc09ec, 0x03bd9785, 0x7fac6dd0,
        0x31cb8504, 0x96eb27b3, 0x55fd3941, 0xda2547e6, 0xabca0a9a,
        0x28507825, 0x530429f4, 0x0a2c86da, 0xe9b66dfb, 0x68dc1462,
        0xd7486900, 0x680ec0a4, 0x27a18dee, 0x4f3ffea2, 0xe887ad8c,
        0xb58ce006, 0x7af4d6b6, 0xaace1e7c, 0xd3375fec, 0xce78a399,
        0x406b2a42, 0x20fe9e35, 0xd9f385b9, 0xee39d7ab, 0x3b124e8b,
        0x1dc9faf7, 0x4b6d1856, 0x26a36631, 0xeae397b2, 0x3a6efa74,
        0xdd5b4332, 0x6841e7f7, 0xca7820fb, 0xfb0af54e, 0xd8feb397,
        0x454056ac, 0xba489527, 0x55533a3a, 0x20838d87, 0xfe6ba9b7,
        0xd096954b, 0x55a867bc, 0xa1159a58, 0xcca92963, 0x99e1db33,
        0xa62a4a56, 0x3f3125f9, 0x5ef47e1c, 0x9029317c, 0xfdf8e802,
        0x04272f70, 0x80bb155c, 0x05282ce3, 0x95c11548, 0xe4c66d22,
        0x48c1133f, 0xc70f86dc, 0x07f9c9ee, 0x41041f0f, 0x404779a4,
        0x5d886e17, 0x325f51eb, 0xd59bc0d1, 0xf2bcc18f, 0x41113564,
        0x257b7834, 0x602a9c60, 0xdff8e8a3, 0x1f636c1b, 0x0e12b4c2,
        0x02e1329e, 0xaf664fd1, 0xcad18115, 0x6b2395e0, 0x333e92e1,
        0x3b240b62, 0xeebeb922, 0x85b2a20e, 0xe6ba0d99, 0xde720c8c,
        0x2da2f728, 0xd0127845, 0x95b794fd, 0x647d0862, 0xe7ccf5f0,
        0x5449a36f, 0x877d48fa, 0xc39dfd27, 0xf33e8d1e, 0x0a476341,
        0x992eff74, 0x3a6f6eab, 0xf4f8fd37, 0xa812dc60, 0xa1ebddf8,
        0x991be14c, 0xdb6e6b0d, 0xc67b5510, 0x6d672c37, 0x2765d43b,
        0xdcd0e804, 0xf1290dc7, 0xcc00ffa3, 0xb5390f92, 0x690fed0b,
        0x667b9ffb, 0xcedb7d9c, 0xa091cf0b, 0xd9155ea3, 0xbb132f88,
        0x515bad24, 0x7b9479bf, 0x763bd6eb, 0x37392eb3, 0xcc115979,
        0x8026e297, 0xf42e312d, 0x6842ada7, 0xc66a2b3b, 0x12754ccc,
        0x782ef11c, 0x6a124237, 0xb79251e7, 0x06a1bbe6, 0x4bfb6350,
        0x1a6b1018, 0x11caedfa, 0x3d25bdd8, 0xe2e1c3c9, 0x44421659,
        0x0a121386, 0xd90cec6e, 0xd5abea2a, 0x64af674e, 0xda86a85f,
        0xbebfe988, 0x64e4c3fe, 0x9dbc8057, 0xf0f7c086, 0x60787bf8,
        0x6003604d, 0xd1fd8346, 0xf6381fb0, 0x7745ae04, 0xd736fccc,
        0x83426b33, 0xf01eab71, 0xb0804187, 0x3c005e5f, 0x77a057be,
        0xbde8ae24, 0x55464299, 0xbf582e61, 0x4e58f48f, 0xf2ddfda2,
        0xf474ef38, 0x8789bdc2, 0x5366f9c3, 0xc8b38e74, 0xb475f255,
        0x46fcd9b9, 0x7aeb2661, 0x8b1ddf84, 0x846a0e79, 0x915f95e2,
        0x466e598e, 0x20b45770, 0x8cd55591, 0xc902de4c, 0xb90bace1,
        0xbb8205d0, 0x11a86248, 0x7574a99e, 0xb77f19b6, 0xe0a9dc09,
        0x662d09a1, 0xc4324633, 0xe85a1f02, 0x09f0be8c, 0x4a99a025,
        0x1d6efe10, 0x1ab93d1d, 0x0ba5a4df, 0xa186f20f, 0x2868f169,
        0xdcb7da83, 0x573906fe, 0xa1e2ce9b, 0x4fcd7f52, 0x50115e01,
        0xa70683fa, 0xa002b5c4, 0x0de6d027, 0x9af88c27, 0x773f8641,
        0xc3604c06, 0x61a806b5, 0xf0177a28, 0xc0f586e0, 0x006058aa,
        0x30dc7d62, 0x11e69ed7, 0x2338ea63, 0x53c2dd94, 0xc2c21634,
        0xbbcbee56, 0x90bcb6de, 0xebfc7da1, 0xce591d76, 0x6f05e409,
        0x4b7c0188, 0x39720a3d, 0x7c927c24, 0x86e3725f, 0x724d9db9,
        0x1ac15bb4, 0xd39eb8fc, 0xed545578, 0x08fca5b5, 0xd83d7cd3,
        0x4dad0fc4, 0x1e50ef5e, 0xb161e6f8, 0xa28514d9, 0x6c51133c,
        0x6fd5c7e7, 0x56e14ec4, 0x362abfce, 0xddc6c837, 0xd79a3234,
        0x92638212, 0x670efa8e, 0x406000e0, 0x3a39ce37, 0xd3faf5cf,
        0xabc27737, 0x5ac52d1b, 0x5cb0679e, 0x4fa33742, 0xd3822740,
        0x99bc9bbe, 0xd5118e9d, 0xbf0f7315, 0xd62d1c7e, 0xc700c47b,
        0xb78c1b6b, 0x21a19045, 0xb26eb1be, 0x6a366eb4, 0x5748ab2f,
        0xbc946e79, 0xc6a376d2, 0x6549c2c8, 0x530ff8ee, 0x468dde7d,
        0xd5730a1d, 0x4cd04dc6, 0x2939bbdb, 0xa9ba4650, 0xac9526e8,
        0xbe5ee304, 0xa1fad5f0, 0x6a2d519a, 0x63ef8ce2, 0x9a86ee22,
        0xc089c2b8, 0x43242ef6, 0xa51e03aa, 0x9cf2d0a4, 0x83c061ba,
        0x9be96a4d, 0x8fe51550, 0xba645bd6, 0x2826a2f9, 0xa73a3ae1,
        0x4ba99586, 0xef5562e9, 0xc72fefd3, 0xf752f7da, 0x3f046f69,
        0x77fa0a59, 0x80e4a915, 0x87b08601, 0x9b09e6ad, 0x3b3ee593,
        0xe990fd5a, 0x9e34d797, 0x2cf0b7d9, 0x022b8b51, 0x96d5ac3a,
        0x017da67d, 0xd1cf3ed6, 0x7c7d2d28, 0x1f9f25cf, 0xadf2b89b,
        0x5ad6b472, 0x5a88f54c, 0xe029ac71, 0xe019a5e6, 0x47b0acfd,
        0xed93fa9b, 0xe8d3c48d, 0x283b57cc, 0xf8d56629, 0x79132e28,
        0x785f0191, 0xed756055, 0xf7960e44, 0xe3d35e8c, 0x15056dd4,
        0x88f46dba, 0x03a16125, 0x0564f0bd, 0xc3eb9e15, 0x3c9057a2,
        0x97271aec, 0xa93a072a, 0x1b3f6d9b, 0x1e6321f5, 0xf59c66fb,
        0x26dcf319, 0x7533d928, 0xb155fdf5, 0x03563482, 0x8aba3cbb,
        0x28517711, 0xc20ad9f8, 0xabcc5167, 0xccad925f, 0x4de81751,
        0x3830dc8e, 0x379d5862, 0x9320f991, 0xea7a90c2, 0xfb3e7bce,
        0x5121ce64, 0x774fbe32, 0xa8b6e37e, 0xc3293d46, 0x48de5369,
        0x6413e680, 0xa2ae0810, 0xdd6db224, 0x69852dfd, 0x09072166,
        0xb39a460a, 0x6445c0dd, 0x586cdecf, 0x1c20c8ae, 0x5bbef7dd,
        0x1b588d40, 0xccd2017f, 0x6bb4e3bb, 0xdda26a7e, 0x3a59ff45,
        0x3e350a44, 0xbcb4cdd5, 0x72eacea8, 0xfa6484bb, 0x8d6612ae,
        0xbf3c6f47, 0xd29be463, 0x542f5d9e, 0xaec2771b, 0xf64e6370,
        0x740e0d8d, 0xe75b1357, 0xf8721671, 0xaf537d5d, 0x4040cb08,
        0x4eb4e2cc, 0x34d2466a, 0x0115af84, 0xe1b00428, 0x95983a1d,
        0x06b89fb4, 0xce6ea048, 0x6f3f3b82, 0x3520ab82, 0x011a1d4b,
        0x277227f8, 0x611560b1, 0xe7933fdc, 0xbb3a792b, 0x344525bd,
        0xa08839e1, 0x51ce794b, 0x2f32c9b7, 0xa01fbac9, 0xe01cc87e,
        0xbcc7d1f6, 0xcf0111c3, 0xa1e8aac7, 0x1a908749, 0xd44fbd9a,
        0xd0dadecb, 0xd50ada38, 0x0339c32a, 0xc6913667, 0x8df9317c,
        0xe0b12b4f, 0xf79e59b7, 0x43f5bb3a, 0xf2d519ff, 0x27d9459c,
        0xbf97222c, 0x15e6fc2a, 0x0f91fc71, 0x9b941525, 0xfae59361,
        0xceb69ceb, 0xc2a86459, 0x12baa8d1, 0xb6c1075e, 0xe3056a0c,
        0x10d25065, 0xcb03a442, 0xe0ec6e0e, 0x1698db3b, 0x4c98a0be,
        0x3278e964, 0x9f1f9532, 0xe0d392df, 0xd3a0342b, 0x8971f21e,
        0x1b0a7441, 0x4ba3348c, 0xc5be7120, 0xc37632d8, 0xdf359f8d,
        0x9b992f2e, 0xe60b6f47, 0x0fe3f11d, 0xe54cda54, 0x1edad891,
        0xce6279cf, 0xcd3e7e6f, 0x1618b166, 0xfd2c1d05, 0x848fd2c5,
        0xf6fb2299, 0xf523f357, 0xa6327623, 0x93a83531, 0x56cccd02,
        0xacf08162, 0x5a75ebb5, 0x6e163697, 0x88d273cc, 0xde966292,
        0x81b949d0, 0x4c50901b, 0x71c65614, 0xe6c6c7bd, 0x327a140a,
        0x45e1d006, 0xc3f27b9a, 0xc9aa53fd, 0x62a80f00, 0xbb25bfe2,
        0x35bdd2f6, 0x71126905, 0xb2040222, 0xb6cbcf7c, 0xcd769c2b,
        0x53113ec0, 0x1640e3d3, 0x38abbd60, 0x2547adf0, 0xba38209c,
        0xf746ce76, 0x77afa1c5, 0x20756060, 0x85cbfe4e, 0x8ae88dd8,
        0x7aaaf9b0, 0x4cf9aa7e, 0x1948c25c, 0x02fb8a8c, 0x01c36ae4,
        0xd6ebe1f9, 0x90d4f869, 0xa65cdea0, 0x3f09252d, 0xc208e69f,
        0xb74e6132, 0xce77e25b, 0x578fdfe3, 0x3ac372e6
    ];

    /**
     * @type {Array.<number>}
     * @const
     * @private
     */
    var C_ORIG = [
        0x4f727068, 0x65616e42, 0x65686f6c, 0x64657253, 0x63727944,
        0x6f756274
    ];

    /**
     * @param {Array.<number>} lr
     * @param {number} off
     * @param {Array.<number>} P
     * @param {Array.<number>} S
     * @returns {Array.<number>}
     * @private
     */
    function _encipher(lr, off, P, S) { // This is our bottleneck: 1714/1905 ticks / 90% - see profile.txt
        var n;
        var l = lr[off];
        var r = lr[off + 1];

        l ^= P[0];
        for (var i = 0; i <= BLOWFISH_NUM_ROUNDS - 2;) {
            // Feistel substitution on left word
            n = S[(l >> 24) & 0xff];
            n += S[0x100 | ((l >> 16) & 0xff)];
            n ^= S[0x200 | ((l >> 8) & 0xff)];
            n += S[0x300 | (l & 0xff)];
            r ^= n ^ P[++i];

            // Feistel substitution on right word
            n = S[(r >> 24) & 0xff];
            n += S[0x100 | ((r >> 16) & 0xff)];
            n ^= S[0x200 | ((r >> 8) & 0xff)];
            n += S[0x300 | (r & 0xff)];
            l ^= n ^ P[++i];
        }
        lr[off] = r ^ P[BLOWFISH_NUM_ROUNDS + 1];
        lr[off + 1] = l;
        return lr;
    }

    /**
     * @param {Array.<number>} data
     * @param {number} offp
     * @returns {{key: number, offp: number}}
     * @private
     */
    function _streamtoword(data, offp) {
        var i;
        var word = 0;
        for (i = 0; i < 4; i++) {
            word = (word << 8) | (data[offp] & 0xff);
            offp = (offp + 1) % data.length;
        }
        return {
            key: word,
            offp: offp
        };
    }

    /**
     * @param {Array.<number>} key
     * @param {Array.<number>} P
     * @param {Array.<number>} S
     * @private
     */
    function _key(key, P, S) {
        var offset = 0;
        var lr = new Array(0x00000000, 0x00000000);
        var plen = P.length;
        var slen = S.length;
        for (var i = 0; i < plen; i++) {
            var sw = _streamtoword(key, offset);
            offset = sw.offp;
            P[i] = P[i] ^ sw.key;
        }
        for (i = 0; i < plen; i += 2) {
            lr = _encipher(lr, 0, P, S);
            P[i] = lr[0];
            P[i + 1] = lr[1];
        }

        for (i = 0; i < slen; i += 2) {
            lr = _encipher(lr, 0, P, S);
            S[i] = lr[0];
            S[i + 1] = lr[1];
        }
    }

    /**
     * Expensive key schedule Blowfish.
     * @param {Array.<number>} data
     * @param {Array.<number>} key
     * @param {Array.<number>} P
     * @param {Array.<number>} S
     * @private
     */
    function _ekskey(data, key, P, S) {
        var offp = 0;
        var lr = new Array(0x00000000, 0x00000000);
        var plen = P.length;
        var slen = S.length;
        var sw;
        for (var i = 0; i < plen; i++) {
            sw = _streamtoword(key, offp);
            offp = sw.offp;
            P[i] = P[i] ^ sw.key;
        }
        offp = 0;
        for (i = 0; i < plen; i += 2) {
            sw = _streamtoword(data, offp);
            offp = sw.offp;
            lr[0] ^= sw.key;

            sw = _streamtoword(data, offp);
            offp = sw.offp;
            lr[1] ^= sw.key;

            lr = _encipher(lr, 0, P, S);
            P[i] = lr[0];
            P[i + 1] = lr[1];
        }
        for (i = 0; i < slen; i += 2) {
            sw = _streamtoword(data, offp);
            offp = sw.offp;
            lr[0] ^= sw.key;

            sw = _streamtoword(data, offp);
            offp = sw.offp;
            lr[1] ^= sw.key;

            lr = _encipher(lr, 0, P, S);
            S[i] = lr[0];
            S[i + 1] = lr[1];
        }
    }

    /**
     * Continues with the callback on the next tick.
     * @param {function(...[*])} callback Callback to execute
     * @private
     */
    function _nextTick(callback) {
        if (typeof process !== 'undefined' && typeof process.nextTick === 'function') {
            if (typeof setImmediate === 'function') {
                setImmediate(callback);
            } else {
                process.nextTick(callback);
            }
        } else {
            setTimeout(callback, 0);
        }
    }

    /**
     * Internaly crypts a string.
     * @param {Array.<number>} b Bytes to crypt
     * @param {Array.<number>} salt Salt bytes to use
     * @param {number} rounds Number of rounds
     * @param {function(Error, Array.<number>)=} callback Callback receiving the error, if any, and the resulting bytes. If
     *  omitted, the operation will be performed synchronously.
     * @returns {Array.<number>} Resulting bytes or if callback has been omitted, otherwise null
     * @private
     */
    function _crypt(b, salt, rounds, callback) {
        var cdata = C_ORIG.slice();
        var clen = cdata.length;

        // Validate
        if (rounds < 4 || rounds > 31) {
            throw (new Error("Illegal number of rounds: " + rounds));
        }
        if (salt.length != BCRYPT_SALT_LEN) {
            throw (new Error("Illegal salt length: " + salt.length + " != " + BCRYPT_SALT_LEN));
        }
        rounds = 1 << rounds;
        var P = P_ORIG.slice();
        var S = S_ORIG.slice();

        _ekskey(salt, b, P, S);

        var i = 0,
            j;

        /**
         * Calcualtes the next round.
         * @returns {Array.<number>} Resulting array if callback has been omitted, otherwise null
         * @private
         */
        function next() {
            if (i < rounds) {
                var start = new Date();
                for (; i < rounds;) {
                    i = i + 1;
                    _key(b, P, S);
                    _key(salt, P, S);
                    if (Date.now() - start > MAX_EXECUTION_TIME) { // TODO (dcode): Is this necessary?
                        break;
                    }
                }
            } else {
                for (i = 0; i < 64; i++) {
                    for (j = 0; j < (clen >> 1); j++) {
                        _encipher(cdata, j << 1, P, S);
                    }
                }
                var ret = [];
                for (i = 0; i < clen; i++) {
                    ret.push(((cdata[i] >> 24) & 0xff) >>> 0);
                    ret.push(((cdata[i] >> 16) & 0xff) >>> 0);
                    ret.push(((cdata[i] >> 8) & 0xff) >>> 0);
                    ret.push((cdata[i] & 0xff) >>> 0);
                }
                if (callback) {
                    callback(null, ret);
                    return null;
                } else {
                    return ret;
                }
            }
            if (callback) {
                _nextTick(next);
            }
            return null;
        }

        // Async
        if (typeof callback !== 'undefined') {
            next();
            return null;
            // Sync
        } else {
            var res;
            while (true) {
                if ((res = next()) !== null) {
                    return res;
                }
            }
        }
    }

    function _stringToBytes(str) {
        var ch, st, re = [];
        for (var i = 0; i < str.length; i++) {
            ch = str.charCodeAt(i);
            st = [];
            do {
                st.push(ch & 0xFF);
                ch = ch >> 8;
            } while (ch);
            re = re.concat(st.reverse());
        }
        return re;
    }

    /**
     * Internally hashes a string.
     * @param {string} s String to hash
     * @param {?string} salt Salt to use, actually never null
     * @param {function(Error, ?string)=} callback Callback receiving the error, if any, and the resulting hash. If omitted,
     *  hashing is perormed synchronously.
     * @returns {?string} Resulting hash if callback has been omitted, else null
     * @private
     */
    function _hash(s, salt, callback) {

        // Validate the salt
        var minor, offset;
        if (salt.charAt(0) != '$' || salt.charAt(1) != '2') {
            throw (new Error("Invalid salt version: " + salt.substring(0, 2)));
        }
        if (salt.charAt(2) == '$') {
            minor = String.fromCharCode(0);
            offset = 3;
        } else {
            minor = salt.charAt(2);
            if (minor != 'a' || salt.charAt(3) != '$') {
                throw (new Error("Invalid salt revision: " + salt.substring(2, 4)));
            }
            offset = 4;
        }

        // Extract number of rounds
        if (salt.charAt(offset + 2) > '$') {
            throw (new Error("Missing salt rounds"));
        }
        var r1 = parseInt(salt.substring(offset, offset + 1), 10) * 10;
        var r2 = parseInt(salt.substring(offset + 1, offset + 2), 10);
        var rounds = r1 + r2;
        var real_salt = salt.substring(offset + 3, offset + 25);
        s += minor >= 'a' ? "\000" : "";

        var passwordb = _stringToBytes(s);
        var saltb = [];
        saltb = base64.decode(real_salt, BCRYPT_SALT_LEN);

        /**
         * Finishs hashing.
         * @param {Array.<number>} bytes Byte array
         * @returns {string}
         * @private
         */
        function finish(bytes) {
            var res = [];
            res.push("$2");
            if (minor >= 'a') res.push(minor);
            res.push("$");
            if (rounds < 10) res.push("0");
            res.push(rounds.toString());
            res.push("$");
            res.push(base64.encode(saltb, saltb.length));
            res.push(base64.encode(bytes, C_ORIG.length * 4 - 1));
            return res.join('');
        }

        // Sync
        if (typeof callback == 'undefined') {
            return finish(_crypt(passwordb, saltb, rounds));

            // Async
        } else {
            _crypt(passwordb, saltb, rounds, function(err, bytes) {
                if (err) {
                    callback(err, null);
                } else {
                    callback(null, finish(bytes));
                }
            });
            return null;
        }
    }

    /**
     * Generates cryptographically secure random bytes.
     * @param {number} len Number of bytes to generate
     * @returns {Array.<number>}
     * @private
     */
    function _randomBytes(len) {
        // node.js, see: http://nodejs.org/api/crypto.html
        if (typeof module !== 'undefined' && module.exports) {
            var crypto = require("crypto");
            return crypto.randomBytes(len);

            // Browser, see: http://www.w3.org/TR/WebCryptoAPI/
        } else {
            var array = new Uint32Array(len);
            if (global.crypto && typeof global.crypto.getRandomValues === 'function') {
                global.crypto.getRandomValues(array);
            } else if (typeof _getRandomValues === 'function') {
                _getRandomValues(array);
            } else {
                throw (new Error("Failed to generate random values: Web Crypto API not available / no polyfill set"));
            }
            return Array.prototype.slice.call(array);
        }
    }

    /**
     * Internally generates a salt.
     * @param {number} rounds Number of rounds to use
     * @returns {string} Salt
     * @throws {Error} If anything goes wrong
     * @private
     */
    function _gensalt(rounds) {
        rounds = rounds || 10;
        if (rounds < 4 || rounds > 31) {
            throw (new Error("Illegal number of rounds: " + rounds));
        }
        var salt = [];
        salt.push("$2a$");
        if (rounds < GENSALT_DEFAULT_LOG2_ROUNDS) salt.push("0");
        salt.push(rounds.toString());
        salt.push('$');
        try {
            salt.push(base64.encode(_randomBytes(BCRYPT_SALT_LEN), BCRYPT_SALT_LEN));
            return salt.join('');
        } catch (err) {
            throw (err);
        }
    }

    // crypto.getRandomValues polyfill to use
    var _getRandomValues = null;

    /**
     * Sets the polyfill that should be used if window.crypto.getRandomValues is not available.
     * @param {function(Uint32Array)} getRandomValues The actual implementation
     * @expose
     */
    bcrypt.setRandomPolyfill = function(getRandomValues) {
        _getRandomValues = getRandomValues;
    };

    /**
     * Synchronously generates a salt.
     * @param {number=} rounds Number of rounds to use, defaults to 10 if omitted
     * @param {number=} seed_length Not supported.
     * @returns {string} Resulting salt
     * @expose
     */
    bcrypt.genSaltSync = function(rounds, seed_length) {
        if (!rounds) rounds = 10;
        return _gensalt(rounds);
    };

    /**
     * Asynchronously generates a salt.
     * @param {(number|function(Error, ?string))=} rounds Number of rounds to use, defaults to 10 if omitted
     * @param {(number|function(Error, ?string))=} seed_length Not supported.
     * @param {function(Error, ?string)=} callback Callback receiving the error, if any, and the resulting salt
     * @expose
     */
    bcrypt.genSalt = function(rounds, seed_length, callback) {
        if (typeof seed_length == 'function') {
            callback = seed_length;
            seed_length = -1; // Not supported.
        }
        var rnd; // Hello closure
        if (typeof rounds == 'function') {
            callback = rounds;
            rnd = GENSALT_DEFAULT_LOG2_ROUNDS;
        } else {
            rnd = parseInt(rounds, 10);
        }
        if (typeof callback != 'function') {
            throw (new Error("Illegal or missing 'callback': " + callback));
        }
        _nextTick(function() { // Pretty thin, but salting is fast enough
            try {
                var res = bcrypt.genSaltSync(rnd);
                callback(null, res);
            } catch (err) {
                callback(err, null);
            }
        });
    };

    /**
     * Synchronously generates a hash for the given string.
     * @param {string} s String to hash
     * @param {(number|string)=} salt Salt length to generate or salt to use, default to 10
     * @returns {?string} Resulting hash, actually never null
     * @expose
     */
    bcrypt.hashSync = function(s, salt) {
        if (!salt) salt = GENSALT_DEFAULT_LOG2_ROUNDS;
        if (typeof salt == 'number') {
            salt = bcrypt.genSaltSync(salt);
        }
        return _hash(s, salt);
    };

    /**
     * Asynchronously generates a hash for the given string.
     * @param {string} s String to hash
     * @param {number|string} salt Salt length to generate or salt to use
     * @param {function(Error, ?string)} callback Callback receiving the error, if any, and the resulting hash
     * @expose
     */
    bcrypt.hash = function(s, salt, callback) {
        if (typeof callback != 'function') {
            throw (new Error("Illegal 'callback': " + callback));
        }
        if (typeof salt == 'number') {
            bcrypt.genSalt(salt, function(err, salt) {
                _hash(s, salt, callback);
            });
        } else {
            _hash(s, salt, callback);
        }
    };

    /**
     * Synchronously tests a string against a hash.
     * @param {string} s String to compare
     * @param {string} hash Hash to test against
     * @returns {boolean} true if matching, otherwise false
     * @throws {Error} If an argument is illegal
     * @expose
     */
    bcrypt.compareSync = function(s, hash) {
        if (typeof s != "string" || typeof hash != "string") {
            throw (new Error("Illegal argument types: " + (typeof s) + ', ' + (typeof hash)));
        }
        if (hash.length != 60) {
            throw (new Error("Illegal hash length: " + hash.length + " != 60"));
        }
        var comp = bcrypt.hashSync(s, hash.substr(0, hash.length - 31));
        var same = comp.length == hash.length;
        var max_length = (comp.length < hash.length) ? comp.length : hash.length;

        // to prevent timing attacks, should check entire string
        // don't exit after found to be false
        for (var i = 0; i < max_length; ++i) {
            if (comp.length >= i && hash.length >= i && comp[i] != hash[i]) {
                same = false;
            }
        }
        return same;
    };

    /**
     * Asynchronously compares the given data against the given hash.
     * @param {string} s Data to compare
     * @param {string} hash Data to be compared to
     * @param {function(Error, boolean)} callback Callback receiving the error, if any, otherwise the result
     * @throws {Error} If the callback argument is invalid
     * @expose
     */
    bcrypt.compare = function(s, hash, callback) {
        if (typeof callback != 'function') {
            throw (new Error("Illegal 'callback': " + callback));
        }
        bcrypt.hash(s, hash.substr(0, 29), function(err, comp) {
            callback(err, hash === comp);
        });
    };

    /**
     * Gets the number of rounds used to encrypt the specified hash.
     * @param {string} hash Hash to extract the used number of rounds from
     * @returns {number} Number of rounds used
     * @throws {Error} If hash is not a string
     * @expose
     */
    bcrypt.getRounds = function(hash) {
        if (typeof hash != "string") {
            throw (new Error("Illegal type of 'hash': " + (typeof hash)));
        }
        return parseInt(hash.split("$")[2], 10);
    };

    /**
     * Gets the salt portion from a hash.
     * @param {string} hash Hash to extract the salt from
     * @returns {string} Extracted salt part portion
     * @throws {Error} If `hash` is not a string or otherwise invalid
     * @expose
     */
    bcrypt.getSalt = function(hash) {
        if (typeof hash != 'string') {
            throw (new Error("Illegal type of 'hash': " + (typeof hash)));
        }
        if (hash.length != 60) {
            throw (new Error("Illegal hash length: " + hash.length + " != 60"));
        }
        return hash.substring(0, 29);
    };

    // Enable module loading if available
    if (typeof module != 'undefined' && module["exports"]) { // CommonJS
        module["exports"] = bcrypt;
    } else if (typeof define != 'undefined' && define["amd"]) { // AMD
        define("bcrypt", function() {
            return bcrypt;
        });
    } else { // Shim
        if (!global["dcodeIO"]) {
            global["dcodeIO"] = {};
        }
        global["dcodeIO"]["bcrypt"] = bcrypt;
    }

})(this);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Cam Pedersen <cam@campedersen.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

(function() {

    self.isomerize = function(obj, dependencies) {
        // if we don't have access to web workers,
        // just run everything in the main thread
        if (!window.Worker) {
            return;
        }

        var code = '';

        if (typeof dependencies == 'string') {
            code += 'window = document = self; self.worker = true;\n';
            code += 'document.documentElement = { style: [] };\n'; // fix for socket.io
            code += 'importScripts(\'' + dependencies + '\');\n';
        } else {
            for (var i in dependencies) {
                var name = dependencies[i];
                var dep = window[name];
                code += toSource(dep, name);
            }
        }

        code += toSource(obj, 'original');
        code += '(' + isomerExternal.toString() + ')();';

        var blob = new Blob([code], {
            type: 'application/javascript'
        });
        var worker = new Worker(URL.createObjectURL(blob));
        var listeners = {};

        worker.onmessage = function(e) {
            var data = JSON.parse(e.data);

            if (!listeners[data.time]) {
                return;
            }

            listeners[data.time].apply(listeners[data.time], data.args);
        };

        for (var i in obj) {
            if (typeof obj[i] == 'function') {
                obj[i] = overrideLocalMethod(i);
            }
        }

        function overrideLocalMethod(methodName) {
            return function isomerProxy() {
                var args = [].slice.call(arguments);
                var callback = args.pop();
                var now = +new Date();
                listeners[now] = callback;

                worker.postMessage(JSON.stringify({
                    name: methodName,
                    time: now,
                    args: args
                }));
            }
        }
    }

    function isomerExternal() {
        onmessage = function(e) {
            var data = JSON.parse(e.data);
            var args = data.args;

            args.push(function() {
                var args = [].slice.call(arguments);
                postMessage(JSON.stringify({
                    time: data.time,
                    args: args
                }));
            });

            original[data.name].apply(original, args);
        }
    }

    function toSource(obj, name) {
        var code = '';

        if (name) {
            code += 'var ' + name + ' = ';
        }

        if (typeof obj == 'function') {
            code += obj.toString();
        } else {
            code += JSON.stringify(obj);
        }

        code += ';\n';

        for (var i in obj) {
            if (typeof obj[i] != 'function') {
                continue;
            }

            if (name) {
                code += name + '.' + i + ' = ';
            }

            code += obj[i].toString() + ';\n';
        }

        for (var i in obj.prototype) {
            if (name) {
                code += name + '.prototype.' + i + ' = ';
            }

            if (typeof obj.prototype[i] == 'function') {
                code += obj.prototype[i].toString() + ';\n';
            } else if (typeof obj.prototype[i] == 'object') {
                code += JSON.stringify(obj.prototype[i]) + ';\n';
            }
        }

        return code;
    }


})();
/*
 *   Json Diff Patch
 *   ---------------
 *   https://github.com/benjamine/JsonDiffPatch
 *   by Benjamin Eidelman - beneidel@gmail.com
 */
(function() {
    "use strict";
    var e = {};
    typeof t != "undefined" && (e = t);
    var t = e;
    e.version = "0.0.7", e.config = {
        textDiffMinLength: 60,
        detectArrayMove: !0,
        includeValueOnArrayMove: !1
    };
    var n = {
        diff: function(t, n, r, i) {
            var s = 0,
                o = 0,
                u, a, f = t.length,
                l = n.length,
                c, h = [],
                p = [],
                d = typeof r == "function" ? function(e, t, n, i) {
                    if (e === t) return !0;
                    if (typeof e != "object" || typeof t != "object") return !1;
                    var s, o;
                    return typeof n == "number" ? (s = h[n], typeof s == "undefined" && (h[n] = s = r(e))) : s = r(e), typeof i == "number" ? (o = p[i], typeof o == "undefined" && (p[i] = o = r(t))) : o = r(t), s === o
                } : function(e, t) {
                    return e === t
                },
                v = function(e, r) {
                    return d(t[e], n[r], e, r)
                },
                m = function(e, r) {
                    if (!i) return;
                    if (typeof t[e] != "object" || typeof n[r] != "object") return;
                    var s = i(t[e], n[r]);
                    if (typeof s == "undefined") return;
                    c || (c = {
                        _t: "a"
                    }), c[r] = s
                };
            while (s < f && s < l && v(s, s)) m(s, s), s++;
            while (o + s < f && o + s < l && v(f - 1 - o, l - 1 - o)) m(f - 1 - o, l - 1 - o), o++;
            if (s + o === f) {
                if (f === l) return c;
                c = c || {
                    _t: "a"
                };
                for (u = s; u < l - o; u++) c[u] = [n[u]];
                return c
            }
            if (s + o === l) {
                c = c || {
                    _t: "a"
                };
                for (u = s; u < f - o; u++) c["_" + u] = [t[u], 0, 0];
                return c
            }
            var g = this.lcs(t.slice(s, f - o), n.slice(s, l - o), {
                areTheSameByIndex: function(e, t) {
                    return v(e + s, t + s)
                }
            });
            c = c || {
                _t: "a"
            };
            var y = [];
            for (u = s; u < f - o; u++) g.indices1.indexOf(u - s) < 0 && (c["_" + u] = [t[u], 0, 0], y.push(u));
            var b = y.length;
            for (u = s; u < l - o; u++) {
                var w = g.indices2.indexOf(u - s);
                if (w < 0) {
                    var E = !1;
                    if (e.config.detectArrayMove && b > 0)
                        for (a = 0; a < b; a++)
                            if (v(y[a], u)) {
                                c["_" + y[a]].splice(1, 2, u, 3), e.config.includeValueOnArrayMove || (c["_" + y[a]][0] = ""), m(y[a], u), y.splice(a, 1), E = !0;
                                break
                            }
                    E || (c[u] = [n[u]])
                } else m(g.indices1[w] + s, g.indices2[w] + s)
            }
            return c
        },
        getArrayIndexBefore: function(e, t) {
            var n, r = t;
            for (var s in e)
                if (e.hasOwnProperty(s) && i(e[s])) {
                    s.slice(0, 1) === "_" ? n = parseInt(s.slice(1), 10) : n = parseInt(s, 10);
                    if (e[s].length === 1) {
                        if (n < t) r--;
                        else if (n === t) return -1
                    } else if (e[s].length === 3)
                        if (e[s][2] === 0) n <= t && r++;
                        else if (e[s][2] === 3) {
                        n <= t && r++;
                        if (e[s][1] > t) r--;
                        else if (e[s][1] === t) return n
                    }
                }
            return r
        },
        patch: function(e, t, n, r) {
            var i, s, o = function(e, t) {
                    return e - t
                },
                u = function(e) {
                    return function(t, n) {
                        return t[e] - n[e]
                    }
                },
                a = [],
                f = [],
                l = [];
            for (i in t)
                if (i !== "_t")
                    if (i[0] == "_") {
                        if (t[i][2] !== 0 && t[i][2] !== 3) throw new Error("only removal or move can be applied at original array indices, invalid diff type: " + t[i][2]);
                        a.push(parseInt(i.slice(1), 10))
                    } else t[i].length === 1 ? f.push({
                        index: parseInt(i, 10),
                        value: t[i][0]
                    }) : l.push({
                        index: parseInt(i, 10),
                        diff: t[i]
                    });
            a = a.sort(o);
            for (i = a.length - 1; i >= 0; i--) {
                s = a[i];
                var c = t["_" + s],
                    h = e.splice(s, 1)[0];
                c[2] === 3 && f.push({
                    index: c[1],
                    value: h
                })
            }
            f = f.sort(u("index"));
            var p = f.length;
            for (i = 0; i < p; i++) {
                var d = f[i];
                e.splice(d.index, 0, d.value)
            }
            var v = l.length;
            if (v > 0) {
                if (typeof n != "function") throw new Error("to patch items in the array an objectInnerPatch function must be provided");
                for (i = 0; i < v; i++) {
                    var m = l[i];
                    n(e, m.index.toString(), m.diff, r)
                }
            }
            return e
        },
        lcs: function(e, t, n) {
            n.areTheSameByIndex = n.areTheSameByIndex || function(n, r) {
                return e[n] === t[r]
            };
            var r = this.lengthMatrix(e, t, n),
                i = this.backtrack(r, e, t, e.length, t.length);
            return typeof e == "string" && typeof t == "string" && (i.sequence = i.sequence.join("")), i
        },
        lengthMatrix: function(e, t, n) {
            var r = e.length,
                i = t.length,
                s, o, u = [r + 1];
            for (s = 0; s < r + 1; s++) {
                u[s] = [i + 1];
                for (o = 0; o < i + 1; o++) u[s][o] = 0
            }
            u.options = n;
            for (s = 1; s < r + 1; s++)
                for (o = 1; o < i + 1; o++) n.areTheSameByIndex(s - 1, o - 1) ? u[s][o] = u[s - 1][o - 1] + 1 : u[s][o] = Math.max(u[s - 1][o], u[s][o - 1]);
            return u
        },
        backtrack: function(e, t, n, r, i) {
            if (r === 0 || i === 0) return {
                sequence: [],
                indices1: [],
                indices2: []
            };
            if (e.options.areTheSameByIndex(r - 1, i - 1)) {
                var s = this.backtrack(e, t, n, r - 1, i - 1);
                return s.sequence.push(t[r - 1]), s.indices1.push(r - 1), s.indices2.push(i - 1), s
            }
            return e[r][i - 1] > e[r - 1][i] ? this.backtrack(e, t, n, r, i - 1) : this.backtrack(e, t, n, r - 1, i)
        }
    };
    e.sequenceDiffer = n, e.dateReviver = function(e, t) {
        var n;
        if (typeof t == "string") {
            n = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2}(?:\.\d*)?)(Z|([+\-])(\d{2}):(\d{2}))$/.exec(t);
            if (n) return new Date(Date.UTC(+n[1], +n[2] - 1, +n[3], +n[4], +n[5], +n[6]))
        }
        return t
    };
    var r = function() {
            var t;
            e.config.diff_match_patch && (t = new e.config.diff_match_patch.diff_match_patch), typeof diff_match_patch != "undefined" && (typeof diff_match_patch == "function" ? t = new diff_match_patch : typeof diff_match_patch == "object" && typeof diff_match_patch.diff_match_patch == "function" && (t = new diff_match_patch.diff_match_patch));
            if (t) return e.config.textDiff = function(e, n) {
                return t.patch_toText(t.patch_make(e, n))
            }, e.config.textPatch = function(e, n) {
                var r = t.patch_apply(t.patch_fromText(n), e);
                for (var i = 0; i < r[1].length; i++)
                    if (!r[1][i]) throw new Error("text patch failed");
                return r[0]
            }, !0
        },
        i = e.isArray = typeof Array.isArray == "function" ? Array.isArray : function(e) {
            return typeof e == "object" && e instanceof Array
        },
        s = e.isDate = function(e) {
            return e instanceof Date || Object.prototype.toString.call(e) === "[object Date]"
        },
        o = function(t, r) {
            return n.diff(t, r, e.config.objectHash, e.diff)
        },
        u = function(e, t) {
            var n, r, i, s;
            s = function(i) {
                r = a(e[i], t[i]), typeof r != "undefined" && (typeof n == "undefined" && (n = {}), n[i] = r)
            };
            for (i in t) t.hasOwnProperty(i) && s(i);
            for (i in e) e.hasOwnProperty(i) && typeof t[i] == "undefined" && s(i);
            return n
        },
        a = e.diff = function(t, n) {
            var a, f, l, c, h;
            if (t === n) return;
            if (t !== t && n !== n) return;
            a = typeof n, f = typeof t, l = n === null, c = t === null, f == "object" && s(t) && (f = "date");
            if (a == "object" && s(n)) {
                a = "date";
                if (f == "date" && t.getTime() === n.getTime()) return
            }
            if (l || c || a == "undefined" || a != f || a == "number" || f == "number" || a == "boolean" || f == "boolean" || a == "string" || f == "string" || a == "date" || f == "date" || a === "object" && i(n) != i(t)) {
                h = [];
                if (typeof t != "undefined")
                    if (typeof n != "undefined") {
                        var p = a == "string" && f == "string" && Math.min(t.length, n.length) > e.config.textDiffMinLength;
                        p && !e.config.textDiff && r(), p && e.config.textDiff ? h.push(e.config.textDiff(t, n), 0, 2) : (h.push(t), h.push(n))
                    } else h.push(t), h.push(0, 0);
                else h.push(n);
                return h
            }
            return i(n) ? o(t, n) : u(t, n)
        },
        f = function(e, t) {
            return i(e) ? e[parseInt(t, 10)] : e[t]
        };
    e.getByKey = f;
    var l = function(e, t, n) {
            if (i(e) && e._key) {
                var r = e._key;
                typeof e._key != "function" && (r = function(t) {
                    return t[e._key]
                });
                for (var s = 0; s < e.length; s++)
                    if (r(e[s]) === t) {
                        typeof n == "undefined" ? (e.splice(s, 1), s--) : e[s] = n;
                        return
                    }
                typeof n != "undefined" && e.push(n);
                return
            }
            typeof n == "undefined" ? i(e) ? e.splice(t, 1) : delete e[t] : e[t] = n
        },
        c = function(t) {
            return e.config.textDiffReverse || (e.config.textDiffReverse = function(e) {
                var t, n, r, i, s, o = null,
                    u = /^@@ +\-(\d+),(\d+) +\+(\d+),(\d+) +@@$/,
                    a, f, l, c = function() {
                        f !== null && (r[f] = "-" + r[f].slice(1)), l !== null && (r[l] = "+" + r[l].slice(1), f !== null && (s = r[f], r[f] = r[l], r[l] = s)), r[a] = "@@ -" + o[3] + "," + o[4] + " +" + o[1] + "," + o[2] + " @@", o = null, a = null, f = null, l = null
                    };
                r = e.split("\n");
                for (t = 0, n = r.length; t < n; t++) {
                    i = r[t];
                    var h = i.slice(0, 1);
                    h === "@" ? (o !== null, o = u.exec(i), a = t, f = null, l = null, r[a] = "@@ -" + o[3] + "," + o[4] + " +" + o[1] + "," + o[2] + " @@") : h == "+" ? (f = t, r[t] = "-" + r[t].slice(1)) : h == "-" && (l = t, r[t] = "+" + r[t].slice(1))
                }
                return o !== null, r.join("\n")
            }), e.config.textDiffReverse(t)
        },
        h = e.reverse = function(e) {
            var t, r;
            if (typeof e == "undefined") return;
            if (e === null) return null;
            if (typeof e == "object" && !s(e)) {
                if (i(e)) {
                    if (e.length < 3) return e.length === 1 ? [e[0], 0, 0] : [e[1], e[0]];
                    if (e[2] === 0) return [e[0]];
                    if (e[2] === 2) return [c(e[0]), 0, 2];
                    throw new Error("invalid diff type")
                }
                r = {};
                if (e._t === "a") {
                    for (t in e)
                        if (e.hasOwnProperty(t) && t !== "_t") {
                            var o, u = t;
                            t.slice(0, 1) === "_" ? o = parseInt(t.slice(1), 10) : o = parseInt(t, 10);
                            if (i(e[t]))
                                if (e[t].length === 1) u = "_" + o;
                                else if (e[t].length === 2) u = n.getArrayIndexBefore(e, o);
                            else if (e[t][2] === 0) u = o.toString();
                            else {
                                if (e[t][2] === 3) {
                                    u = "_" + e[t][1], r[u] = [e[t][0], o, 3];
                                    continue
                                }
                                u = n.getArrayIndexBefore(e, o)
                            } else u = n.getArrayIndexBefore(e, o);
                            r[u] = h(e[t])
                        }
                    r._t = "a"
                } else
                    for (t in e) e.hasOwnProperty(t) && (r[t] = h(e[t]));
                return r
            }
            return typeof e == "string" && e.slice(0, 2) === "@@" ? c(e) : e
        },
        p = e.patch = function(s, o, u, a) {
            var c, h, d = "",
                v;
            typeof o != "string" ? (a = u, u = o, o = null) : typeof s != "object" && (o = null), a && (d += a), d += "/", o !== null && (d += o);
            if (typeof u == "object")
                if (i(u)) {
                    if (u.length < 3) return h = u[u.length - 1], o !== null && l(s, o, h), h;
                    if (u[2] !== 0) {
                        if (u[2] === 2) {
                            e.config.textPatch || r();
                            if (!e.config.textPatch) throw new Error("textPatch function not found");
                            try {
                                h = e.config.textPatch(f(s, o), u[0])
                            } catch (m) {
                                throw new Error('cannot apply patch at "' + d + '": ' + m)
                            }
                            return o !== null && l(s, o, h), h
                        }
                        throw u[2] === 3 ? new Error("Not implemented diff type: " + u[2]) : new Error("invalid diff type: " + u[2])
                    }
                    if (o === null) return;
                    l(s, o)
                } else if (u._t == "a") {
                v = o === null ? s : f(s, o);
                if (typeof v != "object" || !i(v)) throw new Error('cannot apply patch at "' + d + '": array expected');
                n.patch(v, u, t.patch, d)
            } else {
                v = o === null ? s : f(s, o);
                if (typeof v != "object" || i(v)) throw new Error('cannot apply patch at "' + d + '": object expected');
                for (c in u) u.hasOwnProperty(c) && p(v, c, u[c], d)
            }
            return s
        },
        d = e.unpatch = function(e, t, n, r) {
            return typeof t != "string" ? p(e, h(t), n) : p(e, t, h(n), r)
        };
    typeof require == "function" && typeof exports == "object" && typeof module == "object" ? module.exports = e : typeof define == "function" && define.amd ? define(e) : window.jsondiffpatch = e
})();
/**
 * @fileoverview
 * - Using the 'QRCode for Javascript library'
 * - Fixed dataset of 'QRCode for Javascript library' for support full-spec.
 * - this library has no dependencies.
 *
 * @author davidshimjs
 * @see <a href="http://www.d-project.com/" target="_blank">http://www.d-project.com/</a>
 * @see <a href="http://jeromeetienne.github.com/jquery-qrcode/" target="_blank">http://jeromeetienne.github.com/jquery-qrcode/</a>
 */
var QRCode;

(function() {
    //---------------------------------------------------------------------
    // QRCode for JavaScript
    //
    // Copyright (c) 2009 Kazuhiko Arase
    //
    // URL: http://www.d-project.com/
    //
    // Licensed under the MIT license:
    //   http://www.opensource.org/licenses/mit-license.php
    //
    // The word "QR Code" is registered trademark of
    // DENSO WAVE INCORPORATED
    //   http://www.denso-wave.com/qrcode/faqpatent-e.html
    //
    //---------------------------------------------------------------------
    function QR8bitByte(data) {
        this.mode = QRMode.MODE_8BIT_BYTE;
        this.data = data;
        this.parsedData = [];

        // Added to support UTF-8 Characters
        for (var i = 0, l = this.data.length; i < l; i++) {
            var byteArray = [];
            var code = this.data.charCodeAt(i);

            if (code > 0x10000) {
                byteArray[0] = 0xF0 | ((code & 0x1C0000) >>> 18);
                byteArray[1] = 0x80 | ((code & 0x3F000) >>> 12);
                byteArray[2] = 0x80 | ((code & 0xFC0) >>> 6);
                byteArray[3] = 0x80 | (code & 0x3F);
            } else if (code > 0x800) {
                byteArray[0] = 0xE0 | ((code & 0xF000) >>> 12);
                byteArray[1] = 0x80 | ((code & 0xFC0) >>> 6);
                byteArray[2] = 0x80 | (code & 0x3F);
            } else if (code > 0x80) {
                byteArray[0] = 0xC0 | ((code & 0x7C0) >>> 6);
                byteArray[1] = 0x80 | (code & 0x3F);
            } else {
                byteArray[0] = code;
            }

            this.parsedData.push(byteArray);
        }

        this.parsedData = Array.prototype.concat.apply([], this.parsedData);

        if (this.parsedData.length != this.data.length) {
            this.parsedData.unshift(191);
            this.parsedData.unshift(187);
            this.parsedData.unshift(239);
        }
    }

    QR8bitByte.prototype = {
        getLength: function(buffer) {
            return this.parsedData.length;
        },
        write: function(buffer) {
            for (var i = 0, l = this.parsedData.length; i < l; i++) {
                buffer.put(this.parsedData[i], 8);
            }
        }
    };

    function QRCodeModel(typeNumber, errorCorrectLevel) {
        this.typeNumber = typeNumber;
        this.errorCorrectLevel = errorCorrectLevel;
        this.modules = null;
        this.moduleCount = 0;
        this.dataCache = null;
        this.dataList = [];
    }

    QRCodeModel.prototype = {
        addData: function(data) {
            var newData = new QR8bitByte(data);
            this.dataList.push(newData);
            this.dataCache = null;
        },
        isDark: function(row, col) {
            if (row < 0 || this.moduleCount <= row || col < 0 || this.moduleCount <= col) {
                throw new Error(row + "," + col);
            }
            return this.modules[row][col];
        },
        getModuleCount: function() {
            return this.moduleCount;
        },
        make: function() {
            this.makeImpl(false, this.getBestMaskPattern());
        },
        makeImpl: function(test, maskPattern) {
            this.moduleCount = this.typeNumber * 4 + 17;
            this.modules = new Array(this.moduleCount);
            for (var row = 0; row < this.moduleCount; row++) {
                this.modules[row] = new Array(this.moduleCount);
                for (var col = 0; col < this.moduleCount; col++) {
                    this.modules[row][col] = null;
                }
            }
            this.setupPositionProbePattern(0, 0);
            this.setupPositionProbePattern(this.moduleCount - 7, 0);
            this.setupPositionProbePattern(0, this.moduleCount - 7);
            this.setupPositionAdjustPattern();
            this.setupTimingPattern();
            this.setupTypeInfo(test, maskPattern);
            if (this.typeNumber >= 7) {
                this.setupTypeNumber(test);
            }
            if (this.dataCache == null) {
                this.dataCache = QRCodeModel.createData(this.typeNumber, this.errorCorrectLevel, this.dataList);
            }
            this.mapData(this.dataCache, maskPattern);
        },
        setupPositionProbePattern: function(row, col) {
            for (var r = -1; r <= 7; r++) {
                if (row + r <= -1 || this.moduleCount <= row + r) continue;
                for (var c = -1; c <= 7; c++) {
                    if (col + c <= -1 || this.moduleCount <= col + c) continue;
                    if ((0 <= r && r <= 6 && (c == 0 || c == 6)) || (0 <= c && c <= 6 && (r == 0 || r == 6)) || (2 <= r && r <= 4 && 2 <= c && c <= 4)) {
                        this.modules[row + r][col + c] = true;
                    } else {
                        this.modules[row + r][col + c] = false;
                    }
                }
            }
        },
        getBestMaskPattern: function() {
            var minLostPoint = 0;
            var pattern = 0;
            for (var i = 0; i < 8; i++) {
                this.makeImpl(true, i);
                var lostPoint = QRUtil.getLostPoint(this);
                if (i == 0 || minLostPoint > lostPoint) {
                    minLostPoint = lostPoint;
                    pattern = i;
                }
            }
            return pattern;
        },
        createMovieClip: function(target_mc, instance_name, depth) {
            var qr_mc = target_mc.createEmptyMovieClip(instance_name, depth);
            var cs = 1;
            this.make();
            for (var row = 0; row < this.modules.length; row++) {
                var y = row * cs;
                for (var col = 0; col < this.modules[row].length; col++) {
                    var x = col * cs;
                    var dark = this.modules[row][col];
                    if (dark) {
                        qr_mc.beginFill(0, 100);
                        qr_mc.moveTo(x, y);
                        qr_mc.lineTo(x + cs, y);
                        qr_mc.lineTo(x + cs, y + cs);
                        qr_mc.lineTo(x, y + cs);
                        qr_mc.endFill();
                    }
                }
            }
            return qr_mc;
        },
        setupTimingPattern: function() {
            for (var r = 8; r < this.moduleCount - 8; r++) {
                if (this.modules[r][6] != null) {
                    continue;
                }
                this.modules[r][6] = (r % 2 == 0);
            }
            for (var c = 8; c < this.moduleCount - 8; c++) {
                if (this.modules[6][c] != null) {
                    continue;
                }
                this.modules[6][c] = (c % 2 == 0);
            }
        },
        setupPositionAdjustPattern: function() {
            var pos = QRUtil.getPatternPosition(this.typeNumber);
            for (var i = 0; i < pos.length; i++) {
                for (var j = 0; j < pos.length; j++) {
                    var row = pos[i];
                    var col = pos[j];
                    if (this.modules[row][col] != null) {
                        continue;
                    }
                    for (var r = -2; r <= 2; r++) {
                        for (var c = -2; c <= 2; c++) {
                            if (r == -2 || r == 2 || c == -2 || c == 2 || (r == 0 && c == 0)) {
                                this.modules[row + r][col + c] = true;
                            } else {
                                this.modules[row + r][col + c] = false;
                            }
                        }
                    }
                }
            }
        },
        setupTypeNumber: function(test) {
            var bits = QRUtil.getBCHTypeNumber(this.typeNumber);
            for (var i = 0; i < 18; i++) {
                var mod = (!test && ((bits >> i) & 1) == 1);
                this.modules[Math.floor(i / 3)][i % 3 + this.moduleCount - 8 - 3] = mod;
            }
            for (var i = 0; i < 18; i++) {
                var mod = (!test && ((bits >> i) & 1) == 1);
                this.modules[i % 3 + this.moduleCount - 8 - 3][Math.floor(i / 3)] = mod;
            }
        },
        setupTypeInfo: function(test, maskPattern) {
            var data = (this.errorCorrectLevel << 3) | maskPattern;
            var bits = QRUtil.getBCHTypeInfo(data);
            for (var i = 0; i < 15; i++) {
                var mod = (!test && ((bits >> i) & 1) == 1);
                if (i < 6) {
                    this.modules[i][8] = mod;
                } else if (i < 8) {
                    this.modules[i + 1][8] = mod;
                } else {
                    this.modules[this.moduleCount - 15 + i][8] = mod;
                }
            }
            for (var i = 0; i < 15; i++) {
                var mod = (!test && ((bits >> i) & 1) == 1);
                if (i < 8) {
                    this.modules[8][this.moduleCount - i - 1] = mod;
                } else if (i < 9) {
                    this.modules[8][15 - i - 1 + 1] = mod;
                } else {
                    this.modules[8][15 - i - 1] = mod;
                }
            }
            this.modules[this.moduleCount - 8][8] = (!test);
        },
        mapData: function(data, maskPattern) {
            var inc = -1;
            var row = this.moduleCount - 1;
            var bitIndex = 7;
            var byteIndex = 0;
            for (var col = this.moduleCount - 1; col > 0; col -= 2) {
                if (col == 6) col--;
                while (true) {
                    for (var c = 0; c < 2; c++) {
                        if (this.modules[row][col - c] == null) {
                            var dark = false;
                            if (byteIndex < data.length) {
                                dark = (((data[byteIndex] >>> bitIndex) & 1) == 1);
                            }
                            var mask = QRUtil.getMask(maskPattern, row, col - c);
                            if (mask) {
                                dark = !dark;
                            }
                            this.modules[row][col - c] = dark;
                            bitIndex--;
                            if (bitIndex == -1) {
                                byteIndex++;
                                bitIndex = 7;
                            }
                        }
                    }
                    row += inc;
                    if (row < 0 || this.moduleCount <= row) {
                        row -= inc;
                        inc = -inc;
                        break;
                    }
                }
            }
        }
    };
    QRCodeModel.PAD0 = 0xEC;
    QRCodeModel.PAD1 = 0x11;
    QRCodeModel.createData = function(typeNumber, errorCorrectLevel, dataList) {
        var rsBlocks = QRRSBlock.getRSBlocks(typeNumber, errorCorrectLevel);
        var buffer = new QRBitBuffer();
        for (var i = 0; i < dataList.length; i++) {
            var data = dataList[i];
            buffer.put(data.mode, 4);
            buffer.put(data.getLength(), QRUtil.getLengthInBits(data.mode, typeNumber));
            data.write(buffer);
        }
        var totalDataCount = 0;
        for (var i = 0; i < rsBlocks.length; i++) {
            totalDataCount += rsBlocks[i].dataCount;
        }
        if (buffer.getLengthInBits() > totalDataCount * 8) {
            throw new Error("code length overflow. (" + buffer.getLengthInBits() + ">" + totalDataCount * 8 + ")");
        }
        if (buffer.getLengthInBits() + 4 <= totalDataCount * 8) {
            buffer.put(0, 4);
        }
        while (buffer.getLengthInBits() % 8 != 0) {
            buffer.putBit(false);
        }
        while (true) {
            if (buffer.getLengthInBits() >= totalDataCount * 8) {
                break;
            }
            buffer.put(QRCodeModel.PAD0, 8);
            if (buffer.getLengthInBits() >= totalDataCount * 8) {
                break;
            }
            buffer.put(QRCodeModel.PAD1, 8);
        }
        return QRCodeModel.createBytes(buffer, rsBlocks);
    };
    QRCodeModel.createBytes = function(buffer, rsBlocks) {
        var offset = 0;
        var maxDcCount = 0;
        var maxEcCount = 0;
        var dcdata = new Array(rsBlocks.length);
        var ecdata = new Array(rsBlocks.length);
        for (var r = 0; r < rsBlocks.length; r++) {
            var dcCount = rsBlocks[r].dataCount;
            var ecCount = rsBlocks[r].totalCount - dcCount;
            maxDcCount = Math.max(maxDcCount, dcCount);
            maxEcCount = Math.max(maxEcCount, ecCount);
            dcdata[r] = new Array(dcCount);
            for (var i = 0; i < dcdata[r].length; i++) {
                dcdata[r][i] = 0xff & buffer.buffer[i + offset];
            }
            offset += dcCount;
            var rsPoly = QRUtil.getErrorCorrectPolynomial(ecCount);
            var rawPoly = new QRPolynomial(dcdata[r], rsPoly.getLength() - 1);
            var modPoly = rawPoly.mod(rsPoly);
            ecdata[r] = new Array(rsPoly.getLength() - 1);
            for (var i = 0; i < ecdata[r].length; i++) {
                var modIndex = i + modPoly.getLength() - ecdata[r].length;
                ecdata[r][i] = (modIndex >= 0) ? modPoly.get(modIndex) : 0;
            }
        }
        var totalCodeCount = 0;
        for (var i = 0; i < rsBlocks.length; i++) {
            totalCodeCount += rsBlocks[i].totalCount;
        }
        var data = new Array(totalCodeCount);
        var index = 0;
        for (var i = 0; i < maxDcCount; i++) {
            for (var r = 0; r < rsBlocks.length; r++) {
                if (i < dcdata[r].length) {
                    data[index++] = dcdata[r][i];
                }
            }
        }
        for (var i = 0; i < maxEcCount; i++) {
            for (var r = 0; r < rsBlocks.length; r++) {
                if (i < ecdata[r].length) {
                    data[index++] = ecdata[r][i];
                }
            }
        }
        return data;
    };
    var QRMode = {
        MODE_NUMBER: 1 << 0,
        MODE_ALPHA_NUM: 1 << 1,
        MODE_8BIT_BYTE: 1 << 2,
        MODE_KANJI: 1 << 3
    };
    var QRErrorCorrectLevel = {
        L: 1,
        M: 0,
        Q: 3,
        H: 2
    };
    var QRMaskPattern = {
        PATTERN000: 0,
        PATTERN001: 1,
        PATTERN010: 2,
        PATTERN011: 3,
        PATTERN100: 4,
        PATTERN101: 5,
        PATTERN110: 6,
        PATTERN111: 7
    };
    var QRUtil = {
        PATTERN_POSITION_TABLE: [
            [],
            [6, 18],
            [6, 22],
            [6, 26],
            [6, 30],
            [6, 34],
            [6, 22, 38],
            [6, 24, 42],
            [6, 26, 46],
            [6, 28, 50],
            [6, 30, 54],
            [6, 32, 58],
            [6, 34, 62],
            [6, 26, 46, 66],
            [6, 26, 48, 70],
            [6, 26, 50, 74],
            [6, 30, 54, 78],
            [6, 30, 56, 82],
            [6, 30, 58, 86],
            [6, 34, 62, 90],
            [6, 28, 50, 72, 94],
            [6, 26, 50, 74, 98],
            [6, 30, 54, 78, 102],
            [6, 28, 54, 80, 106],
            [6, 32, 58, 84, 110],
            [6, 30, 58, 86, 114],
            [6, 34, 62, 90, 118],
            [6, 26, 50, 74, 98, 122],
            [6, 30, 54, 78, 102, 126],
            [6, 26, 52, 78, 104, 130],
            [6, 30, 56, 82, 108, 134],
            [6, 34, 60, 86, 112, 138],
            [6, 30, 58, 86, 114, 142],
            [6, 34, 62, 90, 118, 146],
            [6, 30, 54, 78, 102, 126, 150],
            [6, 24, 50, 76, 102, 128, 154],
            [6, 28, 54, 80, 106, 132, 158],
            [6, 32, 58, 84, 110, 136, 162],
            [6, 26, 54, 82, 110, 138, 166],
            [6, 30, 58, 86, 114, 142, 170]
        ],
        G15: (1 << 10) | (1 << 8) | (1 << 5) | (1 << 4) | (1 << 2) | (1 << 1) | (1 << 0),
        G18: (1 << 12) | (1 << 11) | (1 << 10) | (1 << 9) | (1 << 8) | (1 << 5) | (1 << 2) | (1 << 0),
        G15_MASK: (1 << 14) | (1 << 12) | (1 << 10) | (1 << 4) | (1 << 1),
        getBCHTypeInfo: function(data) {
            var d = data << 10;
            while (QRUtil.getBCHDigit(d) - QRUtil.getBCHDigit(QRUtil.G15) >= 0) {
                d ^= (QRUtil.G15 << (QRUtil.getBCHDigit(d) - QRUtil.getBCHDigit(QRUtil.G15)));
            }
            return ((data << 10) | d) ^ QRUtil.G15_MASK;
        },
        getBCHTypeNumber: function(data) {
            var d = data << 12;
            while (QRUtil.getBCHDigit(d) - QRUtil.getBCHDigit(QRUtil.G18) >= 0) {
                d ^= (QRUtil.G18 << (QRUtil.getBCHDigit(d) - QRUtil.getBCHDigit(QRUtil.G18)));
            }
            return (data << 12) | d;
        },
        getBCHDigit: function(data) {
            var digit = 0;
            while (data != 0) {
                digit++;
                data >>>= 1;
            }
            return digit;
        },
        getPatternPosition: function(typeNumber) {
            return QRUtil.PATTERN_POSITION_TABLE[typeNumber - 1];
        },
        getMask: function(maskPattern, i, j) {
            switch (maskPattern) {
                case QRMaskPattern.PATTERN000:
                    return (i + j) % 2 == 0;
                case QRMaskPattern.PATTERN001:
                    return i % 2 == 0;
                case QRMaskPattern.PATTERN010:
                    return j % 3 == 0;
                case QRMaskPattern.PATTERN011:
                    return (i + j) % 3 == 0;
                case QRMaskPattern.PATTERN100:
                    return (Math.floor(i / 2) + Math.floor(j / 3)) % 2 == 0;
                case QRMaskPattern.PATTERN101:
                    return (i * j) % 2 + (i * j) % 3 == 0;
                case QRMaskPattern.PATTERN110:
                    return ((i * j) % 2 + (i * j) % 3) % 2 == 0;
                case QRMaskPattern.PATTERN111:
                    return ((i * j) % 3 + (i + j) % 2) % 2 == 0;
                default:
                    throw new Error("bad maskPattern:" + maskPattern);
            }
        },
        getErrorCorrectPolynomial: function(errorCorrectLength) {
            var a = new QRPolynomial([1], 0);
            for (var i = 0; i < errorCorrectLength; i++) {
                a = a.multiply(new QRPolynomial([1, QRMath.gexp(i)], 0));
            }
            return a;
        },
        getLengthInBits: function(mode, type) {
            if (1 <= type && type < 10) {
                switch (mode) {
                    case QRMode.MODE_NUMBER:
                        return 10;
                    case QRMode.MODE_ALPHA_NUM:
                        return 9;
                    case QRMode.MODE_8BIT_BYTE:
                        return 8;
                    case QRMode.MODE_KANJI:
                        return 8;
                    default:
                        throw new Error("mode:" + mode);
                }
            } else if (type < 27) {
                switch (mode) {
                    case QRMode.MODE_NUMBER:
                        return 12;
                    case QRMode.MODE_ALPHA_NUM:
                        return 11;
                    case QRMode.MODE_8BIT_BYTE:
                        return 16;
                    case QRMode.MODE_KANJI:
                        return 10;
                    default:
                        throw new Error("mode:" + mode);
                }
            } else if (type < 41) {
                switch (mode) {
                    case QRMode.MODE_NUMBER:
                        return 14;
                    case QRMode.MODE_ALPHA_NUM:
                        return 13;
                    case QRMode.MODE_8BIT_BYTE:
                        return 16;
                    case QRMode.MODE_KANJI:
                        return 12;
                    default:
                        throw new Error("mode:" + mode);
                }
            } else {
                throw new Error("type:" + type);
            }
        },
        getLostPoint: function(qrCode) {
            var moduleCount = qrCode.getModuleCount();
            var lostPoint = 0;
            for (var row = 0; row < moduleCount; row++) {
                for (var col = 0; col < moduleCount; col++) {
                    var sameCount = 0;
                    var dark = qrCode.isDark(row, col);
                    for (var r = -1; r <= 1; r++) {
                        if (row + r < 0 || moduleCount <= row + r) {
                            continue;
                        }
                        for (var c = -1; c <= 1; c++) {
                            if (col + c < 0 || moduleCount <= col + c) {
                                continue;
                            }
                            if (r == 0 && c == 0) {
                                continue;
                            }
                            if (dark == qrCode.isDark(row + r, col + c)) {
                                sameCount++;
                            }
                        }
                    }
                    if (sameCount > 5) {
                        lostPoint += (3 + sameCount - 5);
                    }
                }
            }
            for (var row = 0; row < moduleCount - 1; row++) {
                for (var col = 0; col < moduleCount - 1; col++) {
                    var count = 0;
                    if (qrCode.isDark(row, col)) count++;
                    if (qrCode.isDark(row + 1, col)) count++;
                    if (qrCode.isDark(row, col + 1)) count++;
                    if (qrCode.isDark(row + 1, col + 1)) count++;
                    if (count == 0 || count == 4) {
                        lostPoint += 3;
                    }
                }
            }
            for (var row = 0; row < moduleCount; row++) {
                for (var col = 0; col < moduleCount - 6; col++) {
                    if (qrCode.isDark(row, col) && !qrCode.isDark(row, col + 1) && qrCode.isDark(row, col + 2) && qrCode.isDark(row, col + 3) && qrCode.isDark(row, col + 4) && !qrCode.isDark(row, col + 5) && qrCode.isDark(row, col + 6)) {
                        lostPoint += 40;
                    }
                }
            }
            for (var col = 0; col < moduleCount; col++) {
                for (var row = 0; row < moduleCount - 6; row++) {
                    if (qrCode.isDark(row, col) && !qrCode.isDark(row + 1, col) && qrCode.isDark(row + 2, col) && qrCode.isDark(row + 3, col) && qrCode.isDark(row + 4, col) && !qrCode.isDark(row + 5, col) && qrCode.isDark(row + 6, col)) {
                        lostPoint += 40;
                    }
                }
            }
            var darkCount = 0;
            for (var col = 0; col < moduleCount; col++) {
                for (var row = 0; row < moduleCount; row++) {
                    if (qrCode.isDark(row, col)) {
                        darkCount++;
                    }
                }
            }
            var ratio = Math.abs(100 * darkCount / moduleCount / moduleCount - 50) / 5;
            lostPoint += ratio * 10;
            return lostPoint;
        }
    };
    var QRMath = {
        glog: function(n) {
            if (n < 1) {
                throw new Error("glog(" + n + ")");
            }
            return QRMath.LOG_TABLE[n];
        },
        gexp: function(n) {
            while (n < 0) {
                n += 255;
            }
            while (n >= 256) {
                n -= 255;
            }
            return QRMath.EXP_TABLE[n];
        },
        EXP_TABLE: new Array(256),
        LOG_TABLE: new Array(256)
    };
    for (var i = 0; i < 8; i++) {
        QRMath.EXP_TABLE[i] = 1 << i;
    }
    for (var i = 8; i < 256; i++) {
        QRMath.EXP_TABLE[i] = QRMath.EXP_TABLE[i - 4] ^ QRMath.EXP_TABLE[i - 5] ^ QRMath.EXP_TABLE[i - 6] ^ QRMath.EXP_TABLE[i - 8];
    }
    for (var i = 0; i < 255; i++) {
        QRMath.LOG_TABLE[QRMath.EXP_TABLE[i]] = i;
    }

    function QRPolynomial(num, shift) {
        if (num.length == undefined) {
            throw new Error(num.length + "/" + shift);
        }
        var offset = 0;
        while (offset < num.length && num[offset] == 0) {
            offset++;
        }
        this.num = new Array(num.length - offset + shift);
        for (var i = 0; i < num.length - offset; i++) {
            this.num[i] = num[i + offset];
        }
    }
    QRPolynomial.prototype = {
        get: function(index) {
            return this.num[index];
        },
        getLength: function() {
            return this.num.length;
        },
        multiply: function(e) {
            var num = new Array(this.getLength() + e.getLength() - 1);
            for (var i = 0; i < this.getLength(); i++) {
                for (var j = 0; j < e.getLength(); j++) {
                    num[i + j] ^= QRMath.gexp(QRMath.glog(this.get(i)) + QRMath.glog(e.get(j)));
                }
            }
            return new QRPolynomial(num, 0);
        },
        mod: function(e) {
            if (this.getLength() - e.getLength() < 0) {
                return this;
            }
            var ratio = QRMath.glog(this.get(0)) - QRMath.glog(e.get(0));
            var num = new Array(this.getLength());
            for (var i = 0; i < this.getLength(); i++) {
                num[i] = this.get(i);
            }
            for (var i = 0; i < e.getLength(); i++) {
                num[i] ^= QRMath.gexp(QRMath.glog(e.get(i)) + ratio);
            }
            return new QRPolynomial(num, 0).mod(e);
        }
    };

    function QRRSBlock(totalCount, dataCount) {
        this.totalCount = totalCount;
        this.dataCount = dataCount;
    }
    QRRSBlock.RS_BLOCK_TABLE = [
        [1, 26, 19],
        [1, 26, 16],
        [1, 26, 13],
        [1, 26, 9],
        [1, 44, 34],
        [1, 44, 28],
        [1, 44, 22],
        [1, 44, 16],
        [1, 70, 55],
        [1, 70, 44],
        [2, 35, 17],
        [2, 35, 13],
        [1, 100, 80],
        [2, 50, 32],
        [2, 50, 24],
        [4, 25, 9],
        [1, 134, 108],
        [2, 67, 43],
        [2, 33, 15, 2, 34, 16],
        [2, 33, 11, 2, 34, 12],
        [2, 86, 68],
        [4, 43, 27],
        [4, 43, 19],
        [4, 43, 15],
        [2, 98, 78],
        [4, 49, 31],
        [2, 32, 14, 4, 33, 15],
        [4, 39, 13, 1, 40, 14],
        [2, 121, 97],
        [2, 60, 38, 2, 61, 39],
        [4, 40, 18, 2, 41, 19],
        [4, 40, 14, 2, 41, 15],
        [2, 146, 116],
        [3, 58, 36, 2, 59, 37],
        [4, 36, 16, 4, 37, 17],
        [4, 36, 12, 4, 37, 13],
        [2, 86, 68, 2, 87, 69],
        [4, 69, 43, 1, 70, 44],
        [6, 43, 19, 2, 44, 20],
        [6, 43, 15, 2, 44, 16],
        [4, 101, 81],
        [1, 80, 50, 4, 81, 51],
        [4, 50, 22, 4, 51, 23],
        [3, 36, 12, 8, 37, 13],
        [2, 116, 92, 2, 117, 93],
        [6, 58, 36, 2, 59, 37],
        [4, 46, 20, 6, 47, 21],
        [7, 42, 14, 4, 43, 15],
        [4, 133, 107],
        [8, 59, 37, 1, 60, 38],
        [8, 44, 20, 4, 45, 21],
        [12, 33, 11, 4, 34, 12],
        [3, 145, 115, 1, 146, 116],
        [4, 64, 40, 5, 65, 41],
        [11, 36, 16, 5, 37, 17],
        [11, 36, 12, 5, 37, 13],
        [5, 109, 87, 1, 110, 88],
        [5, 65, 41, 5, 66, 42],
        [5, 54, 24, 7, 55, 25],
        [11, 36, 12],
        [5, 122, 98, 1, 123, 99],
        [7, 73, 45, 3, 74, 46],
        [15, 43, 19, 2, 44, 20],
        [3, 45, 15, 13, 46, 16],
        [1, 135, 107, 5, 136, 108],
        [10, 74, 46, 1, 75, 47],
        [1, 50, 22, 15, 51, 23],
        [2, 42, 14, 17, 43, 15],
        [5, 150, 120, 1, 151, 121],
        [9, 69, 43, 4, 70, 44],
        [17, 50, 22, 1, 51, 23],
        [2, 42, 14, 19, 43, 15],
        [3, 141, 113, 4, 142, 114],
        [3, 70, 44, 11, 71, 45],
        [17, 47, 21, 4, 48, 22],
        [9, 39, 13, 16, 40, 14],
        [3, 135, 107, 5, 136, 108],
        [3, 67, 41, 13, 68, 42],
        [15, 54, 24, 5, 55, 25],
        [15, 43, 15, 10, 44, 16],
        [4, 144, 116, 4, 145, 117],
        [17, 68, 42],
        [17, 50, 22, 6, 51, 23],
        [19, 46, 16, 6, 47, 17],
        [2, 139, 111, 7, 140, 112],
        [17, 74, 46],
        [7, 54, 24, 16, 55, 25],
        [34, 37, 13],
        [4, 151, 121, 5, 152, 122],
        [4, 75, 47, 14, 76, 48],
        [11, 54, 24, 14, 55, 25],
        [16, 45, 15, 14, 46, 16],
        [6, 147, 117, 4, 148, 118],
        [6, 73, 45, 14, 74, 46],
        [11, 54, 24, 16, 55, 25],
        [30, 46, 16, 2, 47, 17],
        [8, 132, 106, 4, 133, 107],
        [8, 75, 47, 13, 76, 48],
        [7, 54, 24, 22, 55, 25],
        [22, 45, 15, 13, 46, 16],
        [10, 142, 114, 2, 143, 115],
        [19, 74, 46, 4, 75, 47],
        [28, 50, 22, 6, 51, 23],
        [33, 46, 16, 4, 47, 17],
        [8, 152, 122, 4, 153, 123],
        [22, 73, 45, 3, 74, 46],
        [8, 53, 23, 26, 54, 24],
        [12, 45, 15, 28, 46, 16],
        [3, 147, 117, 10, 148, 118],
        [3, 73, 45, 23, 74, 46],
        [4, 54, 24, 31, 55, 25],
        [11, 45, 15, 31, 46, 16],
        [7, 146, 116, 7, 147, 117],
        [21, 73, 45, 7, 74, 46],
        [1, 53, 23, 37, 54, 24],
        [19, 45, 15, 26, 46, 16],
        [5, 145, 115, 10, 146, 116],
        [19, 75, 47, 10, 76, 48],
        [15, 54, 24, 25, 55, 25],
        [23, 45, 15, 25, 46, 16],
        [13, 145, 115, 3, 146, 116],
        [2, 74, 46, 29, 75, 47],
        [42, 54, 24, 1, 55, 25],
        [23, 45, 15, 28, 46, 16],
        [17, 145, 115],
        [10, 74, 46, 23, 75, 47],
        [10, 54, 24, 35, 55, 25],
        [19, 45, 15, 35, 46, 16],
        [17, 145, 115, 1, 146, 116],
        [14, 74, 46, 21, 75, 47],
        [29, 54, 24, 19, 55, 25],
        [11, 45, 15, 46, 46, 16],
        [13, 145, 115, 6, 146, 116],
        [14, 74, 46, 23, 75, 47],
        [44, 54, 24, 7, 55, 25],
        [59, 46, 16, 1, 47, 17],
        [12, 151, 121, 7, 152, 122],
        [12, 75, 47, 26, 76, 48],
        [39, 54, 24, 14, 55, 25],
        [22, 45, 15, 41, 46, 16],
        [6, 151, 121, 14, 152, 122],
        [6, 75, 47, 34, 76, 48],
        [46, 54, 24, 10, 55, 25],
        [2, 45, 15, 64, 46, 16],
        [17, 152, 122, 4, 153, 123],
        [29, 74, 46, 14, 75, 47],
        [49, 54, 24, 10, 55, 25],
        [24, 45, 15, 46, 46, 16],
        [4, 152, 122, 18, 153, 123],
        [13, 74, 46, 32, 75, 47],
        [48, 54, 24, 14, 55, 25],
        [42, 45, 15, 32, 46, 16],
        [20, 147, 117, 4, 148, 118],
        [40, 75, 47, 7, 76, 48],
        [43, 54, 24, 22, 55, 25],
        [10, 45, 15, 67, 46, 16],
        [19, 148, 118, 6, 149, 119],
        [18, 75, 47, 31, 76, 48],
        [34, 54, 24, 34, 55, 25],
        [20, 45, 15, 61, 46, 16]
    ];
    QRRSBlock.getRSBlocks = function(typeNumber, errorCorrectLevel) {
        var rsBlock = QRRSBlock.getRsBlockTable(typeNumber, errorCorrectLevel);
        if (rsBlock == undefined) {
            throw new Error("bad rs block @ typeNumber:" + typeNumber + "/errorCorrectLevel:" + errorCorrectLevel);
        }
        var length = rsBlock.length / 3;
        var list = [];
        for (var i = 0; i < length; i++) {
            var count = rsBlock[i * 3 + 0];
            var totalCount = rsBlock[i * 3 + 1];
            var dataCount = rsBlock[i * 3 + 2];
            for (var j = 0; j < count; j++) {
                list.push(new QRRSBlock(totalCount, dataCount));
            }
        }
        return list;
    };
    QRRSBlock.getRsBlockTable = function(typeNumber, errorCorrectLevel) {
        switch (errorCorrectLevel) {
            case QRErrorCorrectLevel.L:
                return QRRSBlock.RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 0];
            case QRErrorCorrectLevel.M:
                return QRRSBlock.RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 1];
            case QRErrorCorrectLevel.Q:
                return QRRSBlock.RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 2];
            case QRErrorCorrectLevel.H:
                return QRRSBlock.RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 3];
            default:
                return undefined;
        }
    };

    function QRBitBuffer() {
        this.buffer = [];
        this.length = 0;
    }
    QRBitBuffer.prototype = {
        get: function(index) {
            var bufIndex = Math.floor(index / 8);
            return ((this.buffer[bufIndex] >>> (7 - index % 8)) & 1) == 1;
        },
        put: function(num, length) {
            for (var i = 0; i < length; i++) {
                this.putBit(((num >>> (length - i - 1)) & 1) == 1);
            }
        },
        getLengthInBits: function() {
            return this.length;
        },
        putBit: function(bit) {
            var bufIndex = Math.floor(this.length / 8);
            if (this.buffer.length <= bufIndex) {
                this.buffer.push(0);
            }
            if (bit) {
                this.buffer[bufIndex] |= (0x80 >>> (this.length % 8));
            }
            this.length++;
        }
    };
    var QRCodeLimitLength = [
        [17, 14, 11, 7],
        [32, 26, 20, 14],
        [53, 42, 32, 24],
        [78, 62, 46, 34],
        [106, 84, 60, 44],
        [134, 106, 74, 58],
        [154, 122, 86, 64],
        [192, 152, 108, 84],
        [230, 180, 130, 98],
        [271, 213, 151, 119],
        [321, 251, 177, 137],
        [367, 287, 203, 155],
        [425, 331, 241, 177],
        [458, 362, 258, 194],
        [520, 412, 292, 220],
        [586, 450, 322, 250],
        [644, 504, 364, 280],
        [718, 560, 394, 310],
        [792, 624, 442, 338],
        [858, 666, 482, 382],
        [929, 711, 509, 403],
        [1003, 779, 565, 439],
        [1091, 857, 611, 461],
        [1171, 911, 661, 511],
        [1273, 997, 715, 535],
        [1367, 1059, 751, 593],
        [1465, 1125, 805, 625],
        [1528, 1190, 868, 658],
        [1628, 1264, 908, 698],
        [1732, 1370, 982, 742],
        [1840, 1452, 1030, 790],
        [1952, 1538, 1112, 842],
        [2068, 1628, 1168, 898],
        [2188, 1722, 1228, 958],
        [2303, 1809, 1283, 983],
        [2431, 1911, 1351, 1051],
        [2563, 1989, 1423, 1093],
        [2699, 2099, 1499, 1139],
        [2809, 2213, 1579, 1219],
        [2953, 2331, 1663, 1273]
    ];

    function _isSupportCanvas() {
        return typeof CanvasRenderingContext2D != "undefined";
    }

    // android 2.x doesn't support Data-URI spec
    function _getAndroid() {
        var android = false;
        var sAgent = navigator.userAgent;

        if (/android/i.test(sAgent)) { // android
            android = true;
            aMat = sAgent.toString().match(/android ([0-9]\.[0-9])/i);

            if (aMat && aMat[1]) {
                android = parseFloat(aMat[1]);
            }
        }

        return android;
    }

    var svgDrawer = (function() {

        var Drawing = function(el, htOption) {
            this._el = el;
            this._htOption = htOption;
        };

        Drawing.prototype.draw = function(oQRCode) {
            var _htOption = this._htOption;
            var _el = this._el;
            var nCount = oQRCode.getModuleCount();
            var nWidth = Math.floor(_htOption.width / nCount);
            var nHeight = Math.floor(_htOption.height / nCount);

            this.clear();

            function makeSVG(tag, attrs) {
                var el = document.createElementNS('http://www.w3.org/2000/svg', tag);
                for (var k in attrs)
                    if (attrs.hasOwnProperty(k)) el.setAttribute(k, attrs[k]);
                return el;
            }

            var svg = makeSVG("svg", {
                'viewBox': '0 0 ' + String(nCount) + " " + String(nCount),
                'width': '100%',
                'height': '100%',
                'fill': _htOption.colorLight
            });
            svg.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:xlink", "http://www.w3.org/1999/xlink");
            _el.appendChild(svg);

            svg.appendChild(makeSVG("rect", {
                "fill": _htOption.colorDark,
                "width": "1",
                "height": "1",
                "id": "template"
            }));

            for (var row = 0; row < nCount; row++) {
                for (var col = 0; col < nCount; col++) {
                    if (oQRCode.isDark(row, col)) {
                        var child = makeSVG("use", {
                            "x": String(row),
                            "y": String(col)
                        });
                        child.setAttributeNS("http://www.w3.org/1999/xlink", "href", "#template")
                        svg.appendChild(child);
                    }
                }
            }
        };
        Drawing.prototype.clear = function() {
            while (this._el.hasChildNodes())
                this._el.removeChild(this._el.lastChild);
        };
        return Drawing;
    })();
    // XXXddahl: this line fails in Chrome, wtf?
    // var useSVG = document.documentElement.tagName.toLowerCase() === "svg";
    var useSVG = false;

    // Drawing in DOM by using Table tag
    var Drawing = useSVG ? svgDrawer : !_isSupportCanvas() ? (function() {
        var Drawing = function(el, htOption) {
            this._el = el;
            this._htOption = htOption;
        };

        /**
         * Draw the QRCode
         *
         * @param {QRCode} oQRCode
         */
        Drawing.prototype.draw = function(oQRCode) {
            var _htOption = this._htOption;
            var _el = this._el;
            var nCount = oQRCode.getModuleCount();
            var nWidth = Math.floor(_htOption.width / nCount);
            var nHeight = Math.floor(_htOption.height / nCount);
            var aHTML = ['<table style="border:0;border-collapse:collapse;">'];

            for (var row = 0; row < nCount; row++) {
                aHTML.push('<tr>');

                for (var col = 0; col < nCount; col++) {
                    aHTML.push('<td style="border:0;border-collapse:collapse;padding:0;margin:0;width:' + nWidth + 'px;height:' + nHeight + 'px;background-color:' + (oQRCode.isDark(row, col) ? _htOption.colorDark : _htOption.colorLight) + ';"></td>');
                }

                aHTML.push('</tr>');
            }

            aHTML.push('</table>');
            _el.innerHTML = aHTML.join('');

            // Fix the margin values as real size.
            var elTable = _el.childNodes[0];
            var nLeftMarginTable = (_htOption.width - elTable.offsetWidth) / 2;
            var nTopMarginTable = (_htOption.height - elTable.offsetHeight) / 2;

            if (nLeftMarginTable > 0 && nTopMarginTable > 0) {
                elTable.style.margin = nTopMarginTable + "px " + nLeftMarginTable + "px";
            }
        };

        /**
         * Clear the QRCode
         */
        Drawing.prototype.clear = function() {
            this._el.innerHTML = '';
        };

        return Drawing;
    })() : (function() { // Drawing in Canvas
        function _onMakeImage() {
            this._elImage.src = this._elCanvas.toDataURL("image/png");
            this._elImage.style.display = "block";
            this._elCanvas.style.display = "none";
        }

        // Android 2.1 bug workaround
        // http://code.google.com/p/android/issues/detail?id=5141
        if (this._android && this._android <= 2.1) {
            var factor = 1 / window.devicePixelRatio;
            var drawImage = CanvasRenderingContext2D.prototype.drawImage;
            CanvasRenderingContext2D.prototype.drawImage = function(image, sx, sy, sw, sh, dx, dy, dw, dh) {
                if (("nodeName" in image) && /img/i.test(image.nodeName)) {
                    for (var i = arguments.length - 1; i >= 1; i--) {
                        arguments[i] = arguments[i] * factor;
                    }
                } else if (typeof dw == "undefined") {
                    arguments[1] *= factor;
                    arguments[2] *= factor;
                    arguments[3] *= factor;
                    arguments[4] *= factor;
                }

                drawImage.apply(this, arguments);
            };
        }

        /**
         * Check whether the user's browser supports Data URI or not
         *
         * @private
         * @param {Function} fSuccess Occurs if it supports Data URI
         * @param {Function} fFail Occurs if it doesn't support Data URI
         */
        function _safeSetDataURI(fSuccess, fFail) {
            var self = this;
            self._fFail = fFail;
            self._fSuccess = fSuccess;

            // Check it just once
            if (self._bSupportDataURI === null) {
                var el = document.createElement("img");
                var fOnError = function() {
                    self._bSupportDataURI = false;

                    if (self._fFail) {
                        _fFail.call(self);
                    }
                };
                var fOnSuccess = function() {
                    self._bSupportDataURI = true;

                    if (self._fSuccess) {
                        self._fSuccess.call(self);
                    }
                };

                el.onabort = fOnError;
                el.onerror = fOnError;
                el.onload = fOnSuccess;
                el.src = "data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w38GIAXDIBKE0DHxgljNBAAO9TXL0Y4OHwAAAABJRU5ErkJggg=="; // the Image contains 1px data.
                return;
            } else if (self._bSupportDataURI === true && self._fSuccess) {
                self._fSuccess.call(self);
            } else if (self._bSupportDataURI === false && self._fFail) {
                self._fFail.call(self);
            }
        };

        /**
         * Drawing QRCode by using canvas
         *
         * @constructor
         * @param {HTMLElement} el
         * @param {Object} htOption QRCode Options
         */
        var Drawing = function(el, htOption) {
            this._bIsPainted = false;
            this._android = _getAndroid();

            this._htOption = htOption;
            this._elCanvas = document.createElement("canvas");
            this._elCanvas.width = htOption.width;
            this._elCanvas.height = htOption.height;
            el.appendChild(this._elCanvas);
            this._el = el;
            this._oContext = this._elCanvas.getContext("2d");
            this._bIsPainted = false;
            this._elImage = document.createElement("img");
            this._elImage.alt = "Scan me!";
            this._elImage.style.display = "none";
            this._el.appendChild(this._elImage);
            this._bSupportDataURI = null;
        };

        /**
         * Draw the QRCode
         *
         * @param {QRCode} oQRCode
         */
        Drawing.prototype.draw = function(oQRCode) {
            var _elImage = this._elImage;
            var _oContext = this._oContext;
            var _htOption = this._htOption;

            var nCount = oQRCode.getModuleCount();
            var nWidth = _htOption.width / nCount;
            var nHeight = _htOption.height / nCount;
            var nRoundedWidth = Math.round(nWidth);
            var nRoundedHeight = Math.round(nHeight);

            _elImage.style.display = "none";
            this.clear();

            for (var row = 0; row < nCount; row++) {
                for (var col = 0; col < nCount; col++) {
                    var bIsDark = oQRCode.isDark(row, col);
                    var nLeft = col * nWidth;
                    var nTop = row * nHeight;
                    _oContext.strokeStyle = bIsDark ? _htOption.colorDark : _htOption.colorLight;
                    _oContext.lineWidth = 1;
                    _oContext.fillStyle = bIsDark ? _htOption.colorDark : _htOption.colorLight;
                    _oContext.fillRect(nLeft, nTop, nWidth, nHeight);

                    // ì•ˆí‹° ì•¨ë¦¬ì–´ì‹± ë°©ì§€ ì²˜ë¦¬
                    _oContext.strokeRect(
                        Math.floor(nLeft) + 0.5,
                        Math.floor(nTop) + 0.5,
                        nRoundedWidth,
                        nRoundedHeight
                    );

                    _oContext.strokeRect(
                        Math.ceil(nLeft) - 0.5,
                        Math.ceil(nTop) - 0.5,
                        nRoundedWidth,
                        nRoundedHeight
                    );
                }
            }

            this._bIsPainted = true;
        };

        /**
         * Make the image from Canvas if the browser supports Data URI.
         */
        Drawing.prototype.makeImage = function() {
            if (this._bIsPainted) {
                _safeSetDataURI.call(this, _onMakeImage);
            }
        };

        /**
         * Return whether the QRCode is painted or not
         *
         * @return {Boolean}
         */
        Drawing.prototype.isPainted = function() {
            return this._bIsPainted;
        };

        /**
         * Clear the QRCode
         */
        Drawing.prototype.clear = function() {
            this._oContext.clearRect(0, 0, this._elCanvas.width, this._elCanvas.height);
            this._bIsPainted = false;
        };

        /**
         * @private
         * @param {Number} nNumber
         */
        Drawing.prototype.round = function(nNumber) {
            if (!nNumber) {
                return nNumber;
            }

            return Math.floor(nNumber * 1000) / 1000;
        };

        return Drawing;
    })();

    /**
     * Get the type by string length
     *
     * @private
     * @param {String} sText
     * @param {Number} nCorrectLevel
     * @return {Number} type
     */
    function _getTypeNumber(sText, nCorrectLevel) {
        var nType = 1;
        var length = _getUTF8Length(sText);

        for (var i = 0, len = QRCodeLimitLength.length; i <= len; i++) {
            var nLimit = 0;

            switch (nCorrectLevel) {
                case QRErrorCorrectLevel.L:
                    nLimit = QRCodeLimitLength[i][0];
                    break;
                case QRErrorCorrectLevel.M:
                    nLimit = QRCodeLimitLength[i][1];
                    break;
                case QRErrorCorrectLevel.Q:
                    nLimit = QRCodeLimitLength[i][2];
                    break;
                case QRErrorCorrectLevel.H:
                    nLimit = QRCodeLimitLength[i][3];
                    break;
            }

            if (length <= nLimit) {
                break;
            } else {
                nType++;
            }
        }

        if (nType > QRCodeLimitLength.length) {
            throw new Error("Too long data");
        }

        return nType;
    }

    function _getUTF8Length(sText) {
        var replacedText = encodeURI(sText).toString().replace(/\%[0-9a-fA-F]{2}/g, 'a');
        return replacedText.length + (replacedText.length != sText ? 3 : 0);
    }

    /**
     * @class QRCode
     * @constructor
     * @example
     * new QRCode(document.getElementById("test"), "http://jindo.dev.naver.com/collie");
     *
     * @example
     * var oQRCode = new QRCode("test", {
     *    text : "http://naver.com",
     *    width : 128,
     *    height : 128
     * });
     *
     * oQRCode.clear(); // Clear the QRCode.
     * oQRCode.makeCode("http://map.naver.com"); // Re-create the QRCode.
     *
     * @param {HTMLElement|String} el target element or 'id' attribute of element.
     * @param {Object|String} vOption
     * @param {String} vOption.text QRCode link data
     * @param {Number} [vOption.width=256]
     * @param {Number} [vOption.height=256]
     * @param {String} [vOption.colorDark="#000000"]
     * @param {String} [vOption.colorLight="#ffffff"]
     * @param {QRCode.CorrectLevel} [vOption.correctLevel=QRCode.CorrectLevel.H] [L|M|Q|H]
     */
    QRCode = function(el, vOption) {
        this._htOption = {
            width: 256,
            height: 256,
            typeNumber: 4,
            colorDark: "#000000",
            colorLight: "#ffffff",
            correctLevel: QRErrorCorrectLevel.H
        };

        if (typeof vOption === 'string') {
            vOption = {
                text: vOption
            };
        }

        // Overwrites options
        if (vOption) {
            for (var i in vOption) {
                this._htOption[i] = vOption[i];
            }
        }

        if (typeof el == "string") {
            el = document.getElementById(el);
        }

        this._android = _getAndroid();
        this._el = el;
        this._oQRCode = null;
        this._oDrawing = new Drawing(this._el, this._htOption);

        if (this._htOption.text) {
            this.makeCode(this._htOption.text);
        }
    };

    /**
     * Make the QRCode
     *
     * @param {String} sText link data
     */
    QRCode.prototype.makeCode = function(sText) {
        this._oQRCode = new QRCodeModel(_getTypeNumber(sText, this._htOption.correctLevel), this._htOption.correctLevel);
        this._oQRCode.addData(sText);
        this._oQRCode.make();
        this._el.title = sText;
        this._oDrawing.draw(this._oQRCode);
        this.makeImage();
    };

    /**
     * Make the Image from Canvas element
     * - It occurs automatically
     * - Android below 3 doesn't support Data-URI spec.
     *
     * @private
     */
    QRCode.prototype.makeImage = function() {
        if (typeof this._oDrawing.makeImage == "function" && (!this._android || this._android >= 3)) {
            this._oDrawing.makeImage();
        }
    };

    /**
     * Clear the QRCode
     */
    QRCode.prototype.clear = function() {
        this._oDrawing.clear();
    };

    /**
     * @name QRCode.CorrectLevel
     */
    QRCode.CorrectLevel = QRErrorCorrectLevel;
})();