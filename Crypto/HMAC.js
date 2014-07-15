/**
 *
 * @copyright Copyright (c) 2011-2014 ZyraTech.com
 * @license   IP of Richie Bartlett, Jr. (Rich@RichieBartlett.com) [All Rights Reserved.]
 
 Inspired by: http://cdnjs.cloudflare.com/ajax/libs/dropbox.js/0.10.3/dropbox.js
		 http://en.wikipedia.org/wiki/HMAC
 */


Ext.define('Ext.Crypto.HMAC', {
	alias: 'crypto.hmac',
	alternateClassName: ['Ext.Crypto.HmacSha'],
	requires: [
		'Ext.Crypto',
		'Ext.Crypto.SHA1'
	],
	singleton : true,


	key: null,
	
	/* Blocksize is 64 (bytes) when using one of the following hash functions: SHA-1, MD5, RIPEMD-128/160. */
	BLOCK_SIZE: 64,

	/* Blocksize of hash in bytes */
	HASH_BLOCK_SIZE: 16,

	/* inner pad constant */
	INNER_PAD: 0x36363636,

	/* outer pad constant */
	OUTER_PAD: 0x5C5C5C5C,



	/**
	 * setup the HMAC encoder with user passed configs (if any)
	 */
	constructor: function (config) {
        config = config || {};
        Ext.apply(this, config);
		
	},


    /**
     * inner pad algorithm.
     */
	iPAD: function() {
		var _i, i, 
			_results = [];

		for (i = _i = 0; _i < this.HASH_BLOCK_SIZE; i = ++_i) {
			_results.push(this.key[i] ^ this.INNER_PAD);
		}

		return _results;
	},

    /**
     * outer pad algorithm.
     */
	oPAD: function() {
		var _i, i, 
			_results = [];

		for (i = _i = 0; _i < this.HASH_BLOCK_SIZE; i = ++_i) {
			_results.push(this.key[i] ^ this.OUTER_PAD);
		}

		return _results;
	},

    /**
     * SHA-1 HMAC hash algorithm.
     */
	encode: function (string, key, length, keyLength) {
		var hash1;

		if (key.length > this.HASH_BLOCK_SIZE) {
			this.key = Ext.Crypto.SHA1.encode(key, keyLength);
		}
		
		hash1 = Ext.Crypto.SHA1.encode(this.iPAD().concat(string), this.BLOCK_SIZE + length);

		return Ext.Crypto.SHA1.encode(this.oPAD().concat(hash1), this.BLOCK_SIZE + 20);
    }

});
