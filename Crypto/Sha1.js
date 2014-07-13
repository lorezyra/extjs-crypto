/**
 *
 * @copyright Copyright (c) 2011-2014 ZyraTech.com
 * @license   IP of Richie Bartlett, Jr. (Rich@RichieBartlett.com) [All Rights Reserved.]
 
 Inspired by: http://cdnjs.cloudflare.com/ajax/libs/dropbox.js/0.10.3/dropbox.js
 
 	White Paper:  	FIPS PUB 180-4
		http://en.wikipedia.org/wiki/SHA-1
 */


Ext.define('Ext.Crypto.SHA1', {
	alias: 'crypto.sha1',
	alternateClassName: ['Ext.Crypto.Sha1'],
	requires: [
		'Ext.Crypto',
		'Ext.Crypto.Base64'
	],
	singleton : true,


	data: null,

	_hash: [],

	digestSize: 160, //bits
	
	ROUNDS_MIN: 80, //array size

	resetHash: function () {
		this._hash = [
			0x67452301,
			0xefcdab89,
			0x98badcfe,
			0x10325476,
			0xc3d2e1f0
		];
	},

	K_CONSTANT: [ // http://en.wikipedia.org/wiki/Nothing_up_my_sleeve_number
		0x5A827999, 	// 2^30 * 2^.5
		0x6ED9EBA1, 	// 2^30 * 3^.5
		0x8F1BBCDC,		// 2^30 * 5^.5
		0xCA62C1D6, 	// 2^30 * 10^.5
	],





	/**
	 * setup the SHA1 encoder with user passed configs (if any)
	 */
	constructor: function (config) {
        config = config || {};
        Ext.apply(this, config);
		
		//setup *private* vars:
		this.digestSize = 160;
		this.ROUNDS_MIN = 80;
		
		this.resetHash();
	},

    /**
     * SHA-1 hash algorithm.

	Note 1: All variables are unsigned 32 bits and wrap modulo 2^32 when calculating, except
			ml the message length which is 64 bits, and
			string the message digest which is 160 bits.
	Note 2: All constants in this pseudo code are in big endian.
			Within each word, the most significant byte is stored in the leftmost byte position
     */
	encode: function (string, length) {
		var a, a0, 
			b, b0, 
			c, c0, 
			d, d0, 
			e, e0, 
			limit, 
			n, 
			t, 
			state = [], 
			i = 0, 
			j = 0, 
			_i = 0;
		
		string[ length >> 2 ] |= 1 << (31 - ((length & 0x03) << 3));
		string[ (((length + 8) >> 6) << 4) + 15 ] = length << 3;

		state = Array(this.ROUNDS_MIN);

		a = this._hash[0];
		b = this._hash[1];
		c = this._hash[2];
		d = this._hash[3];
		e = this._hash[4];

		limit = string.length;
		
		while (i < limit) {
            // Working variables
			a0 = a;
			b0 = b;
			c0 = c;
			d0 = d;
			e0 = e;

			// Computation
			for (j = _i = 0; _i < this.ROUNDS_MIN; j = ++_i) {
				if (j < 16) {
					state[j] = string[(i + j) << 2 >> 2] | 0;
				} else {
					n = (state[(j - 3) << 2 >> 2] | 0) ^ (state[(j - 8) << 2 >> 2] | 0) ^ (state[(j - 14) << 2 >> 2] | 0) ^ (state[(j - 16) << 2 >> 2] | 0);
					state[j] = (n << 1) | (n >>> 31);
				}
				
				t = (((((a << 5) | (a >>> 27)) + e) | 0) + state[j << 2 >> 2]) | 0;
				
				
				if (j < 20) {
					t = (t + ((((b & c) | (~b & d)) + this.K_CONSTANT[0]) | 0)) | 0;
				} else if (j < 40) {
					t = (t + (((b ^ c ^ d) + this.K_CONSTANT[1]) | 0)) | 0;
				} else if (j < 60) {
					t = (t + (((b & c) | (b & d) | (c & d)) - 0x70e44324) | 0) | 0;
				} else {
					t = (t + (((b ^ c ^ d) - 0x359d3e2a) | 0)) | 0;
				}
	
				e = d;
				d = c;
				c = (b << 30) | (b >>> 2);
				b = a;
				a = t;
			}

            // Add this chunk's hash to result so far
			a = (a0 + a) | 0;
			b = (b0 + b) | 0;
			c = (c0 + c) | 0;
			d = (d0 + d) | 0;
			e = (e0 + e) | 0;
			i = (i + 16) | 0;
		}


		// Produce the final hash value (big-endian) as a 160 bit number:		
		return Ext.Crypto.Base64.arrayToBase64([a, b, c, d, e]);
	}
	
});
