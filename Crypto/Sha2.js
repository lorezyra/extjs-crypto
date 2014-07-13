/**
 *
 * @copyright Copyright (c) 2011-2014 ZyraTech.com
 * @license   IP of Richie Bartlett, Jr. (Rich@RichieBartlett.com) [All Rights Reserved.]
 
 Inspired by: http://cdnjs.cloudflare.com/ajax/libs/dropbox.js/0.10.3/dropbox.js
		 http://en.wikipedia.org/wiki/SHA-2
		 http://www.akkadia.org/drepper/SHA-crypt.txt
 */


Ext.define('Ext.Crypto.SHA2', {
	alias: 'crypto.sha2',
	alternateClassName: ['Ext.Crypto.Sha2'],
	requires: [
		'Ext.Crypto',
		'Ext.Crypto.Base64',
		'Ext.Crypto.SHA1'
	],
	singleton : true,


	data: null,

	HASH_CONSTANT: [],

	K_CONSTANT: [], // http://en.wikipedia.org/wiki/Nothing_up_my_sleeve_number

	digestSize: 256, //bits

	/** Default number of rounds if not explicitly specified. */
	ROUNDS_DEFAULT: 5000,

    /** Maximum number of rounds. */
    ROUNDS_MAX: 999999999,

    /** Minimum number of rounds. */
    ROUNDS_MIN: 1000,

    /** Prefix for optional rounds specification. */
    ROUNDS_PREFIX: "rounds=",

    /** The number of bytes the final hash value will have (SHA-256 variant). */
    SHA256_BLOCKSIZE: 32,

    /** The prefixes that can be used to identify this crypt() variant (SHA-256). */
    SHA256_PREFIX: "$5$",

    /** The number of bytes the final hash value will have (SHA-512 variant). */
    SHA512_BLOCKSIZE: 64,

    /** The prefixes that can be used to identify this crypt() variant (SHA-512). */
    SHA512_PREFIX: "$6$",

    /** The pattern to match valid salt values. */
    SALT_PATTERN: Pattern.compile("^\\$([56])\\$(rounds=(\\d+)\\$)?([\\.\\/a-zA-Z0-9]{1,16}).*"),








	/**
	// HASH_CONSTANT & K_CONSTANT can be calculated programmatically...
	//	However, it's far faster to save the CPU cycles and declare them as constants!

	var n = 2, nPrime = 0;
	while (nPrime < 64) { // calculate the hash and key for SHA256
		if (Ext.Crypto.isPrime(n)) {
			if (nPrime < 8) {
				this.HASH_CONSTANT[nPrime] = Ext.Crypto.fractionalPart(Math.pow(n, 1 / 2));
			}
			this.K_CONSTANT[nPrime] = Ext.Crypto.fractionalPart(Math.pow(n, 1 / 3));

			nPrime++;
		}

		n++;
	}
	**/

	/* Initialize SHA2-224 hash values (in big endian): */
	resetHash224: function () {
		// The second 32 bits of the fractional parts of the square roots of the 9th through 16th primes 23..53
		this.HASH_CONSTANT = [
			0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
		];
		
	},

	/* Initialize SHA2-224 key values: */
	resetK224: function () {
		// first 32 bits of the fractional parts of the square roots of the first 64 primes 2..311
		this.K_CONSTANT = [
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
		];
		
	},

	/* Initialize SHA2-256 hash values: */
	resetHash256: function () {
		// first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19
		this.HASH_CONSTANT = [
			0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
		];
		
	},

	/* Initialize SHA2-256 key values: (same as SHA2-224) */
	resetK256: resetK224,

	/* Initialize SHA2-384 hash values: */
	resetHash384: function () {
		// 64-bit hash values taken from the 9th through 16th primes
		this.HASH_CONSTANT = [
			0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 
			0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
		];
		
	},

	/* Initialize SHA2-384 key values: (same as SHA2-512) */
	resetK384: resetK512,

	/* Initialize SHA2-512 hash values (in big endian): */
	resetHash512: function () {
		// first 64 bits of the fractional parts of the square roots of the first 8 primes 2..19
		this.HASH_CONSTANT = [
			0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 
			0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
		];
		
	},

	/* Initialize SHA2-512 key values: */
	resetK512: function () {
		// 64-bit hash values taken from the first 80 primes 2..409
		this.K_CONSTANT = [
			0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
			0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
			0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
			0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
			0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
			0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
			0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
			0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
			0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
			0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
			0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
			0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
			0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
			0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
			0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
			0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
		];
		
	},

	/**
	 * setup the SHA2 encoder with user passed configs (if any)
	 */
	constructor: function (config) {
        config = config || {};
        Ext.apply(this, config);
		
		//setup *private* vars:
		this.digestSize = 256;
		this.ROUNDS_MIN = 1000;
		
		//this.resetHash256();
		//this.resetK256();
	},

    /**
     * SHA-2:encode entry point

		** Defaults to SHA2:256 implementation **
	 */
	encode: function(value, type) {
		type = (type || 'sha256').toLowerCase();

		try {
			return this[type](value);
		} catch(e) {
			//<debug>
			Ext.Error.raise("Invalid function call.¥n" + e.description);
			//</debug>
		}
	},

    /**
     * SHA-2:256 hash algorithm.

		Note 1: All variables are 32 bit unsigned integers and addition is calculated modulo 232
		Note 2: For each round, there is one round constant k[i] and one entry in the message schedule array w[i], 0 ≤ i ≤ 63
		Note 3: The compression function uses 8 working variables, a through h
		Note 4: Big-endian convention is used when expressing the constants in this pseudocode,
			and when parsing message block data from bytes to words, for example,
			the first word of the input message "abc" after padding is 0x61626380
	 */
	sha256: function(string, length) {
		var a, a0, 
			b, b0, 
			c, c0, 
			d, d0, 
			e, e0, 
			f, f0, 
			g, g0, 
			h, h0, 
			gamma0, gamma0x, 
			gamma1, gamma1x, 
			i = 0, 
			_i = 0, 
			j = 0, 
			t1, t2,
			limit, maj, 
			sigma0, sigma1, 
			ch, sj, 
			state = Array(80);

		string[length >> 2] |= 1 << (this.SHA256_BLOCKSIZE - 1 - ((length & 0x03) << 3));
		string[(((length + 8) >> 6) << 4) + 15] = length << 3;
		
		this.resetHash256();
		this.resetK256();

		// Initialize working variables to current hash value:
		a = this.HASH_CONSTANT[0];
		b = this.HASH_CONSTANT[1];
		c = this.HASH_CONSTANT[2];
		d = this.HASH_CONSTANT[3];
		e = this.HASH_CONSTANT[4];
		f = this.HASH_CONSTANT[5];
		g = this.HASH_CONSTANT[6];
		h = this.HASH_CONSTANT[7];

		limit = string.length;

		// Process the message in successive 512-bit chunks:
		while (i < limit) {
			a0 = a;
			b0 = b;
			c0 = c;
			d0 = d;
			e0 = e;
			f0 = f;
			g0 = g;
			h0 = h;

			for (j = _i = 0; _i < 64; j = ++_i) {
				if (j < 16) {
					sj = state[j] = string[(i + j) << 2 >> 2] | 0;
				} else {
					//Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
					gamma0x = state[(j - 15) << 2 >> 2] | 0;
					gamma0 = ((gamma0x << 25) | (gamma0x >>> 7)) ^ ((gamma0x << 14) | (gamma0x >>> 18)) ^ (gamma0x >>> 3);
					gamma1x = state[(j - 2) << 2 >> 2] | 0;
					gamma1 = ((gamma1x << 15) | (gamma1x >>> 17)) ^ ((gamma1x << 13) | (gamma1x >>> 19)) ^ (gamma1x >>> 10);
					sj = state[j] = (((gamma0 + (state[(j - 7) << 2 >> 2] | 0)) | 0) + ((gamma1 + (state[(j - 16) << 2 >> 2] | 0)) | 0)) | 0;
				}

				ch = (e & f) ^ (~e & g);
				maj = (a & b) ^ (a & c) ^ (b & c);

				sigma0 = ((a << 30) | (a >>> 2)) ^ ((a << 19) | (a >>> 13)) ^ ((a << 10) | (a >>> 22));
				sigma1 = ((e << 26) | (e >>> 6)) ^ ((e << 21) | (e >>> 11)) ^ ((e << 7) | (e >>> 25));

				t1 = (((((h + sigma1) | 0) + ((ch + sj) | 0)) | 0) + (this.K_CONSTANT[j << 2 >> 2] | 0)) | 0;
				t2 = (sigma0 + maj) | 0;

				h = g;
				g = f;
				f = e;
				e = (d + t1) | 0;
				d = c;
				c = b;
				b = a;
				a = (t1 + t2) | 0;
			}

			//Add the compressed chunk to the current hash value:
			a = (a0 + a) | 0;
			b = (b0 + b) | 0;
			c = (c0 + c) | 0;
			d = (d0 + d) | 0;
			e = (e0 + e) | 0;
			f = (f0 + f) | 0;
			g = (g0 + g) | 0;
			h = (h0 + h) | 0;
			i += 16; // words
		}

		return Ext.Crypto.Base64.arrayToBase64([a, b, c, d, e, f, g, h]);
	},


    /**
     * SHA-2:224 hash algorithm.
	   SHA-224 is identical to SHA-256, except that:
			the initial hash values h0 through h7 are different, and
			the output is constructed by omitting h7.
	 */
	sha224: function(string, length) {
		var a, a0, 
			b, b0, 
			c, c0, 
			d, d0, 
			e, e0, 
			f, f0, 
			g, g0, 
			h, h0, 
			gamma0, gamma0x, 
			gamma1, gamma1x, 
			i = 0, 
			_i = 0, 
			j = 0, 
			t1, t2,
			limit, maj, 
			sigma0, sigma1, 
			ch, sj, 
			state = Array(80);

		string[length >> 2] |= 1 << (this.SHA256_BLOCKSIZE - 1 - ((length & 0x03) << 3));
		string[(((length + 8) >> 6) << 4) + 15] = length << 3;
		
		this.resetHash224();
		this.resetK224();

		// Initialize working variables to current hash value:
		a = this.HASH_CONSTANT[0];
		b = this.HASH_CONSTANT[1];
		c = this.HASH_CONSTANT[2];
		d = this.HASH_CONSTANT[3];
		e = this.HASH_CONSTANT[4];
		f = this.HASH_CONSTANT[5];
		g = this.HASH_CONSTANT[6];
		h = this.HASH_CONSTANT[7];

		limit = string.length;

		// Process the message in successive 512-bit chunks:
		while (i < limit) {
			a0 = a;
			b0 = b;
			c0 = c;
			d0 = d;
			e0 = e;
			f0 = f;
			g0 = g;
			h0 = h;

			for (j = _i = 0; _i < 64; j = ++_i) {
				if (j < 16) {
					sj = state[j] = string[(i + j) << 2 >> 2] | 0;
				} else {
					//Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
					gamma0x = state[(j - 15) << 2 >> 2] | 0;
					gamma0 = ((gamma0x << 25) | (gamma0x >>> 7)) ^ ((gamma0x << 14) | (gamma0x >>> 18)) ^ (gamma0x >>> 3);
					gamma1x = state[(j - 2) << 2 >> 2] | 0;
					gamma1 = ((gamma1x << 15) | (gamma1x >>> 17)) ^ ((gamma1x << 13) | (gamma1x >>> 19)) ^ (gamma1x >>> 10);
					sj = state[j] = (((gamma0 + (state[(j - 7) << 2 >> 2] | 0)) | 0) + ((gamma1 + (state[(j - 16) << 2 >> 2] | 0)) | 0)) | 0;
				}

				ch = (e & f) ^ (~e & g);
				maj = (a & b) ^ (a & c) ^ (b & c);

				sigma0 = ((a << 30) | (a >>> 2)) ^ ((a << 19) | (a >>> 13)) ^ ((a << 10) | (a >>> 22));
				sigma1 = ((e << 26) | (e >>> 6)) ^ ((e << 21) | (e >>> 11)) ^ ((e << 7) | (e >>> 25));

				t1 = (((((h + sigma1) | 0) + ((ch + sj) | 0)) | 0) + (this.K_CONSTANT[j << 2 >> 2] | 0)) | 0;
				t2 = (sigma0 + maj) | 0;

				h = g;
				g = f;
				f = e;
				e = (d + t1) | 0;
				d = c;
				c = b;
				b = a;
				a = (t1 + t2) | 0;
			}

			//Add the compressed chunk to the current hash value:
			a = (a0 + a) | 0;
			b = (b0 + b) | 0;
			c = (c0 + c) | 0;
			d = (d0 + d) | 0;
			e = (e0 + e) | 0;
			f = (f0 + f) | 0;
			g = (g0 + g) | 0;
			h = (h0 + h) | 0;
			i += 16; // words
		}

		return Ext.Crypto.Base64.arrayToBase64([a, b, c, d, e, f, g]);
	},


    /**
     * SHA-2:384 hash algorithm.
		// TODO
	 */
	sha384: function(string, length) {
		return false;
	},


    /**
     * SHA-2:512 hash algorithm.
		// TODO
	 */
	sha512: function(string, length) {
		return false;
	}
	
});
