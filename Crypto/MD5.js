/**
 *
 * @copyright Copyright (c) 2011-2014 ZyraTech.com
 * @license   IP of Richie Bartlett, Jr. (Rich@RichieBartlett.com) [All Rights Reserved.]
 
 Inspired by: http://www.freebsd.org/cgi/cvsweb.cgi/src/lib/libcrypt/crypt-md5.c?rev=1.1;content-type=text%2Fplain
		 http://en.wikipedia.org/wiki/MD5


		NOTE: *** DO NOT USE FOR SECURE ENCRYPTION!! **
		This class is better used for checksum'ing files for transfer and upload...
 */


Ext.define('Ext.Crypto.MD5', {
	alias: 'crypto.md5',
	alternateClassName: ['Ext.Crypto.Md5'],
	requires: [
		'Ext.Crypto',
		'Ext.Crypto.Base64'
	],
	singleton : true,


	data: null,

	/**
	// HASH_CONSTANT & K_CONSTANT can be calculated programmatically...
	//	However, it's far faster to save the CPU cycles and declare them as constants!
	**/
	HASH_CONSTANT: [],
	K_CONSTANT: [], // http://en.wikipedia.org/wiki/Nothing_up_my_sleeve_number

	digestSize: 128, //bits

    /** The number of rounds of the big loop. */
	ROUNDS: 1000,

    /** The number of bytes of the final hash. */
    DEFAULT_BLOCKSIZE: 32,

    /** The prefixes that can be used to identify this crypt() variant (SHA-256). */
    APR1_PREFIX: "$apr1$",

    /** The Identifier of this crypt() variant. */
    MD5_PREFIX: "$1$",









	/* Initialize MD5 hash values (in big endian): */
	resetHash: function () {
		this.HASH_CONSTANT = [
			0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
		];
		
	},

	/* Initialize MD5 key values: */
	resetK: function () {
		/**
		 * This could be programmatically calculated, but having a constant table is *MUCH* faster:
			 for (var i = 0; i < 64; i++) {
				this.K_CONSTANT[i] = (Math.abs(Math.sin(i + 1)) * 0x100000000) | 0;
			}
		*/
		this.K_CONSTANT = [
			0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
			0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
			0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
			0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
			0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
			0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
			0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
			0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
			0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
			0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
			0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
			0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
			0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
			0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
			0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
			0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
		];
		
	},



	/**
	 * setup the MD5 encoder with user passed configs (if any)
	 */
	constructor: function (config) {
        config = config || {};
        Ext.apply(this, config);
		
		//setup *private* vars:
		this.digestSize = 128;
		this.ROUNDS = 1000;
		this.DEFAULT_BLOCKSIZE = 32;
		
		this.resetHash();
		this.resetK();
	},

    /**
     * MD5:encode entry point
		The MD5 hash is calculated according to this algorithm. All values are in little-endian.
	 */
	encode: function (M, offset) {
		var a, b, c, d,
			i = 0,
			M_off = [];
			
		// Swap endian
		for (var i = 0; i < 16; i++) {
			M_offset_i = M[offset + i];
		
			M[offset + i] = (
				(((M_offset_i << 8)  | (M_offset_i >>> 24)) & 0x00ff00ff) |
				(((M_offset_i << 24) | (M_offset_i >>> 8))  & 0xff00ff00)
			);
		}
		
		// Working varialbes
		a = this.HASH_CONSTANT[0];
		b = this.HASH_CONSTANT[1];
		c = this.HASH_CONSTANT[2];
		d = this.HASH_CONSTANT[3];
		
		// Computation - without for loop by manually left-rotating a,b,c,d...
		a = this.FF(a, b, c, d, M[0],  7,  this.K_CONSTANT[0]);
		d = this.FF(d, a, b, c, M[1],  12, this.K_CONSTANT[1]);
		c = this.FF(c, d, a, b, M[2],  17, this.K_CONSTANT[2]);
		b = this.FF(b, c, d, a, M[3],  22, this.K_CONSTANT[3]);
		a = this.FF(a, b, c, d, M[4],  7,  this.K_CONSTANT[4]);
		d = this.FF(d, a, b, c, M[5],  12, this.K_CONSTANT[5]);
		c = this.FF(c, d, a, b, M[6],  17, this.K_CONSTANT[6]);
		b = this.FF(b, c, d, a, M[7],  22, this.K_CONSTANT[7]);
		a = this.FF(a, b, c, d, M[8],  7,  this.K_CONSTANT[8]);
		d = this.FF(d, a, b, c, M[9],  12, this.K_CONSTANT[9]);
		c = this.FF(c, d, a, b, M[10], 17, this.K_CONSTANT[10]);
		b = this.FF(b, c, d, a, M[11], 22, this.K_CONSTANT[11]);
		a = this.FF(a, b, c, d, M[12], 7,  this.K_CONSTANT[12]);
		d = this.FF(d, a, b, c, M[13], 12, this.K_CONSTANT[13]);
		c = this.FF(c, d, a, b, M[14], 17, this.K_CONSTANT[14]);
		b = this.FF(b, c, d, a, M[15], 22, this.K_CONSTANT[15]);
		
		a = this.GG(a, b, c, d, M[1],  5,  this.K_CONSTANT[16]);
		d = this.GG(d, a, b, c, M[6],  9,  this.K_CONSTANT[17]);
		c = this.GG(c, d, a, b, M[11], 14, this.K_CONSTANT[18]);
		b = this.GG(b, c, d, a, M[0],  20, this.K_CONSTANT[19]);
		a = this.GG(a, b, c, d, M[5],  5,  this.K_CONSTANT[20]);
		d = this.GG(d, a, b, c, M[10], 9,  this.K_CONSTANT[21]);
		c = this.GG(c, d, a, b, M[15], 14, this.K_CONSTANT[22]);
		b = this.GG(b, c, d, a, M[4],  20, this.K_CONSTANT[23]);
		a = this.GG(a, b, c, d, M[9],  5,  this.K_CONSTANT[24]);
		d = this.GG(d, a, b, c, M[14], 9,  this.K_CONSTANT[25]);
		c = this.GG(c, d, a, b, M[3],  14, this.K_CONSTANT[26]);
		b = this.GG(b, c, d, a, M[8],  20, this.K_CONSTANT[27]);
		a = this.GG(a, b, c, d, M[13], 5,  this.K_CONSTANT[28]);
		d = this.GG(d, a, b, c, M[2],  9,  this.K_CONSTANT[29]);
		c = this.GG(c, d, a, b, M[7],  14, this.K_CONSTANT[30]);
		b = this.GG(b, c, d, a, M[12], 20, this.K_CONSTANT[31]);
		
		a = this.HH(a, b, c, d, M[5],  4,  this.K_CONSTANT[32]);
		d = this.HH(d, a, b, c, M[8],  11, this.K_CONSTANT[33]);
		c = this.HH(c, d, a, b, M[11], 16, this.K_CONSTANT[34]);
		b = this.HH(b, c, d, a, M[14], 23, this.K_CONSTANT[35]);
		a = this.HH(a, b, c, d, M[1],  4,  this.K_CONSTANT[36]);
		d = this.HH(d, a, b, c, M[4],  11, this.K_CONSTANT[37]);
		c = this.HH(c, d, a, b, M[7],  16, this.K_CONSTANT[38]);
		b = this.HH(b, c, d, a, M[10], 23, this.K_CONSTANT[39]);
		a = this.HH(a, b, c, d, M[13], 4,  this.K_CONSTANT[40]);
		d = this.HH(d, a, b, c, M[0],  11, this.K_CONSTANT[41]);
		c = this.HH(c, d, a, b, M[3],  16, this.K_CONSTANT[42]);
		b = this.HH(b, c, d, a, M[6],  23, this.K_CONSTANT[43]);
		a = this.HH(a, b, c, d, M[9],  4,  this.K_CONSTANT[44]);
		d = this.HH(d, a, b, c, M[12], 11, this.K_CONSTANT[45]);
		c = this.HH(c, d, a, b, M[15], 16, this.K_CONSTANT[46]);
		b = this.HH(b, c, d, a, M[2],  23, this.K_CONSTANT[47]);
		
		a = this.II(a, b, c, d, M[0],  6,  this.K_CONSTANT[48]);
		d = this.II(d, a, b, c, M[7],  10, this.K_CONSTANT[49]);
		c = this.II(c, d, a, b, M[14], 15, this.K_CONSTANT[50]);
		b = this.II(b, c, d, a, M[5],  21, this.K_CONSTANT[51]);
		a = this.II(a, b, c, d, M[12], 6,  this.K_CONSTANT[52]);
		d = this.II(d, a, b, c, M[3],  10, this.K_CONSTANT[53]);
		c = this.II(c, d, a, b, M[10], 15, this.K_CONSTANT[54]);
		b = this.II(b, c, d, a, M[1],  21, this.K_CONSTANT[55]);
		a = this.II(a, b, c, d, M[8],  6,  this.K_CONSTANT[56]);
		d = this.II(d, a, b, c, M[15], 10, this.K_CONSTANT[57]);
		c = this.II(c, d, a, b, M[6],  15, this.K_CONSTANT[58]);
		b = this.II(b, c, d, a, M[13], 21, this.K_CONSTANT[59]);
		a = this.II(a, b, c, d, M[4],  6,  this.K_CONSTANT[60]);
		d = this.II(d, a, b, c, M[11], 10, this.K_CONSTANT[61]);
		c = this.II(c, d, a, b, M[2],  15, this.K_CONSTANT[62]);
		b = this.II(b, c, d, a, M[9],  21, this.K_CONSTANT[63]);
		
		// Add this chunk's hash to result so far:
		a = (this.HASH_CONSTANT[0] + a) | 0;
		b = (this.HASH_CONSTANT[1] + b) | 0;
		c = (this.HASH_CONSTANT[2] + c) | 0;
		d = (this.HASH_CONSTANT[3] + d) | 0;

		// Produce the final hash value (big-endian) as a 160 bit number:		
		return Ext.Crypto.Base64.arrayToBase64([a, b, c, d]);
	},

    FF: function (a, b, c, d, x, s, t) {
        var n = a + ((b & c) | (~b & d)) + x + t;
        return ((n << s) | (n >>> (this.DEFAULT_BLOCKSIZE - s))) + b;
    },

    GG: function (a, b, c, d, x, s, t) {
        var n = a + ((b & d) | (c & ~d)) + x + t;
        return ((n << s) | (n >>> (this.DEFAULT_BLOCKSIZE - s))) + b;
    },

    HH: function (a, b, c, d, x, s, t) {
        var n = a + (b ^ c ^ d) + x + t;
        return ((n << s) | (n >>> (this.DEFAULT_BLOCKSIZE - s))) + b;
    },

    II: function (a, b, c, d, x, s, t) {
        var n = a + (c ^ (b | ~d)) + x + t;
        return ((n << s) | (n >>> (this.DEFAULT_BLOCKSIZE - s))) + b;
    }
	
});
