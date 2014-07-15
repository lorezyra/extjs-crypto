/**
 *
 * @copyright Copyright (c) 2011-2014 ZyraTech.com
 * @license   IP of Richie Bartlett, Jr. (Rich@RichieBartlett.com) [All Rights Reserved.]
 */


Ext.define('Ext.Crypto', {
    alias: 'crypto.crypto',
    alternateClassName: ['Ext.Cryptography', 'Ext.crypto'],

    uses: [
        'Ext.String'
    ],

	singleton : true,

	compatibility: '4.2',

	charSets: {
     	/* CharEncodingISO Latin Alphabet No. 1, a.k.a. ISO-LATIN-1. */
		ISO_8859_1 : "ISO-8859-1",

     	/* Seven-bit ASCII, also known as ISO646-US, also known as the Basic Latin block of the Unicode character set. */
		US_ASCII : "US-ASCII",

     	/* Sixteen-bit Unicode Transformation Format, The byte order specified by a mandatory initial byte-order mark
     		(either order accepted on input, big-endian used on output) */
		UTF_16 : "UTF-16",

     	/* Sixteen-bit Unicode Transformation Format, big-endian byte order. */
		UTF_16BE : "UTF-16BE",

     	/* Sixteen-bit Unicode Transformation Format, little-endian byte order. */
		UTF_16LE : "UTF-16LE",

     	/* Eight-bit Unicode Transformation Format. */
		UTF_8 : "UTF-8"
	},
	
	
	/* Message Digest Algorithms */
	digests: {
		/**
		 * The MD2 message digest algorithm defined in RFC 1319.
		 */
		MD2: "MD2",

		/**
		 * The MD5 message digest algorithm defined in RFC 1321.
		 */
		MD5: "MD5",

		/**
		 * The SHA-1 hash algorithm defined in the FIPS PUB 180-2.
		 */
		SHA_1: "SHA-1",

		/**
		 * The SHA-256 hash algorithm defined in the FIPS PUB 180-2.
		 */
		SHA_256: "SHA-256",

		/**
		 * The SHA-384 hash algorithm defined in the FIPS PUB 180-2.
		 */
		SHA_384: "SHA-384",

		/**
		 * The SHA-512 hash algorithm defined in the FIPS PUB 180-2.
		 */
		SHA_512: "SHA-512"		
	},


	/* default block size */
	DEFAULT_BLOCKSIZE: 16, // 512/32

    /**
     *  MIME chunk size per RFC 2045 section 6.8.
     */
	MIME_CHUNK_SIZE: 76,

	/**
     * PEM chunk size per RFC 1421 section 4.3.2.4.
     */
	PEM_CHUNK_SIZE: 64,

    /**
     * Defines the default buffer size - currently {@value}
     * - must be large enough for at least one encoded block+separator
     */
	DEFAULT_BUFFER_SIZE: 8192,


/*
	constructor: function(config) {
        config = config || {};
        Ext.apply(this, config);
	},
	
	encode: function(value, type) {
		type = (type || 'base64').toLowerCase();

		return this[type](value);
	},
	
	decode: function(value, type) {
		type = (type || 'base64').toLowerCase();

		return this[type](value);
	},
*/


    /**
     * Checks if n is a prime number or not.
     * @param n - integer
     * @return true if n is prime
     */
	isPrime: function (n) {
		var factor,
			sqrtN = Math.sqrt(n);

		for (factor = 2; factor <= sqrtN; factor++) {
			if (!(n % factor)) {
				return false;
			}
		}

		return true;
	},

    /**
     * Get decimal portion of n
     * @param n - integer
     * @return decimal (32 bit integer)
     */
	fractionalPart: function (n) {
		//return ((x - Math.floor(x)) * 0x100000000) | 0;
		return ((n - (n | 0)) * 0x100000000) | 0;
	},

    /**
     * Checks if a byte value is whitespace or not.
     * Whitespace is taken to mean: space, tab, CR, LF
     * @param byteToCheck
     *            the byte to check
     * @return true if byte is whitespace, otherwise false
     */
	isWhiteSpace: function (byteToCheck) {
        switch (byteToCheck) {
            case ' ' : /* 0x0020  // space char */
            case '\n': /* 0x000A  // Line Feed <LF> */
            case '\r': /* 0x000D  // Carriage Return <CR> */
            case '\t': /* 0x0009  // Horizontal Tab <HT> */
			case 0x000C: // Form Separator <FF>
			case 0x2028: // Line Separator <LS>
			case 0x2029: // Paragraph Separator <PS>		
                return true;
            default :
                return false;
        }
    },

   //NOTE: only supports US_ASCII; not UTF_8 safe
	reverse: function (/*String*/ strg){//v2.0
	   //return strg.split('').reverse().join('');
	   return Array.from(strg).reverse().join('');

	}//end function reverseString

});