/**
 *
 * @copyright Copyright (c) 2011-2014 ZyraTech.com
 * @license   IP of Richie Bartlett, Jr. (Rich@RichieBartlett.com) [All Rights Reserved.]
 
 Inspired by: http://svn.apache.org/repos/asf/webservices/commons/trunk/modules/util/
			  https://commons.apache.org/proper/commons-codec/apidocs/src-html/org/apache/commons/codec/binary/BaseNCodec.html
  Technical white paper on base64 implementation: 
  	http://www.ietf.org/rfc/rfc3548.txt
	http://www.ietf.org/rfc/rfc2045.txt
 */


//TODO: create baseNcodec? https://commons.apache.org/proper/commons-codec/apidocs/src-html/org/apache/commons/codec/binary/BaseNCodec.html

/**
 * @class Ext.Crypto.Base64
 *
 * Base64 is a group of similar binary-to-text encoding schemes that represent binary data in an ASCII string format by
 * translating it into a radix-64 representation.
 *
 * This class is an implementation of base64 encoding and decoding functions and is UTF-8 safe.
 *
 * @singleton
 */
Ext.define('Ext.Crypto.Base64', {
	alias: 'crypto.base64',
	alternateClassName: ['Ext.Crypto.base64'],
	requires: 'Ext.Crypto',
	singleton : true,

	
	/* End Of File code*/
	EOF: -1,

    /**
     * BASE32 characters are 6 bits in length.
     * They are formed by taking a block of 3 octets to form a 24-bit string,
     * which is converted into 4 BASE64 characters.
     */
    BITS_PER_ENCODED_BYTE: 6,
    BYTES_PER_UNENCODED_BLOCK: 3,
    BYTES_PER_ENCODED_BLOCK: 4,

    /* Chunk separator per RFC 2045 section 2.1. */
	CHUNK_SEPARATOR: [
		'\r' /* 0x000D */, // Carriage Return <CR>
		'\n' /* 0x000A */, // Line Feed <LF>
		0x2028, // Line Separator <LS>
		0x2029  // Paragraph Separator <PS>		
	],
	
    /* Byte used to pad encoded output. */
	PAD_DEFAULT: '=',
	PAD: PAD_DEFAULT, // instance variable just in case it needs to vary later
	
    /**
     * @private
     */
	STANDARD_ENCODE_TABLE: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",

    /**
     * This is a copy of the STANDARD_ENCODE_TABLE above, but with + and /
     * changed to - and _ to make the encoded Base64 results more URL-SAFE.
     * This table is only used when the Base64's mode is set to URL-SAFE.
     */
	URL_SAFE_ENCODE_TABLE: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",

    /**
     * This array is a lookup table that translates Unicode characters drawn from the "Base64 Alphabet" (as specified
     * in Table 1 of RFC 2045) into their 6-bit positive integer equivalents. Characters that are not in the Base64
     * alphabet but fall within the bounds of the array are translated to -1.
     *
     * Note: '+' and '-' both decode to 62. '/' and '_' both decode to 63. This means decoder seamlessly handles both
     * URL_SAFE and STANDARD base64. (The encoder, on the other hand, needs to know ahead of time what to emit).
     *
     * Thanks to "commons" project in ws.apache.org for this code.
     * http://svn.apache.org/repos/asf/webservices/commons/trunk/modules/util/
     */
    DECODE_TABLE: [
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, 62, -1, 63, 52, 53, 54,
            55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4,
            5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, -1, -1, -1, -1, 63, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34,
            35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
    ],

    /** 
     * @private
	 * Mask used to extract 6 bits; used when encoding
	 */
	MASK_6BITS: 0x3F,

    /*
     * @private
	 * Convenience variable to help us determine when our buffer is going to run out of room and needs resizing.
	 */
	decodeSize: 0,

    /*
     * @private
	 * Convenience variable to help us determine when our buffer is going to run out of room and needs resizing. 
	 */
	encodeSize: 0,

    /**
     * @private
     * Chunksize for encoding. Not used when decoding.
     * A value of zero or less implies no chunking of the encoded data.
     * Rounded down to nearest multiple of encodedBlockSize.
     */
	lineLength: 0,

    /**
     * @private
     * Size of chunk separator. Not used unless {@link #lineLength} &gt; 0.
     */
    chunkSeparatorLength: 1,

    /*
     * @private
	 * default the table to use for codec
	 */
	encodeTable: this.STANDARD_ENCODE_TABLE,

    /*
     * @private
	 * table to use for codec with default pad code
	 */
	keyMap: this.encodeTable + this.PAD_DEFAULT,




	/**
	 * setup the base64 en/decoder with user passed configs (if any)
	 */
	constructor: function (config) {
        config = config || {};
        Ext.apply(this, config);
		
		this.setKeyMap();
	},
	

	/**
	 * Function resets the keyMap to the encodeTable config and adds the Pad code
	 */
	setKeyMap: function () {
        this.keyMap = this.encodeTable + this.PAD;
    },

	/**
	 * Function returns the boolean value if url-safe table is used for encoding
	 */
	isUrlSafe: function () {
        return this.encodeTable == this.URL_SAFE_ENCODE_TABLE;
    },


    /**
     * Encodes given string in to base64 formatted string
     * @param input
     * @returns {string}
     */
	encode: function (value) {
		var len,
			chr1,
			chr2,
			chr3 = "",
			enc1,
			enc2,
			enc3,
			enc4 = "",
			output = '',
			i = 0;
		
		input = this._utf8_encode(input);
		len = input.length;
		
		while (i < len) {
			chr1 = input.charCodeAt(i++);
			chr2 = input.charCodeAt(i++);
			chr3 = input.charCodeAt(i++);
			
			enc1 = chr1 >> 2;
			enc2 = ((chr1 & this.BYTES_PER_UNENCODED_BLOCK) << this.BYTES_PER_ENCODED_BLOCK) | (chr2 >> this.BYTES_PER_ENCODED_BLOCK);
			enc3 = ((chr2 & 15) << 2) | (chr3 >> this.BITS_PER_ENCODED_BYTE);
			enc4 = chr3 & this.MASK_6BITS;
			
			if (isNaN(chr2)) {
				enc3 = enc4 = this.MASK_6BITS + 1;
			} else if (isNaN(chr3)) {
				enc4 = this.MASK_6BITS + 1;
			}
			
			output += this.encodeTable.charAt(enc1) +
				this.keyMap.charAt(enc2) +
				this.keyMap.charAt(enc3) +
				this.keyMap.charAt(enc4);
			chr1 = chr2 = chr3 = "";
			enc1 = enc2 = enc3 = enc4 = "";
		}
		
		return output;
	},
	

    /**
     * Decodes given base64 formatted string
     * @param input
     * @returns {string}
     */
	decode: function (value) {
		var base64test,
			len,
			chr1,
			chr2,
			chr3 = "",
			enc1,
			enc2,
			enc3,
			enc4 = "",
			output = "",
			i = 0;
		
		if ( isURLsafe() ) {

			base64test = /[^A-Za-z0-9\-\_\=]/g;

			if ( base64test.exec(value) ) {
				//<debug>
				Ext.Error.raise("There were invalid base64 characters in the input text.\n" +
				"Valid base64 (URL safe) characters are A-Z, a-z, 0-9, '-', '_',and '" + this.PAD + "'\n" +
				"Expect errors in decoding.");
				//</debug>
			}

			// remove all characters that are not in the URL safe "alphabet": A-Z, a-z, 0-9, -, _, or =
			input = value.replace(base64test, "");

		} else {

			base64test = /[^A-Za-z0-9\+\/\=]/g;

			if ( base64test.exec(value) ) {
				//<debug>
				Ext.Error.raise("There were invalid base64 characters in the input text.\n" +
				"Valid base64 characters are A-Z, a-z, 0-9, '+', '/',and '" + this.PAD + "'\n" +
				"Expect errors in decoding.");
				//</debug>
			}

			// remove all characters that are not in the Standard "alphabet": A-Z, a-z, 0-9, +, /, or =
			input = value.replace(base64test, "");
		}
		
		while (i < input.length) {
			enc1 = this.keyMap.indexOf(input.charAt(i++));
			enc2 = this.keyMap.indexOf(input.charAt(i++));
			enc3 = this.keyMap.indexOf(input.charAt(i++));
			enc4 = this.keyMap.indexOf(input.charAt(i++));
			
			chr1 = (enc1 << 2) | (enc2 >> this.BYTES_PER_ENCODED_BLOCK);
			chr2 = ((enc2 & 15) << this.BYTES_PER_ENCODED_BLOCK) | (enc3 >> 2);
			chr3 = ((enc3 & this.BYTES_PER_UNENCODED_BLOCK) << this.BITS_PER_ENCODED_BYTE) | enc4;
			
			output += String.fromCharCode(chr1);
			
			if (enc3 != this.MASK_6BITS + 1) {
				output += String.fromCharCode(chr2);
			}
			if (enc4 != this.MASK_6BITS + 1) {
				output += String.fromCharCode(chr3);
			}
			
			chr1 = chr2 = chr3 = "";
			enc1 = enc2 = enc3 = enc4 = "";
		
		}
		
		return this._utf8_decode(output);
	},
	
    /**
     * Returns whether or not the octet is in the base 64 alphabet.
     *
     * @param octet
	 */
	isBase64: function (octet) {
        return octet == this.PAD_DEFAULT || (octet >= 0 && octet < this.DECODE_TABLE.length && this.DECODE_TABLE[octet] != -1);
    },
	
    /**
     * Generates a string of random chars from the Base64 alphabet.
     *
     * @param num
     *            Number of chars to generate.
     */
	getRandomSalt: function (num) {
        var rand, 
			i = 1,
			saltString = "";
        
		for (i = 1; i <= num; i++) {
			rand = Ext.Number.randomInt(0, this.keyMap.length); //<<-- Math.random() - not as reliable as a closed system such as a UNIX server.
            
			saltString += this.keyMap.charAt(rand);
        }

        return saltString;
    },
	
	
	arrayToBase64: function(array) {
		var i2, 
			trit,
			i = 0, 
			string = "", 
			limit = array.length * this.BYTES_PER_ENCODED_BLOCK;

		while (i < limit) {
			i2 = i;
			trit = ((array[i2 >> 2] >> ((this.BYTES_PER_UNENCODED_BLOCK - (i2 & this.BYTES_PER_UNENCODED_BLOCK)) << this.BYTES_PER_UNENCODED_BLOCK)) & 0xFF) << 16;
			i2++;
			trit |= ((array[i2 >> 2] >> ((this.BYTES_PER_UNENCODED_BLOCK - (i2 & this.BYTES_PER_UNENCODED_BLOCK)) << this.BYTES_PER_UNENCODED_BLOCK)) & 0xFF) << 8;
			i2++;
			trit |= (array[i2 >> 2] >> ((this.BYTES_PER_UNENCODED_BLOCK - (i2 & this.BYTES_PER_UNENCODED_BLOCK)) << this.BYTES_PER_UNENCODED_BLOCK)) & 0xFF;
			string += this.keyMap[ (trit >> 18) & this.MASK_6BITS ];
			string += this.keyMap[ (trit >> 12) & this.MASK_6BITS ];
			i++;

			if (i >= limit) {
				string += this.PAD;
			} else {
				string += this.keyMap[ (trit >> this.BITS_PER_ENCODED_BYTE) & this.MASK_6BITS ];
			}

			i++;

			if (i >= limit) {
				string += this.PAD;
			} else {
				string += this.keyMap[ trit & this.MASK_6BITS ];
			}

			i++;

		}
		return string;
	},

    /**
     * @private
     * UTF-8 encoding
     */
    _utf8_encode : function (string) {
        string = string.replace(/\r\n/g,"\n");
        var utftext = '',
            n = 0,
            len = string.length;

        for (n = 0; n < len; n++) {

            var c = string.charCodeAt(n);

            if (c < 128) {
                utftext += String.fromCharCode(c);
            } else if ((c > 127) && (c < 2048)) {
                utftext += String.fromCharCode((c >> this.BITS_PER_ENCODED_BYTE) | 192);
                utftext += String.fromCharCode((c & this.MASK_6BITS) | 128);
            } else {
                utftext += String.fromCharCode((c >> 12) | 224);
                utftext += String.fromCharCode(((c >> this.BITS_PER_ENCODED_BYTE) & 63) | 128);
                utftext += String.fromCharCode((c & this.MASK_6BITS) | 128);
            }

        }

        return utftext;
    },

    /**
     * @private
     * UTF-8 decoding
     */
    _utf8_decode : function (utftext) {
        var string = '',
            i = 0,
            c = 0,
            c3 = 0,
            c2 = 0,
            len = utftext.length;

        while (i < len) {
            c = utftext.charCodeAt(i);

            if (c < 128) {
                string += String.fromCharCode(c);
                i++;
            } else if ((c > 191) && (c < 224)) {
                c2 = utftext.charCodeAt(i + 1);
                string += String.fromCharCode(((c & 31) << this.BITS_PER_ENCODED_BYTE) | (c2 & this.MASK_6BITS));
                i += 2;
            } else {
                c2 = utftext.charCodeAt(i + 1);
                c3 = utftext.charCodeAt(i + 2);
                string += String.fromCharCode(((c & 15) << 12) | ((c2 & this.MASK_6BITS) << this.BITS_PER_ENCODED_BYTE) | (c3 & this.MASK_6BITS));
                i += 3;
            }
        }

        return string;
    }

});
