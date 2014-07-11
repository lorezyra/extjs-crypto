/**
 *
 * @copyright Copyright (c) 2011-2014 ZyraTech.com
 * @license   IP of Richie Bartlett, Jr. (Rich@RichieBartlett.com) [All Rights Reserved.]
 
 */


Ext.define('Ext.Crypto.Hex', {
	alias: 'crypto.hex',
	alternateClassName: ['Ext.Crypto.hex'],
	requires: [
		'Ext.Crypto'
	],
	singleton : true,



	charset: null,

    /**
     * Default charset name is {@link Charsets#UTF_8}
     */
	DEFAULT_CHARSET: Ext.Crypto.charSets.UTF_8,

    /**
     * Default charset name is {@link CharEncoding#UTF_8}
     */
	DEFAULT_CHARSET_NAME: Ext.Crypto.charSets.UTF_8,

    /**
     * Used to build output as Hex
     */
    DIGITS_LOWER: ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'],
	DIGITS_UPPER: ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'],




	/**
	 * setup the HEX encoder with user passed configs (if any)
	 */
	constructor: function (config) {
        config = config || {};
        Ext.apply(this, config);
		
		//setup *private* vars:
		this.charset = this.DEFAULT_CHARSET;
	},

    /**
     * Returns the numeric value of string ch found at index.
     *
     * @param ch
     *            a byte[] to convert to Hex integer
     * @return HEX digit
     */
	toDigit: function (ch, index) {
        var digit = parseInt(ch, 16);
        if (digit == -1) {
			//<debug>
			Ext.Error.raise("Illegal hexadecimal character " + ch + " at index " + index);
			//</debug>
        }
        return digit;
    },

    /**
     * Converts an array of bytes into an array of characters representing the hexadecimal values of each byte in order.
     * The returned array will be double the length of the passed array, as it takes two characters to represent any
     * given byte.
     *
     * @param data
     *            a byte[] to convert to Hex characters
     * @return A char[] containing hexadecimal characters
     */
	encode: function (data, toLowerCase) {
        var i = 0,
			j = 0,
			out = [],
			l = data.length,
			toDigits = toLowerCase ? this.DIGITS_LOWER : this.DIGITS_UPPER;
		
		data = Ext.Array.toArray(data);

        // two characters form the hex value.
        for (i = 0, j = 0; i < l; i++) {
            out[j++] = toDigits[(0xF0 & data[i]) >>> 4];
            out[j++] = toDigits[0x0F & data[i]];
        }
        return out;
	},


    /**
     * Converts an array of characters representing hexadecimal values into an array of bytes of those same values. The
     * returned array will be half the length of the passed array, as it takes two characters to represent any given
     * byte. An exception is thrown if the passed char array has an odd number of elements.
     *
     * @param data
     *            An array of characters containing hexadecimal digits
     * @return A byte array containing binary data decoded from the supplied char array.
     * @throws DecoderException
     *             Thrown if an odd number or illegal of characters is supplied
     */

	decode: function (data) {
        var f,
			i = 0,
			j = 0,
			out = [],
			len = data.length;

        if ((len & 0x01) != 0) {
			//<debug>
			Ext.Error.raise("Unable to decode HEX value: Odd number of characters.");
			//</debug>
        }

        // two characters form the hex value.
        for (i = 0, j = 0; j < len; i++) {
            f = this.toDigit(data[j], j) << 4;
            j++;
            f = f | this.toDigit(data[j], j);
            j++;s
            out[i] = (f & 0xFF);
        }

        return out;
	},
	
	getCharset: function () {
        return this.charset;
    },
	
    /**
     * Performs an inversion of the HEX num
     *
     * @param num
     *           HEX integer to convert to inverted Hex integer
     * @return HEX integer
     */
	invert: function(/*Integer (in Hex)*/ num) {
		//TODO: dynamically handle larger numbers.
		var x;

		x = ((num >> 24) & 0xff) |       // byte 3 to byte 0
			((num << 8)  & 0xff0000) |   // byte 1 to byte 2
			((num >> 8)  & 0xff00) |     // byte 2 to byte 1
			((num << 24) & 0xff000000);  // byte 0 to byte 3
			
		return x; // flipped value!
	},


/// This section inspired by: http://developer.classpath.org/doc/java/lang/Integer-source.html
	
    /**
     * Performs a binary left bit rotation of the HEX num
     *
     * @param intToShift
     *           HEX integer to rotate
     * @return HEX integer
     */
	rotateLeft: function(/*HEX Integer*/ intToShift, /*Integer*/ ShiftX) {
		return (intToShift << ShiftX) | (intToShift >>> ShiftX);
	},
	
    /**
     * Performs a binary right bit rotation  of the HEX num
     *
     * @param num
     *           HEX integer to rotate
     * @return HEX integer
     */
	rotateRight: function(/*HEX Integer*/ intToShift, /*Integer*/ ShiftX) {
		return (intToShift << - ShiftX) | (intToShift >>> ShiftX);
	}

	
});
