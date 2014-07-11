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

	charSets: {
     	/* CharEncodingISO Latin Alphabet No. 1, a.k.a. ISO-LATIN-1. */
		ISO_8859_1 : "ISO-8859-1",

     	/* Seven-bit ASCII, also known as ISO646-US, also known as the Basic Latin block of the Unicode character set. */
		US_ASCII : "US-ASCII",

     	/*      * Sixteen-bit Unicode Transformation Format, The byte order specified by a mandatory initial byte-order mark
     			* (either order accepted on input, big-endian used on output) */
		UTF_16 : "UTF-16",

     	/* Sixteen-bit Unicode Transformation Format, big-endian byte order. */
		UTF_16BE : "UTF-16BE",

     	/* Sixteen-bit Unicode Transformation Format, little-endian byte order. */
		UTF_16LE : "UTF-16LE",

     	/* Eight-bit Unicode Transformation Format. */
		UTF_8 : "UTF-8"
	},
	
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

	
    /**
     * Checks if a byte value is whitespace or not.
     * Whitespace is taken to mean: space, tab, CR, LF
     * @param byteToCheck
     *            the byte to check
     * @return true if byte is whitespace, otherwise false
     */
	isWhiteSpace: function (byteToCheck) {
        switch (byteToCheck) {
            case ' ' :
            case '\n' :
            case '\r' :
            case '\t' :
                return true;
            default :
                return false;
        }
    },

   //NOTE: only supports US_ASCII; not UTF_8 safe
	reverse: function (/*String*/ strg){//v2.0
		// reverses the order of the letters in passed string strg
		// Example: "hello" becomes "olleh"...
	   /* expensive method:
	   var temp="";
	   for(var x=0; x<strg.length; x++){
		   temp=strg.substring(x, x+1) + temp;
		}
	   return(temp);
	   */
	   //convert string to array and return
	   return strg.split('').reverse().join('');
	}//end function reverseString

});