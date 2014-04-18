/**
 *
 * @link      http://www.Linspira.com/js/ for the canonical source
 * @copyright Copyright (c) 2011-2014 Linspira.com
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
	   //NOTE: only supports ASCII; not UTF8 safe
	   return strg.split('').reverse().join('');
	}//end function reverseString

});