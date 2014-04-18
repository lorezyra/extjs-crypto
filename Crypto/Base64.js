/**
 *
 * @link      http://www.Linspira.com/js/ for the canonical source
 * @copyright Copyright (c) 2011-2014 Linspira.com
 * @license   IP of Richie Bartlett, Jr. (Rich@RichieBartlett.com) [All Rights Reserved.]
 
 Inspired by: https://github.com/brainfucker/node-base64/blob/master/js_base64_for_comparsion.js
 */


Ext.define('Ext.Crypto.Base64', {
	alias: 'crypto.base64',
	alternateClassName: ['Ext.Crypto.base64'],
	requires: 'Ext.Crypto',
	singleton : true,
	
	keyMap: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",

	encode: function(value) {
		input = escape(value);
		var chr1,
			chr2,
			chr3 = "",
			enc1,
			enc2,
			enc3,
			enc4 = "",
			output = "",
			i = 0;
		
		do {
			chr1 = input.charCodeAt(i++);
			chr2 = input.charCodeAt(i++);
			chr3 = input.charCodeAt(i++);
			
			enc1 = chr1 >> 2;
			enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
			enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
			enc4 = chr3 & 63;
			
			if (isNaN(chr2)) {
				enc3 = enc4 = 64;
			} else if (isNaN(chr3)) {
				enc4 = 64;
			}
			
			output += this.keyMap.charAt(enc1) +
				this.keyMap.charAt(enc2) +
				this.keyMap.charAt(enc3) +
				this.keyMap.charAt(enc4);
			chr1 = chr2 = chr3 = "";
			enc1 = enc2 = enc3 = enc4 = "";
		} while (i < input.length);
		
		return output;
	},
	
	decode: function(value) {
		var chr1,
			chr2,
			chr3 = "",
			enc1,
			enc2,
			enc3,
			enc4 = "",
			output = "",
			i = 0;
		
		var base64test = /[^A-Za-z0-9\+\/\=]/g;
		if ( base64test.exec(value) ) {
			//<debug>
			Ext.Error.raise("There were invalid base64 characters in the input text.\n" +
			"Valid base64 characters are A-Z, a-z, 0-9, '+', '/',and '='\n" +
			"Expect errors in decoding.");
			//</debug>
		}
		// remove all characters that are not A-Z, a-z, 0-9, +, /, or =
		input = value.replace(/[^A-Za-z0-9\+\/\=]/g, "");
		
		do {
			enc1 = this.keyMap.indexOf(input.charAt(i++));
			enc2 = this.keyMap.indexOf(input.charAt(i++));
			enc3 = this.keyMap.indexOf(input.charAt(i++));
			enc4 = this.keyMap.indexOf(input.charAt(i++));
			
			chr1 = (enc1 << 2) | (enc2 >> 4);
			chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
			chr3 = ((enc3 & 3) << 6) | enc4;
			
			output += String.fromCharCode(chr1);
			
			if (enc3 != 64) {
				output += String.fromCharCode(chr2);
			}
			if (enc4 != 64) {
				output += String.fromCharCode(chr3);
			}
			
			chr1 = chr2 = chr3 = "";
			enc1 = enc2 = enc3 = enc4 = "";
		
		} while (i < input.length);
		
		return unescape(output);
	}

});