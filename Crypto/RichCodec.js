/**
 *
 * @copyright Copyright (c) 2011-2014 ZyraTech.com
 * @license   IP of Richie Bartlett, Jr. (Rich@RichieBartlett.com) [All Rights Reserved.]
 
 Inspired by: https://github.com/brainfucker/node-base64/blob/master/js_base64_for_comparsion.js
 */


Ext.define('Ext.Crypto.RichCodec', {
	alias: 'crypto.richCodec',
	alternateClassName: ['Ext.Crypto.richCodec'],
	requires: 'Ext.Crypto',
	singleton : true,

	encode: function(value) {
		return this.richCodec(value, true);
	},
	
	decode: function(value) {
		return this.richCodec(value, false);
	},
	
    richCodec : function(str, mode) { //v2.0
		/* richCodec is an encrypting _and_ decrypting string function
		   str: string to translate
		   mode: encrypting (mode=true) [default] ; decrypting (mode=false)
		   
		   Based on a simple translation table scheme.
		   NOTE: only supports ASCII text.
		*/
		var trans_Table = new Array(2), unknownChar = "ｶ", charStr="";
		trans_Table[0] = "OtW?5*A\\K]0`yF1^rD)Iu-Ce8~X,i:Lo3 Q@w;EpH\"Zq}N=xU%<gT/6hYj[Bf_d|k>2lM(s$Pa&V9m!vG4'n.#Sb+cJ7{zRｶ";//encrypted String
		trans_Table[1] = "0987654321<>?:\"{}|=-`+_)(*&^%$#@!~\\][/.,'; zyxwvutsrqpomnlkjihgfedcbaABCDEFGHIJKLNMOPQRSTUVWXYZｶ";//97 chars allowed
		
		if( str ){
		//Step 1: translate characters
			for( var strPtr=0; strPtr<str.length; strPtr++ ){
			
				charStr=str.substring( strPtr, strPtr+1 );
				
				for( var i=0; i<trans_Table[(mode? 1:0)].length; i++ ){
				
					if ( trans_Table[(mode? 1:0)].substring(i, i+1)==str.substring(strPtr, strPtr+1) ){
					
						str=str.substring(0, strPtr)+trans_Table[(mode? 0:1)].substring(i, i+1)+str.substring(strPtr+1, str.length);
						break;//nothing more to do...
					
					}//end if char found
				
				}//end for i
				
				if ( charStr==str.substring(strPtr, strPtr+1) ) { str=str.substring(0, strPtr)+unknownChar+str.substring(strPtr+1, str.length); }
				
				if ( strPtr>str.length ){ break; }//safety feature
			
			}//end for strPtr
			
		//Step 2: reverse character order
			str=Ext.Crypto.reverse(str);
		}//end if str exist
		return(str);
	} //end function cryptString

});