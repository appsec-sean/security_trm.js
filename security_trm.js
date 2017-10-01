/* Crypto primitives */

function sha1(str) {
    
    /*
    Non-standard functions
    */
    
    /* Binary to Hex conversion */
    function convertHex(binInt) {
        var t1="", i, h;
        for(i=7; i>=0; i--) {
            h = (binInt>>>(i*4))&0x0f;
            t1 += h.toString(16);
        }
        return t1;
    };
    
    
    /* Rotate Left (circular left shift) - FIPS 180-4 Sec 2.2.2 */
    function rotl(x,n) {
        return ((x<<n) | (x>>>(32-n))); /* where 32 is SHA-1's word size (w) */
    };


    function utf8Encode(string) {
        string = string.replace(/\r\n/g,"\n");
        var utfStr = "";
        for (var n = 0; n < string.length; n++) {
            var c = string.charCodeAt(n);
            if (c < 128) {
                utfStr += String.fromCharCode(c);
            }
            else if((c > 127) && (c < 2048)) {
                utfStr += String.fromCharCode((c >> 6) | 192);
                utfStr += String.fromCharCode((c & 63) | 128);
            }
            else {
                utfStr += String.fromCharCode((c >> 12) | 224);
                utfStr += String.fromCharCode(((c >> 6) & 63) | 128);
                utfStr += String.fromCharCode((c & 63) | 128);
            }
        }
        return utfStr;
    };

    var blockPointer, i, j, W = new Array(80), A, B, C, D, E, temp;
    
    
    /* Set initial hash values - FIPS 180-4 Sec 5.3.1 */
    var H0 = 0x67452301, H1 = 0xEFCDAB89, H2 = 0x98BADCFE, H3 = 0x10325476, H4 = 0xC3D2E1F0;
    
    
    /* Message padding and parsing - FIPS 180-4 Secs 5.1.1 and 5.2.1 */
    str = utf8Encode(str);
    var str_len = str.length;
    var word_array = new Array();
    for(i=0; i<str_len-3; i+=4) {
        j = str.charCodeAt(i)<<24 | str.charCodeAt(i+1)<<16 | str.charCodeAt(i+2)<<8 | str.charCodeAt(i+3);
        word_array.push(j);
    }
    
    switch(str_len % 4) {
        case 0:
            i = 0x080000000;
        break;
        case 1:
            i = str.charCodeAt(str_len-1)<<24 | 0x0800000;
        break;
        case 2:
            i = str.charCodeAt(str_len-2)<<24 | str.charCodeAt(str_len-1)<<16 | 0x08000;
        break;
        case 3:
            i = str.charCodeAt(str_len-3)<<24 | str.charCodeAt(str_len-2)<<16 | str.charCodeAt(str_len-1)<<8 | 0x80;
        break;
    }
    word_array.push(i);
    while((word_array.length % 16) != 14) word_array.push(0);
    word_array.push(str_len>>>29);
    word_array.push((str_len<<3)&0x0ffffffff);
    
    
    /* SHA-1 Computation - FIPS 180-4 Sec 6.1.2 */
    for (blockPointer=0; blockPointer<word_array.length; blockPointer+=16) {
        
        /* Step 1 - prepare message schedule */
        for(i=0; i<16; i++) W[i] = word_array[blockPointer+i];
        for(i=16; i<=79; i++) W[i] = rotl(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);
        /* End Step 1 */
        
        /* Step 2 - initialise working variables */
        A = H0;
        B = H1;
        C = H2;
        D = H3;
        E = H4;
        /* End Step 2 */
        
        /* Steps 3 and 4 - computing intermediate values */
        /* First 20 rounds */
        for(i= 0; i<=19; i++) {
            temp = (rotl(A,5) + ((B&C) | (~B&D)) + E + W[i] + 0x5A827999) & 0x0ffffffff;
            E = D;
            D = C;
            C = rotl(B,30);
            B = A;
            A = temp;
        }
        /* Second 20 rounds */
        for(i=20; i<=39; i++) {
            temp = (rotl(A,5) + (B ^ C ^ D) + E + W[i] + 0x6ED9EBA1) & 0x0ffffffff;
            E = D;
            D = C;
            C = rotl(B,30);
            B = A;
            A = temp;
        }
        /* Third 20 rounds */
        for(i=40; i<=59; i++) {
            temp = (rotl(A,5) + ((B&C) | (B&D) | (C&D)) + E + W[i] + 0x8F1BBCDC) & 0x0ffffffff;
            E = D;
            D = C;
            C = rotl(B,30);
            B = A;
            A = temp;
        }
        /* Final 20 rounds */
        for(i=60; i<=79; i++) {
            temp = (rotl(A,5) + (B ^ C ^ D) + E + W[i] + 0xCA62C1D6) & 0x0ffffffff;
            E = D;
            D = C;
            C = rotl(B,30);
            B = A;
            A = temp;
        }
        H0 = (H0 + A) & 0x0ffffffff;
        H1 = (H1 + B) & 0x0ffffffff;
        H2 = (H2 + C) & 0x0ffffffff;
        H3 = (H3 + D) & 0x0ffffffff;
        H4 = (H4 + E) & 0x0ffffffff;
    }
    /* End Steps 3 and 4 */
    
    /* Create resulting message digest */
    var temp = convertHex(H0) + convertHex(H1) + convertHex(H2) + convertHex(H3) + convertHex(H4);
    return temp.toLowerCase();
}


/*
Token generation
1. Randomly generate a word
2. Check if that word's sha1 hash matches criteria
3. If match, the client's token is that word
4. If no match, restart at step 1

Default criteria: First hex digit equals 0
Requires 16 (2^4) sha1 computations on average

Recommended criteria: First 4 hex digits equal 0
Takes ~1 second on an average laptop / smartphone

Modify criteria by changing the value of hexCriteria below
Do NOT set hexCriteria < 1
Do NOT set hexCriteria > 39
You shouldn't set hexCriteria > 10, otherwise each form submission will take days
hexCriteria = 2 would insist first two hex digits equal 0 (256 computations on average (16^2))
hexCriteria = y would insist first y hex digits equal 0 (16^y computations on average)
*/

var hexCriteria = 1;
var charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", j = 20, hexMatch = "", tokenHash = "1111111111111111111111111111111111111111"; /* j=10 gives a 10 character random word */
for (i=0; i<hexCriteria; i++) {
    hexMatch += "0";
}

function generateWord() {
    word = "";
    for (var i=0; i<j; i++) {
        word += charset.charAt(Math.floor(Math.random() * charset.length));
    }
    return word;
}

function generateToken() {
    while (tokenHash.substring(0, hexCriteria) != hexMatch) {
        possibleToken = generateWord();
        tokenHash = sha1(possibleToken);
    }
    return possibleToken;
}

var clientToken = generateToken();

/*
DOM interaction
*/
document.getElementById('submitWithSha1').onclick = function() {
    document.getElementById('sha1Str').value = clientToken;
    return false;
}
