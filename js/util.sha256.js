/*
* A JavaScript implementation of the SHA256 hash function.
*
* FILE:	sha256.js
* VERSION:	0.8
* AUTHOR:	Christoph Bichlmeier <informatik@zombiearena.de>
*           Arne Goedeke <el+sha256@laramies.com>
*           Ulf Hermann <ulf_hermann@gmx.net>
*
* NOTE: This version is not tested thoroughly!
*
* Copyright (c) 2003, Christoph Bichlmeier
* Copyright (c) 2011, Arne Goedeke
* Copyright (c) 2012, Arne Goedeke
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
* 3. Neither the name of the copyright holder nor the names of contributors
*    may be used to endorse or promote products derived from this software
*    without specific prior written permission.
*
* ======================================================================
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
* OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
* BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
* WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
* OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
* EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/** @namespace */
UTIL.SHA256 = (function() {


    /** SHA256 logical functions. */

    function rotr(n, x)	{
        return (x >>> n) | (x << (32 - n));
    }

    /* Add 32-bit integers with 16-bit operations - might be needed sometimes.
     * (bug in some JS-interpreters: overflow)
     *
     * safe_add : function(x, y) {
     *      var lsw = (x & 0xffff) + (y & 0xffff);
     *  	var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
     *      return (msw << 16) | (lsw & 0xffff);
     *  }
     */
    
    var add = function(x, y) {
        return (x + y) & 0xffffffff;
    };

    var sigma0 = function(x) {
        return rotr(7, x) ^ rotr(18, x) ^ (x >>> 3);
    };

    var sigma1 = function(x) {
        return rotr(17, x) ^ rotr(19, x) ^ (x >>> 10);
    };

    var choice = function(x,y,z) {
        return (x & y) ^ (~x & z);
    };

    var majority = function(x,y,z) {
        return (x & y) ^ (x & z) ^ (y & z);
    };

    var expand = function(t1, w, j) {
        return t1 + (w[j & 0x0f] += sigma1(w[(j + 14) & 0x0f]) +
                w[(j + 9) & 0x0f] + sigma0(w[(j + 1) & 0x0f]));
    };

    var transform_sigma0 = function(x) {
        return rotr(2, x) ^ rotr(13, x) ^ rotr(22, x);
    };

    var transform_sigma1 = function(x) {
        return rotr(6, x) ^ rotr(11, x) ^ rotr(25, x);
    };


    /** Hash constant words K. */
    var k256 = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];


    /** The actual algorithm. */
    return {

        /** Test if the JS-interpreter is working properly. */
        self_test : function() {
            return (new UTIL.SHA256.Hash()).update("message digest").hex_digest() ===
                    "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650";
        },

        /** Transform a 512-bit message block. */
        transform : function(hash, w) {
            var a, b, c, d, e, f, g, h, j, t1, t2;

            /* Initialize registers with the previous intermediate value */
            a = hash[0];
            b = hash[1];
            c = hash[2];
            d = hash[3];
            e = hash[4];
            f = hash[5];
            g = hash[6];
            h = hash[7];

            for(j = 0; j < 64; j++) {
                t1 = h + transform_sigma1(e) + choice(e, f, g) + k256[j];
                if (j < 16) {
                    t1 += w[j];
                } else {
                    t1 = expand(t1, w, j);
                }
                t2 = transform_sigma0(a) + majority(a, b, c);
                h = g;
                g = f;
                f = e;
                e = add(d, t1);
                d = c;
                c = b;
                b = a;
                a = add(t1, t2);
            }

            // can this overflow and also possibly overflow to something above
            // 2^53 which would lead to completely fucked up results?

            /* Compute the current intermediate hash value */
            hash[0] += a;
            hash[1] += b;
            hash[2] += c;
            hash[3] += d;
            hash[4] += e;
            hash[5] += f;
            hash[6] += g;
            hash[7] += h;

            return hash;
        },

        /** Read the next chunk of data and update the SHA256 computation. */
        low_update : function(hash, data, len) {
            var curpos = 0;
            var w;
            var i;
            var j;

            if (UTIL.arrayp(data)) {
                if (data.length === 64) {
                    w = new Array(16);
                    for(j = 0; j < 16; j++) {
                        w[j] = (data[curpos] << 24) |
                               (data[curpos+1] << 16) |
                               (data[curpos+2] << 8) |
                               (data[curpos+3]);
                        curpos += 4;
                    }
                    return this.transform(hash, w);
                } else if (data.length === 16) {
                    return this.transform(hash, data);
                }
                /* Transform as many times as possible */
            } else {
                w = new Array(16);
                for(i = 0; i + 63 < len; i += 64) {
                    for (j = 0; j < 16; j++) {
                        w[j] = (data.charCodeAt(curpos) << 24) |
                               (data.charCodeAt(curpos+1) << 16) |
                               (data.charCodeAt(curpos+2) << 8) |
                               (data.charCodeAt(curpos+3));
                        curpos += 4;
                    }
                    this.transform(hash, w);
                }
                return hash;
            }

            UTIL.error("Bad argument to low_update.");
            return false;
        },

        /** Finish the computation by operations such as padding. */
        consume_string : function(data, W, len, offset) {
            var i;
            if (arguments.length < 4) offset = 0;
            if (!len) {
                len = 64;
            } else {
                len = Math.min(64, len);
            }
            for (i = 0; i < len >>> 2; i++) {
                W[i] = (data.charCodeAt(offset) << 24) |
                       (data.charCodeAt(offset+1) << 16) |
                       (data.charCodeAt(offset+2) << 8) |
                       (data.charCodeAt(offset+3));
                offset += 4;
            }
            i = 0;
            switch (len & 3) {
                case 3:
                    i |= (data.charCodeAt(offset+2) << 8);
                case 2:
                    i |= (data.charCodeAt(offset+1) << 16)
                case 1:
                    i |= (data.charCodeAt(offset) << 24)
                    W[len>>2] = i;
            }
        },

        low_final : function(hash, data, len) {
            len *= 8;
            var w = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];

            this.consume_string(data, w, data.length);
            w[data.length >>> 2] |= 0x80 << (8 * (3 - (data.length & 3)));

            if (data.length <= 56) {
                w[15] = len;
                return this.transform(hash, w);
            } else {
                this.transform(hash, w);
            }

            w = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,len];
            return this.transform(hash, w);
        }
    }
})();


/** SyncDB integration. */
UTIL.SHA256.Hash = UTIL.Hash.extend({
    /** @lends UTIL.SHA256.Hash */

    /**
     * @constructs UTIL.SHA256.Hash 
     * @augments UTIL.Hash
     */
    constructor : function() {
        this.init();
    },

    block_bytes : 64,

    /* Initialise the SHA256 computation */
    init : function() {
        this.ihash = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ];
        this.final_val = null;
        this.length = 0;
        this.buf = "";
    },

    update : function(data) {
        this.final_val = null;

        if (UTIL.stringp(data)) {
            this.length += data.length;
            this.buf += data;
            if (this.buf.length >= 64) {
                UTIL.SHA256.low_update(this.ihash, this.buf, this.buf.length & 0xffffffc0);
                this.buf = this.buf.substr(this.buf.length & 0xffffffc0);
            }
        } else if (this.buf.length) {
            UTIL.error("Using Hash in string mode already.\n");
        } else {
            this.length += 64;
            UTIL.SHA256.low_update(this.ihash, data);
        }

        return this;
    },

    digest : function() {
        if (!this.final_val) {
            this.final_val = UTIL.SHA256.low_final(this.ihash, this.buf, this.length);
        }
        return this.final_val.concat();
    }
});
