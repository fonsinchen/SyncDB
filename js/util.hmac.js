/** A hmac implementation. */
var HMAC = Base.extend({
    constructor : function(hashp) {
        this.hashp = hashp;
    },

    get : function(key) {
        return new this.hmac(new this.hashp(), key);
    },

    hmac : Base.extend({
        constructor : function(hash, key) {
            var blen;
            this.hash = hash;
            blen = hash.block_bytes;
            hash.init();
            if (key.length > blen) {
                hash.update(key);
                key = hash.string_digest(key);
                hash.init();
            }
            var a;

            if (key.length < blen) {
                a = new Array(blen - key.length);
                key += String.fromCharCode.apply(window, a);
            }
            this.o_key_pad = this.xor(key, 0x5c);
            this.i_key_pad = this.xor(key, 0x36);
        },

        //TODO: move this somewhere else
        xor : function(s, i) {
            var a = new Array(s.length);
            for (var j = 0; j < a.length; j++) a[j] = s.charCodeAt(j)^i;
            return String.fromCharCode.apply(window, a);
        },

        hmac : function(s) {
            var inner;
            this.hash.update(this.i_key_pad + s)
            inner = this.hash.string_digest();
            this.hash.init();
            this.hash.update(this.o_key_pad + inner);
            inner = this.hash.hex_digest();
            this.hash.init();
            return inner;
        }
    })
});
