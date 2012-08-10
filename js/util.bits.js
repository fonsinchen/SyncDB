UTIL.Bits = {
    bit_vector : function(n) {return new Array(Math.ceil(n >>> 5));},
    is_set : function(v, n) {return !!(v[n >>> 5] & (1 << (n & 31)));},
    set : function(v, n) {v[n >>> 5] |= 1 << (n & 31);},
    unset : function(v, n) {v[n >>> 5] &= ~(1 << (n & 31));},
    set_val : function(v, n, bit) {
        if (bit) {
            this.bvSet(v, n);
        } else {
            this.bvUnset(v, n);
        }
    },
    get_int : function (v, n, len) {
        t = v[n >>> 5];
        t >>>= n & 31;
        if (len > 32 - (n & 31)) {
            t |= v[(n >>> 5) + 1] << (32 - (n & 31));
        }
        return t & (1 << len) - 1;
    },
    round_up32 : function(t) {
        t |= t >> 1;
        t |= t >> 2;
        t |= t >> 4;
        t |= t >> 8;
        t |= t >> 16;
    }
}