
/**
 * @namespace
 * Bloom filter module.
 */
UTIL.Bloom = {
    table_mag : function(n, p) {
        return Math.floor(Math.log(n * UTIL.Bloom.amount_hashes(p) / Math.LN2) / Math.LN2) + 1;
    },

    amount_hashes : function(p) {
        return Math.ceil(- Math.log(p) / Math.LN2);
    },
    
    hash_length : function(n, p) {
        return UTIL.Bloom.table_mag(n, p) * UTIL.Bloom.amount_hashes(p);
    },
    
    hash_loop : function(subject, key, callback) {
        subject.hash.init();
        subject.hash.update(key);
        subject.hash.digest();
        var _n = 0;
        for (var _j = 0; _j < subject.amount_hashes; _j++) {
            if (!callback(UTIL.Bits.get_int(_n, _n, subject.table_mag))) break;
            _n += subject.table_mag;
        }
    }
};

UTIL.Bloom.Filter = Base.extend(/** @lends UTIL.Bloom.Filter */{
    /** @constructs UTIL.Bloom.Filter */
    constructor : function(n, p, hash, table) {
        this.hash = hash;
        this.n = n;
        this.removed = 0;
        this.p = p;
        /*
         * Let n be number of elements in the table, and p the required
         * probability of false posisitves. Then, the amount of bits in the 
         * vector have to be chosen like
         * 	m = - (n ln p)/((ln 2)^2)
         * The number of different hash functions giving hashes in [0, m-1]
         * is optimal at k = ln2 (m/n).
         * let R the amount of removed entries. Then the probability for
         * false positives due to removed entries is R/n
	     */
        if (table) {
            if (table.length & (table.length - 1)) {
                UTIL.error("Non power of two table length.");
            }
            this.table = table;
            this.table_mag = Math.round(Math.log(table.length)/Math.LN2);
        } else {
            this.table_mag = UTIL.Bloom.table_mag(n, p); 
            this.table = new UTIL.BitVector(1 << this.table_mag);
        }
        this.amount_hashes = UTIL.Bloom.amount_hashes(p);

        if (this.amount_hashes * this.table_mag > hash.block_bytes * 8) {
            UTIL.log("Requirements cannot be fulfilled. Would need %d bits of" +
                    "hash key (\"Too big to fail\"-condition). has: %d",
                    this.amount_hashes * this.table_mag,
                    hash.block_bytes * 8);

            this.amount_hashes = Math.floor(hash.block_bytes * 8 / this.table_mag);
            if (this.amount_hashes == 0) {
                UTIL.error("Hash has less bits that table size. What year is this?\n");
            }
        }
    },

    prob : function() {
        // this is not strictly correct. but maybe a sufficient thing for
        // now. we need to look into this.
        if (this.removed >= this.n) return 1;
        if (this.n == 0) return 0;
        return Math.min(1, this.removed / this.n 
                + Math.pow((1 - Math.exp(- this.amount_hashes 
                * this.n / (1 << this.table_mag))), this.amount_hashes));
    },

    set : function() {
        for (var i = 0; i < arguments.length; i++) {
            UTIL.Bloom.hash_loop(this, arguments[i], function(_t) {
                if (this.table.get(_t) == 0) this.table.set(_t);
                return true;
            });
        }
        this.n++;
    },

    get : function() {
        var ret = true;
        for (var i = 0; i < arguments.length; i++) {
            UTIL.Bloom.hash_loop(this, arguments[i], function(t) {
                return (ret = (this.table.get(t) !== 0));
            });
            if (!ret) return false;
        }
        return true;
    },

    // this is purely for bookkeeping purposes. you can "remove"
    // entries twice, so this might be biased. but you cannot remove
    // ones that the tree knows it doesnt have. so the ones that would
    // normally be removed are the real ones and some p in 1 false
    // positives.
    remove : function(key) {
        if (this.get(key)) {
            this.removed++;
            return true;
        }
        return false;
    }
});

if (window.serialization) {
    serialization.BitVector = serialization.Struct.extend({
        constructor : function() {
            this.base("_bitvector", {
                length : new serialization.Integer(),
                field : new serialization.Binary()
            });
        },
        encode : function(bv) {
            var c = bv.length >>> 3 + (!!(bv.length & 7) ? 1 : 0);
            var s = new Array(c);
            for (var i = 0; i < c; i++) {
                s[i] = bv.get_int(i * 8, 8);
            }
            return this.base({
                field : String.fromCharCode.apply(window, s),
                length : bv.length
            });
        },
        can_encode : function(bv) {
            return bv instanceof UTIL.BitVector;
        },
        decode : function(atom) {
            var o = this.base(atom);
            var c = o.length >>> 5 + (!!(o.length & 31) ? 1 : 0);
            var a = new Array(c);
            var i;
            for (i = 0; i < c; i++) {
                a[i] = o.field.charCodeAt(i*4) |
                       o.field.charCodeAt(i*4+1) << 8 |
                       o.field.charCodeAt(i*4+2) << 16 |
                       o.field.charCodeAt(i*4+3) << 24;
            }
            return new UTIL.BitVector(a, o.length);
        }
    });

    serialization.Bloom = serialization.Struct.extend({
        constructor : function(hash) {
            this.hash = hash;
            this.base("_bloom", {
                n : new serialization.Integer(),
                p : new serialization.Float(),
                removed : new serialization.Integer(),
                table : new serialization.BitVector()
            });
        },
        can_encode : function(b) {
            return b instanceof UTIL.Bloom.Filter;
        },
        decode : function(atom) {
            var o = this.base(atom);
            var b = new UTIL.Bloom.Filter(o.n, o.p, this.hash, o.table);
            b.n = o.n;
            b.removed = o.removed;
            return b;
        }
    });
}

// TODO: this should probably use the same defines
UTIL.BitVector = Base.extend({
    /** @lends UTIL.BitVector */
    /** @constructs UTIL.BitVector */
    constructor : function(a, b) {
        if (UTIL.arrayp(a)) {
            this.field = a;
            this.length = arguments.length > 1 ? b : a.length*32;
        } else {
            this.length = a;
            this.field = UTIL.Bits.bit_vector(a);
            var i;
            if (b) for (i = 0; i < this.field.length; i++) {
                this.field[i] = b;
            }
        }
    },

    get : function(idx) {
        return UTIL.Bits.is_set(this.field, idx) ? 1 : 0;
    },

    set : function(idx, val) {
        UTIL.Bits.set_val(this.field, idx, (arguments.length === 1) ? 1 : val);
    },

    clear : function() {
        var i;
        for (i = 0; i < this.field.length; i++) {
            this.field[i] = 0;
        }
    },

    get_int : function(n, len) {
        return UTIL.Bits.get_int(this.field, n, len);
    },

    enlarge : function(len, val) {
        var of = this.field;
        this.field = new Array(of.length + len >>> 5 + (len % 32 ? 1 : 0));
        var i;
        for (i = 0; i < of.length; i++) {
            this.field[i] = of[i];
        }
        if (val) for (i = of.length; i < this.field.length; i++) {
            this.field[i] = val;
        }
    },

    toString : function(base) {
        if (base == 2) {
            var ret = "";
            var i;
            for (i = 0; i < this.field.length - 1; i++)
                ret += UTIL.sprintf("%032b", this.field[i]);
                ret += UTIL.sprintf("%0"+ ((this.length % 32) || 32) + "b",
                        this.field[i]);
            return ret;
        } else {
            return UTIL.sprintf("UTIL.BitVector(%d)", this.length);
        }
    }
});
