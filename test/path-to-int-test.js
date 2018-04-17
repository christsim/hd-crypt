var assert = require('assert');

var { pathToInt, pathFromInt } = require('../src/path-to-int.js');

describe('path to int', () => {
    it('test path from int', () => {
        var path = pathFromInt(0);
        assert.equal(path, "/0");

        var path = pathFromInt(0x8000000);
        assert.equal(path, "/0/1");

        var path = pathFromInt(0x8000001);
        assert.equal(path, "/1/1");

        var path = pathFromInt(0x8000000 - 1);
        assert.equal(path, "/134217727");

        var path = pathFromInt(0x8000000 * 2);
        assert.equal(path, "/0/2");

        var path = pathFromInt(0x8000000 * 2 + 100);
        assert.equal(path, "/100/2");
    });

    it('test path from int', () => {
        var v = pathToInt("/0");
        assert.equal(v, 0);

        var v = pathToInt("/1");
        assert.equal(v, 1);

        var v = pathToInt("/0/1");
        assert.equal(v, 0x8000000);

        var v = pathToInt("/100/2");
        assert.equal(v, 0x8000000 * 2 + 100);

        var v = pathToInt("/134217727");
        assert.equal(v, 0x8000000 - 1);

        var v = pathToInt("/0/2");
        assert.equal(v, 0x8000000 * 2);

        var v = pathToInt("/100/2");
        assert.equal(v, 0x8000000 * 2 + 100);
    });

    it('test path from int to path', () => {
        var p = pathFromInt(1524005762685);
        var v = pathToInt(p);
        var p2 = pathFromInt(v);
        assert.equal(v, 1524005762685);
        assert.equal(p, p2);

    });
    
    
});
