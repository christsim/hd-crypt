
const MAX_OFFSET = 0x8000000;

function pathFromInt(v, acc = "") {
    if (v < MAX_OFFSET) {
        return acc + "/" + v.toString()
    }

    return pathFromInt(Math.trunc(v / MAX_OFFSET), acc + "/" + v % MAX_OFFSET);
}

function pathToInt(p, acc = 0) {
    const paths = p.substring(1).split(/\/(.+)/);

    return paths
        .filter(p => p != '')
        .map(x => parseInt(x))
        .reverse()
        .reduce((acc, v) => acc * MAX_OFFSET + v, 0);
}

module.exports = {
    pathFromInt,
    pathToInt,
}