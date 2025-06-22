// PoseidonMerkleProof.circom
pragma circom 2.0.0;

include "circomlib/poseidon.circom";

template MerkleProof(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal output root;

    var hash = leaf;

    for (var i = 0; i < depth; i++) {
        var sibling = pathElements[i];
        hash <== Poseidon(pathIndices[i] == 0 ? [hash, sibling] : [sibling, hash]);
    }

    root <== hash;
}
