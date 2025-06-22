contract RIPHopFuzzer {
    IRIPRouter public router;

    constructor(address _r) {
        router = IRIPRouter(_r);
    }

    function fuzz(bytes4[] calldata selectors, uint8 depth) external {
        for (uint i = 0; i < selectors.length; i++) {
            router.forward(abi.encodePacked(selectors[i], uint8(depth)));
        }
    }
}
