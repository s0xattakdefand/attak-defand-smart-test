// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IABIReconMutator {
    function guess(bytes4 selector, string calldata label) external;
}

interface IBytecodeRecon {
    function labelHash(bytes32 codeHash, string calldata label) external;
}

contract SimStrategyAI_ReverseLoop {
    IABIReconMutator public abiRecon;
    IBytecodeRecon public codeRecon;

    constructor(address _abiRecon, address _byteRecon) {
        abiRecon = IABIReconMutator(_abiRecon);
        codeRecon = IBytecodeRecon(_byteRecon);
    }

    function analyzeReplay(bytes4 sel, address target) external {
        string memory guess = string.concat("fuzz_", toHex(sel));
        abiRecon.guess(sel, guess);
        codeRecon.labelHash(keccak256(target.code), guess);
    }

    function toHex(bytes4 data) internal pure returns (string memory) {
        bytes memory alpha = "0123456789abcdef";
        bytes memory s = new bytes(10);
        s[0] = '0'; s[1] = 'x';
        for (uint i = 0; i < 4; i++) {
            s[2 + i * 2] = alpha[uint8(data[i] >> 4)];
            s[3 + i * 2] = alpha[uint8(data[i] & 0x0f)];
        }
        return string(s);
    }
}
