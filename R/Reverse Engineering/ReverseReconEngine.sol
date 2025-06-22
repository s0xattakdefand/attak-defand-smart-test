// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IABIReconMutator {
    function guess(bytes4 selector, string calldata label) external;
}

interface IBytecodeRecon {
    function labelHash(bytes32 hash, string calldata label) external;
}

interface IEntropyABIEnhancer {
    function update(bytes4 selector, string calldata name, uint8 entropy, bool ok) external;
}

contract ReverseReconEngine {
    IABIReconMutator public abiRecon;
    IBytecodeRecon public byteRecon;
    IEntropyABIEnhancer public enhancer;

    struct SelectorProfile {
        bytes4 selector;
        string label;
        uint8 entropy;
        uint256 score;
    }

    bytes4[] public tracked;
    mapping(bytes4 => SelectorProfile) public profile;

    constructor(address _abi, address _byte, address _enh) {
        abiRecon = IABIReconMutator(_abi);
        byteRecon = IBytecodeRecon(_byte);
        enhancer = IEntropyABIEnhancer(_enh);
    }

    function logReplay(bytes4 sel, address target, bool success) external {
        uint8 ent = countBits(sel);
        string memory guess = string.concat("guess_", toHex(sel));

        abiRecon.guess(sel, guess);
        byteRecon.labelHash(keccak256(target.code), guess);
        enhancer.update(sel, guess, ent, success);

        SelectorProfile storage p = profile[sel];
        p.selector = sel;
        p.label = guess;
        p.entropy = ent;
        p.score += ent * (success ? 2 : 1);

        if (!isTracked(sel)) tracked.push(sel);
    }

    function getTopSelector() external view returns (bytes4 top) {
        uint256 max = 0;
        for (uint256 i = 0; i < tracked.length; i++) {
            if (profile[tracked[i]].score > max) {
                max = profile[tracked[i]].score;
                top = tracked[i];
            }
        }
    }

    function countBits(bytes4 sel) internal pure returns (uint8 b) {
        uint32 x = uint32(sel);
        while (x != 0) { b++; x &= (x - 1); }
    }

    function toHex(bytes4 data) internal pure returns (string memory) {
        bytes memory a = "0123456789abcdef";
        bytes memory s = new bytes(10);
        s[0] = '0'; s[1] = 'x';
        for (uint i = 0; i < 4; i++) {
            s[2 + i * 2] = a[uint8(data[i] >> 4)];
            s[3 + i * 2] = a[uint8(data[i] & 0x0f)];
        }
        return string(s);
    }

    function isTracked(bytes4 sel) internal view returns (bool) {
        for (uint256 i = 0; i < tracked.length; i++) {
            if (tracked[i] == sel) return true;
        }
        return false;
    }
}
