// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SteganalysisSuite.sol
/// @notice Four “Steganalysis”‑style detection patterns and hardened defenses  
///   1) LSB Statistical Test  
///   2) Payload‑Length Variance Test  
///   3) URI‑Marker Detection  
///   4) Bytecode‑Signature Scan  

error Stg__VarianceTooLow();
error Stg__BadLength();
error Stg__BadMarker();
error Stg__NotAllowed();

////////////////////////////////////////////////////////////////////////
// 1) LSB STATISTICAL TEST
//
//  • Vulnerable: stores secrets in LSB → detectable by counting 1‑bits
//  • Attack: compute ratio of LSB=1 over a range
//  • Defense: flip LSB via on‑chain randomness to hide bias
////////////////////////////////////////////////////////////////////////
contract StorageLSBVuln {
    mapping(uint256 => uint256) public data;
    function store(uint256 id, uint256 base, bool secretBit) external {
        data[id] = (base & ~uint256(1)) | (secretBit ? 1 : 0);
    }
}
contract Attack_StatLSB {
    StorageLSBVuln public target;
    constructor(StorageLSBVuln _t) { target = _t; }
    /// @return ones count of LSB=1 and total samples
    function detect(uint256 start, uint256 end) external view returns (uint256 ones, uint256 total) {
        for (uint256 i = start; i <= end; i++) {
            if ((target.data(i) & 1) == 1) ones++;
            total++;
        }
    }
}
contract StorageLSBSafe {
    mapping(uint256 => uint256) public data;
    /// flips LSB using last blockhash to remove bias
    function store(uint256 id, uint256 base) external {
        // no secretBit input; hides any embedded information
        uint256 rand = uint256(keccak256(abi.encodePacked(blockhash(block.number - 1), id)));
        data[id] = (base & ~uint256(1)) | (rand & 1);
    }
}

////////////////////////////////////////////////////////////////////////
// 2) PAYLOAD‑LENGTH VARIANCE TEST
//
//  • Vulnerable: variable‑length payloads reveal hidden data sizes
//  • Attack: compute variance of payload lengths to detect anomalies
//  • Defense: enforce fixed‑length or constant padding
////////////////////////////////////////////////////////////////////////
contract PayloadVuln {
    mapping(uint256 => bytes) public payloads;
    function store(uint256 id, bytes calldata p) external {
        payloads[id] = p;
    }
}
contract Attack_LengthVariance {
    PayloadVuln public target;
    constructor(PayloadVuln _t) { target = _t; }
    /// @notice returns mean and variance of lengths over [start,end]
    function stats(uint256 start, uint256 end) external view returns (uint256 mean, uint256 variance) {
        uint256 sum; uint256 sumSq; uint256 n;
        for (uint256 i = start; i <= end; i++) {
            uint256 L = target.payloads(i).length;
            sum   += L;
            sumSq += L * L;
            n++;
        }
        mean     = n > 0 ? sum / n : 0;
        variance = n > 1 ? (sumSq - sum * mean) / (n - 1) : 0;
    }
}
contract PayloadSafe {
    uint256 public constant FIXED_LEN = 128;
    mapping(uint256 => bytes) public payloads;
    error Stg__BadLength();
    function store(uint256 id, bytes calldata p) external {
        if (p.length > FIXED_LEN) revert Stg__BadLength();
        bytes memory tmp = new bytes(FIXED_LEN);
        for (uint256 i; i < p.length; i++) tmp[i] = p[i];
        payloads[id] = tmp;
    }
}

////////////////////////////////////////////////////////////////////////
// 3) URI‑MARKER DETECTION
//
//  • Vulnerable: hides secret after “?secret=” in URI
//  • Attack: detect presence of marker
//  • Defense: strip or reject URIs containing marker
////////////////////////////////////////////////////////////////////////
contract MetadataStegVuln {
    mapping(uint256 => string) public tokenURI;
    function setURI(uint256 id, string calldata uri) external {
        tokenURI[id] = uri;
    }
}
contract Attack_MetadataMarker {
    MetadataStegVuln public target;
    constructor(MetadataStegVuln _t) { target = _t; }
    /// @return true if “?secret=” appears
    function hasHidden(uint256 id) external view returns (bool) {
        bytes memory b = bytes(target.tokenURI(id));
        bytes memory m = bytes("?secret=");
        for (uint256 i; i + m.length <= b.length; i++) {
            bool ok = true;
            for (uint256 j; j < m.length; j++) {
                if (b[i + j] != m[j]) { ok = false; break; }
            }
            if (ok) return true;
        }
        return false;
    }
}
contract MetadataStegSafe {
    mapping(uint256 => string) public tokenURI;
    error Stg__BadMarker();
    function setURI(uint256 id, string calldata uri) external {
        bytes memory b    = bytes(uri);
        bytes memory marker = bytes("?secret=");
        for (uint256 i; i + marker.length <= b.length; i++) {
            bool ok = true;
            for (uint256 j; j < marker.length; j++) {
                if (b[i + j] != marker[j]) { ok = false; break; }
            }
            if (ok) revert Stg__BadMarker();
        }
        tokenURI[id] = uri;
    }
}

////////////////////////////////////////////////////////////////////////
// 4) BYTECODE‑SIGNATURE SCAN
//
//  • Vulnerable: embeds known constant signature → detectable via extcodecopy
//  • Attack: scan runtime code for magic bytes
//  • Defense: do not embed or encrypt constants
////////////////////////////////////////////////////////////////////////
contract BytecodeStegVuln {
    // embed magic signature “0xdeadbeef” in code
    bytes4 private constant SIG = 0xdeadbeef;
    function noop() external pure {}
}
contract Attack_BytecodeScan {
    /// extracts code and scans for SIG
    function scan(address target) external view returns (bool found) {
        uint256 size;
        assembly { size := extcodesize(target) }
        bytes memory code = new bytes(size);
        assembly { extcodecopy(target, add(code, 0x20), 0, size) }
        for (uint256 i; i + 4 <= size; i++) {
            bytes4 w;
            assembly { w := mload(add(add(code, 0x20), i)) }
            if (w == SIG) { found = true; return found; }
        }
    }
}
contract BytecodeStegSafe {
    function noop() external pure {}
    // no embedded signatures
}
