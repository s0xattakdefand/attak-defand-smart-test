// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SteganographySuite.sol
/// @notice Four on‑chain “Steganography” patterns: hiding data in innocuous carriers,
///         plus attacks to extract hidden data and hardened defenses to prevent it.

error Steg__BadLSB();
error Steg__TooLarge();
error Steg__BadMarker();
error Steg__NotAllowed();

////////////////////////////////////////////////////////////////////////////////
// 1) STORAGE LSB EMBEDDING
//
//   • Vulnerable: hides one bit of secret in the LSB of a stored value
//   • Attack: read storage and mask LSB to recover hidden bit
//   • Defense: clear LSB before storing or reject altered LSB
////////////////////////////////////////////////////////////////////////////////
contract StorageLSBVuln {
    mapping(uint256 => uint256) public data;

    /// stores value but hides secret bit in LSB
    function store(uint256 id, uint256 value, bool secretBit) external {
        data[id] = (value & ~uint256(1)) | (secretBit ? 1 : 0);
    }
}

/// Attack: extract the hidden bit by masking LSB
contract Attack_StorageLSB {
    StorageLSBVuln public target;
    constructor(StorageLSBVuln _t) { target = _t; }

    function revealBit(uint256 id) external view returns (bool) {
        return (target.data(id) & 1) == 1;
    }
}

contract StorageLSBSafe {
    mapping(uint256 => uint256) public data;

    /// rejects any attempt to set LSB ≠ 0
    function store(uint256 id, uint256 value) external {
        if ((value & 1) != 0) revert Steg__BadLSB();
        data[id] = value;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) EVENT PAYLOAD HIDDEN MARKER
//
//   • Vulnerable: hides secret payload after a marker in event data
//   • Attack: listen to logs and parse payload after the marker
//   • Defense: only emit sanitized data or hashed payload
////////////////////////////////////////////////////////////////////////////////
contract EventStegVuln {
    event Msg(string visible, bytes hidden);

    /// attacker emits visible text plus hidden bytes
    function send(string calldata text, bytes calldata secret) external {
        emit Msg(text, secret);
    }
}

/// Attack: decode the hidden bytes from the event
contract Attack_EventSteg {
    // parsing must be done off‑chain by filtering Msg events and reading `hidden`
    // here shown as a stub
    function parseEvent(bytes calldata logData) external pure returns (bytes memory) {
        return logData; // off‑chain parse of event.hidden
    }
}

contract EventStegSafe {
    event Msg(string visible);

    /// only emit visible text; drop hidden bytes
    function send(string calldata text) external {
        emit Msg(text);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) METADATA URI EMBEDDING
//
//   • Vulnerable: hides secret JSON parameter in tokenURI query string
//   • Attack: fetch URI and parse query after `?secret=`
//   • Defense: strip query or reject URIs containing `?secret=` marker
////////////////////////////////////////////////////////////////////////////////
contract MetadataStegVuln {
    mapping(uint256 => string) public tokenURI;

    function setURI(uint256 id, string calldata uri) external {
        tokenURI[id] = uri;
    }
}

/// Attack: split URI at `?secret=` to recover hidden data
contract Attack_MetadataSteg {
    MetadataStegVuln public target;
    constructor(MetadataStegVuln _t) { target = _t; }

    function revealSecret(uint256 id) external view returns (string memory) {
        string memory uri = target.tokenURI(id);
        bytes memory b = bytes(uri);
        // off‑chain split at "?secret="; stub here returns full URI
        return uri;
    }
}

contract MetadataStegSafe {
    mapping(uint256 => string) public tokenURI;
    error Steg__BadMarker();

    /// reject URIs containing hidden‑marker
    function setURI(uint256 id, string calldata uri) external {
        bytes memory b = bytes(uri);
        // simple check for substring "?secret="
        bytes memory marker = bytes("?secret=");
        for (uint i = 0; i + marker.length <= b.length; i++) {
            bool found = true;
            for (uint j = 0; j < marker.length; j++) {
                if (b[i + j] != marker[j]) { found = false; break; }
            }
            if (found) revert Steg__BadMarker();
        }
        tokenURI[id] = uri;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) BYTECODE PAYLOAD EMBEDDING
//
//   • Vulnerable: embeds a secret constant in the contract’s bytecode
//   • Attack: read raw runtime bytecode via extcodecopy to extract secret
//   • Defense: do not embed secrets in code or restrict code access
////////////////////////////////////////////////////////////////////////////////
contract BytecodeStegVuln {
    // embed secret bytes in a constant
    bytes6 private constant SECRET = hex"736563726574"; // "secret" in ASCII

    function noop() external pure {}
}

contract Attack_BytecodeSteg {
    /// extracts the entire runtime code; off‑chain parse to locate SECRET
    function extractCode(address target) external view returns (bytes memory) {
        uint size;
        assembly { size := extcodesize(target) }
        bytes memory code = new bytes(size);
        assembly { extcodecopy(target, add(code, 0x20), 0, size) }
        return code;
    }
}

contract BytecodeStegSafe {
    function noop() external pure {}
    // no secret constants in code
}
