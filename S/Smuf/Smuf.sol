// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// Shared errors
error Smurf__NotOwner();
error Smurf__AmplifierLimitExceeded();
error Smurf__Reentrant();

/// Simple Reentrancy Guard
abstract contract NonReentrant {
    uint256 private _status;
    modifier nonReentrant() {
        if (_status == 1) revert Smurf__Reentrant();
        _status = 1;
        _;
        _status = 0;
    }
}

////////////////////////////////////////////////////////////////////////
// 1) UNAUTHENTICATED AMPLIFIER REGISTRY
////////////////////////////////////////////////////////////////////////

/// ❌ Vulnerable: anyone can register amplifiers and trigger broad reflection
contract SmurfRegistryVuln {
    address[] public amplifiers;
    event AmplifierAdded(address indexed amp);

    function addAmplifier(address amp) external {
        amplifiers.push(amp);
        emit AmplifierAdded(amp);
    }

    /// Broadcasts received ETH equally to all registered amplifiers
    function reflect() external payable {
        uint256 len = amplifiers.length;
        require(len > 0, "no amplifiers");
        uint256 share = msg.value / len;
        for (uint256 i; i < len; ++i) {
            (bool ok, ) = amplifiers[i].call{value: share}("");
            require(ok, "send failed");
        }
    }
}

/// Demo exploit: register a malicious amplifier contract
contract Attack_SmurfRegistry {
    SmurfRegistryVuln public target;
    constructor(SmurfRegistryVuln _t) { target = _t; }
    function exploit(address fakeAmp) external {
        target.addAmplifier(fakeAmp);
    }
}

/// ✅ Safe: only owner may add amplifiers
contract SmurfRegistrySafe {
    address[] public amplifiers;
    address public immutable owner;
    event AmplifierAdded(address indexed amp);

    constructor() { owner = msg.sender; }

    function addAmplifier(address amp) external {
        if (msg.sender != owner) revert Smurf__NotOwner();
        amplifiers.push(amp);
        emit AmplifierAdded(amp);
    }

    function reflect() external payable {
        uint256 len = amplifiers.length;
        require(len > 0, "no amplifiers");
        uint256 share = msg.value / len;
        for (uint256 i; i < len; ++i) {
            (bool ok, ) = amplifiers[i].call{value: share}("");
            require(ok, "send failed");
        }
    }
}

////////////////////////////////////////////////////////////////////////
// 2) UNBOUNDED AMPLIFICATION (BULK DOS)
////////////////////////////////////////////////////////////////////////

/// ❌ Vulnerable: no limit on amplifier count → reflect() can run out of gas
contract SmurfBulkVuln is SmurfRegistryVuln { }

/// Demo exploit: register a huge list, then call reflect() to DOS
contract Attack_SmurfBulk {
    SmurfBulkVuln public target;
    constructor(SmurfBulkVuln _t) { target = _t; }

    function flood(address[] calldata amps) external payable {
        for (uint256 i; i < amps.length; ++i) {
            target.addAmplifier(amps[i]);
        }
        target.reflect{value: msg.value}();
    }
}

/// ✅ Safe: cap the total number of amplifiers to prevent DOS
contract SmurfBulkSafe {
    address[] public amplifiers;
    address public immutable owner;
    uint256 public constant MAX_AMPLIFIERS = 50;
    event AmplifierAdded(address indexed amp);

    constructor() { owner = msg.sender; }

    function addAmplifier(address amp) external {
        if (msg.sender != owner)                      revert Smurf__NotOwner();
        if (amplifiers.length >= MAX_AMPLIFIERS)      revert Smurf__AmplifierLimitExceeded();
        amplifiers.push(amp);
        emit AmplifierAdded(amp);
    }

    function reflect() external payable {
        uint256 len = amplifiers.length;
        require(len > 0, "no amplifiers");
        uint256 share = msg.value / len;
        for (uint256 i; i < len; ++i) {
            (bool ok, ) = amplifiers[i].call{value: share}("");
            require(ok, "send failed");
        }
    }
}

////////////////////////////////////////////////////////////////////////
// 3) DELEGATECALL AMPLIFICATION VULNERABILITY
////////////////////////////////////////////////////////////////////////

/// ❌ Vulnerable: uses delegatecall to amplifiers → a malicious amp can hijack or self‑destruct this contract
contract SmurfDelegateVuln {
    address[] public amplifiers;
    event AmplifierAdded(address indexed amp);

    function addAmplifier(address amp) external {
        amplifiers.push(amp);
        emit AmplifierAdded(amp);
    }

    /// Broadcasts a raw payload via delegatecall
    function reflectDelegate(bytes calldata data) external {
        for (uint256 i; i < amplifiers.length; ++i) {
            (bool ok, ) = amplifiers[i].delegatecall(data);
            require(ok, "delegatecall failed");
        }
    }
}

/// Demo exploit: malicious amplifier self‑destructs the host
contract Attack_SmurfDelegate {
    SmurfDelegateVuln public target;
    constructor(SmurfDelegateVuln _t) { target = _t; }

    function exploit(bytes calldata data) external {
        // first register attacker as amplifier
        target.addAmplifier(address(this));
        // then trigger delegatecall into this contract
        target.reflectDelegate(data);
    }

    // fallback invoked via delegatecall
    fallback() external {
        selfdestruct(payable(msg.sender));
    }
}

/// ✅ Safe: whitelist amplifiers, use CALL instead of DELEGATECALL
contract SmurfDelegateSafe {
    address[] public amplifiers;
    address public immutable owner;
    mapping(address => bool) public approved;
    event AmplifierAdded(address indexed amp);
    event AmplifierApproved(address indexed amp);

    constructor(address[] memory initial) {
        owner = msg.sender;
        for (uint256 i; i < initial.length; ++i) {
            approved[initial[i]] = true;
            amplifiers.push(initial[i]);
        }
    }

    function approveAmplifier(address amp) external {
        if (msg.sender != owner) revert Smurf__NotOwner();
        approved[amp] = true;
        emit AmplifierApproved(amp);
    }

    function addAmplifier(address amp) external {
        if (msg.sender != owner) revert Smurf__NotOwner();
        require(approved[amp], "not approved");
        amplifiers.push(amp);
        emit AmplifierAdded(amp);
    }

    function reflectDelegate(bytes calldata data) external {
        for (uint256 i; i < amplifiers.length; ++i) {
            address amp = amplifiers[i];
            if (!approved[amp]) revert Smurf__NotOwner();
            // safe: use call, not delegatecall
            (bool ok, ) = amp.call(data);
            require(ok, "call failed");
        }
    }
}

////////////////////////////////////////////////////////////////////////
// 4) REENTRANCY IN REFLECTION
////////////////////////////////////////////////////////////////////////

/// ❌ Vulnerable: no reentrancy guard → an amplifier can re‑enter reflect() and drain more funds
contract SmurfReentrancyVuln {
    address[] public amplifiers;

    function addAmplifier(address amp) external {
        amplifiers.push(amp);
    }

    function reflect() external payable {
        uint256 len = amplifiers.length;
        uint256 share = msg.value / len;
        for (uint256 i; i < len; ++i) {
            (bool ok, ) = amplifiers[i].call{value: share}("");
            require(ok, "send failed");
        }
    }
}

/// Demonstrator amplifier that re‑enters on receipt
contract Attack_SmurfReentrancy {
    SmurfReentrancyVuln public target;
    constructor(SmurfReentrancyVuln _t) { target = _t; }

    receive() external payable {
        if (address(target).balance > 0) {
            // re‑enter to grab more
            target.reflect{value: msg.value}();
        }
    }

    function exploit(address honestAmp) external payable {
        target.addAmplifier(address(this));
        target.addAmplifier(honestAmp);
        target.reflect{value: msg.value}();
    }
}

/// ✅ Safe: nonReentrant guard prevents nested reflect()
contract SmurfReentrancySafe is NonReentrant {
    address[] public amplifiers;

    function addAmplifier(address amp) external {
        amplifiers.push(amp);
    }

    function reflect() external payable nonReentrant {
        uint256 len = amplifiers.length;
        uint256 share = msg.value / len;
        for (uint256 i; i < len; ++i) {
            (bool ok, ) = amplifiers[i].call{value: share}("");
            require(ok, "send failed");
        }
    }
}
