// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WebProxyAutoDiscoverySuite.sol
/// @notice On‐chain analogues of “Web Proxy Auto-Discovery” (WPAD) patterns:
///   Types: DHCP, DNS, WPADFile, PACScript  
///   AttackTypes: DNSPoisoning, DHCPSpoofing, FileTampering, Bypass  
///   DefenseTypes: DNSSEC, DHCPAuth, HTTPSFetch, SignatureValidation, RateLimit  

enum WebProxyAutoDiscoveryType     { DHCP, DNS, WPADFile, PACScript }
enum WPADAttackType                { DNSPoisoning, DHCPSpoofing, FileTampering, Bypass }
enum WPADDefenseType               { DNSSEC, DHCPAuth, HTTPSFetch, SignatureValidation, RateLimit }

error WPAD__NotAuthorized();
error WPAD__InvalidSignature();
error WPAD__TooManyRequests();
error WPAD__FetchFailed();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE DISCOVERER
//    • ❌ no validation: any record or file accepted → DNSPoisoning, FileTampering
////////////////////////////////////////////////////////////////////////////////
contract WPADVuln {
    mapping(WebProxyAutoDiscoveryType => string) public config;
    event ConfigLoaded(
        address indexed who,
        WebProxyAutoDiscoveryType dtype,
        string                     data,
        WPADAttackType             attack
    );

    function loadConfig(WebProxyAutoDiscoveryType dtype, string calldata data) external {
        config[dtype] = data;
        emit ConfigLoaded(msg.sender, dtype, data, WPADAttackType.DNSPoisoning);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates poisoning, spoofing, tampering and bypass
////////////////////////////////////////////////////////////////////////////////
contract Attack_WPAD {
    WPADVuln public target;
    WebProxyAutoDiscoveryType public lastType;
    string public lastData;

    constructor(WPADVuln _t) { target = _t; }

    function poisonDNS(string calldata record) external {
        target.loadConfig(WebProxyAutoDiscoveryType.DNS, record);
        lastType = WebProxyAutoDiscoveryType.DNS;
        lastData = record;
    }

    function spoofDHCP(string calldata record) external {
        target.loadConfig(WebProxyAutoDiscoveryType.DHCP, record);
        lastType = WebProxyAutoDiscoveryType.DHCP;
        lastData = record;
    }

    function tamperFile(string calldata url) external {
        target.loadConfig(WebProxyAutoDiscoveryType.WPADFile, url);
        lastType = WebProxyAutoDiscoveryType.WPADFile;
        lastData = url;
    }

    function bypass() external {
        target.loadConfig(WebProxyAutoDiscoveryType.PACScript, "");
        lastType = WebProxyAutoDiscoveryType.PACScript;
        lastData = "";
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH DNSSEC
//    • ✅ Defense: DNSSEC – require signed DNS record
////////////////////////////////////////////////////////////////////////////////
contract WPADSafeDNSSEC {
    mapping(WebProxyAutoDiscoveryType => string) public config;
    address public dnssecSigner;
    event ConfigLoaded(
        address indexed who,
        WebProxyAutoDiscoveryType dtype,
        string                     data,
        WPADDefenseType            defense
    );
    error WPAD__InvalidSignature();

    constructor(address _signer) {
        dnssecSigner = _signer;
    }

    function loadDNSConfig(string calldata record, bytes calldata sig) external {
        // only DNS type
        bytes32 h = keccak256(abi.encodePacked(WebProxyAutoDiscoveryType.DNS, record));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != dnssecSigner) revert WPAD__InvalidSignature();

        config[WebProxyAutoDiscoveryType.DNS] = record;
        emit ConfigLoaded(msg.sender, WebProxyAutoDiscoveryType.DNS, record, WPADDefenseType.DNSSEC);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH HTTPS FETCH & SIGNATURE VALIDATION
//    • ✅ Defense: HTTPSFetch – require HTTPS URL  
//               SignatureValidation – verify file signature
////////////////////////////////////////////////////////////////////////////////
contract WPADSafeHTTPS {
    mapping(WebProxyAutoDiscoveryType => string) public config;
    address public fileSigner;
    event ConfigLoaded(
        address indexed who,
        WebProxyAutoDiscoveryType dtype,
        string                     url,
        WPADDefenseType            defense
    );
    error WPAD__FetchFailed();
    error WPAD__InvalidSignature();

    constructor(address _signer) {
        fileSigner = _signer;
    }

    function loadFileConfig(string calldata url, bytes calldata fileSig) external {
        // require HTTPS URL prefix
        bytes memory b = bytes(url);
        require(b.length >= 8, "invalid url");
        require(b[0]=='h' && b[1]=='t' && b[2]=='t' && b[3]=='p' && b[4]=='s', "HTTPS required");

        // stub fetch success check
        bool fetched = true;
        if (!fetched) revert WPAD__FetchFailed();

        // validate signature over url
        bytes32 h = keccak256(abi.encodePacked(WebProxyAutoDiscoveryType.WPADFile, url));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(fileSig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != fileSigner) revert WPAD__InvalidSignature();

        config[WebProxyAutoDiscoveryType.WPADFile] = url;
        emit ConfigLoaded(msg.sender, WebProxyAutoDiscoveryType.WPADFile, url, WPADDefenseType.SignatureValidation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH DHCP AUTH & RATE LIMIT
//    • ✅ Defense: DHCPAuth – require authorized DHCP server  
//               RateLimit – cap loads per block
////////////////////////////////////////////////////////////////////////////////
contract WPADSafeAdvanced {
    mapping(WebProxyAutoDiscoveryType => string) public config;
    mapping(address => bool) public dhcpServer;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 3;

    event ConfigLoaded(
        address indexed who,
        WebProxyAutoDiscoveryType dtype,
        string                     data,
        WPADDefenseType            defense
    );
    error WPAD__NotAuthorized();
    error WPAD__TooManyRequests();

    function authorizeDHCP(address server, bool ok) external {
        // stub admin
        dhcpServer[server] = ok;
    }

    function loadDHCPConfig(string calldata record) external {
        if (!dhcpServer[msg.sender]) revert WPAD__NotAuthorized();
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert WPAD__TooManyRequests();

        config[WebProxyAutoDiscoveryType.DHCP] = record;
        emit ConfigLoaded(msg.sender, WebProxyAutoDiscoveryType.DHCP, record, WPADDefenseType.DHCPAuth);
    }
}
