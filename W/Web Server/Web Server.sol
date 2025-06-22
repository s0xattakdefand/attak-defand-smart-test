// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WebServerSuite.sol
/// @notice On‑chain analogues of “Web Server” patterns:
///   Types: Static, Dynamic, ReverseProxy, LoadBalancer  
///   AttackTypes: DirectoryTraversal, XSSInjection, DoS, SSRF  
///   DefenseTypes: InputValidation, OutputEncoding, RateLimit, DomainWhitelist  

enum WebServerType        { Static, Dynamic, ReverseProxy, LoadBalancer }
enum WebServerAttackType  { DirectoryTraversal, XSSInjection, DoS, SSRF }
enum WebServerDefenseType { InputValidation, OutputEncoding, RateLimit, DomainWhitelist }

error WS__InvalidPath();
error WS__UnsafeInput();
error WS__TooManyRequests();
error WS__DomainNotAllowed();

////////////////////////////////////////////////////////////////////////
// 1) STATIC FILE SERVER
//    • Type: Static
//    • Vulnerable to directory traversal
////////////////////////////////////////////////////////////////////////
contract StaticFileServerVuln {
    mapping(string => bytes) public files;
    event FileServed(address indexed who, string path, bytes content, WebServerAttackType attack);

    function addFile(string calldata path, bytes calldata content) external {
        files[path] = content;
    }

    /// ❌ no path sanitization
    function serve(string calldata path) external {
        bytes memory content = files[path];
        emit FileServed(msg.sender, path, content, WebServerAttackType.DirectoryTraversal);
    }
}

contract Attack_DirectoryTraversal {
    StaticFileServerVuln public srv;
    constructor(StaticFileServerVuln _srv) { srv = _srv; }

    /// attacker requests traversal path
    function steal() external {
        srv.serve("../../etc/passwd");
    }
}

contract StaticFileServerSafe {
    mapping(string => bytes) public files;
    event FileServed(address indexed who, string path, bytes content, WebServerDefenseType defense);

    function addFile(string calldata path, bytes calldata content) external {
        files[path] = content;
    }

    /// ✅ reject any “..” in path
    function serve(string calldata path) external {
        bytes memory p = bytes(path);
        for (uint i; i + 1 < p.length; i++) {
            if (p[i] == "." && p[i+1] == ".") revert WS__InvalidPath();
        }
        bytes memory content = files[path];
        emit FileServed(msg.sender, path, content, WebServerDefenseType.InputValidation);
    }
}

////////////////////////////////////////////////////////////////////////
// 2) DYNAMIC TEMPLATE RENDER
//    • Type: Dynamic
//    • Vulnerable to XSS injection
////////////////////////////////////////////////////////////////////////
contract TemplateRenderVuln {
    event Rendered(address indexed who, string html, WebServerAttackType attack);

    /// ❌ injects input directly into template
    function render(string calldata tpl, string calldata userInput) external {
        string memory html = string(abi.encodePacked(tpl, userInput));
        emit Rendered(msg.sender, html, WebServerAttackType.XSSInjection);
    }
}

contract Attack_XSSInjection {
    TemplateRenderVuln public trg;
    constructor(TemplateRenderVuln _t) { trg = _t; }

    function exploit() external {
        trg.render("<div>", "<script>alert(1)</script>");
    }
}

contract TemplateRenderSafe {
    event Rendered(address indexed who, string html, WebServerDefenseType defense);

    /// ✅ naive output encoding: escape '<' and '>'
    function render(string calldata tpl, string calldata userInput) external {
        bytes memory inb = bytes(userInput);
        bytes memory esc = new bytes(inb.length * 6); // worst-case &lt;&gt;
        uint k;
        for (uint i; i < inb.length; i++) {
            if (inb[i] == "<") {
                bytes memory e = bytes("&lt;");
                for (uint j; j < e.length; j++) esc[k++] = e[j];
            } else if (inb[i] == ">") {
                bytes memory e = bytes("&gt;");
                for (uint j; j < e.length; j++) esc[k++] = e[j];
            } else {
                esc[k++] = inb[i];
            }
        }
        bytes memory out = new bytes(bytes(tpl).length + k);
        uint idx;
        for (uint i; i < bytes(tpl).length; i++) out[idx++] = bytes(tpl)[i];
        for (uint i; i < k; i++) out[idx++] = esc[i];
        emit Rendered(msg.sender, string(out), WebServerDefenseType.OutputEncoding);
    }
}

////////////////////////////////////////////////////////////////////////
// 3) REVERSE PROXY
//    • Type: ReverseProxy
//    • Vulnerable to SSRF
////////////////////////////////////////////////////////////////////////
contract ReverseProxyVuln {
    event Proxied(address indexed who, string url, bytes data, WebServerAttackType.SSRF);

    /// ❌ trusts arbitrary URL
    function proxy(string calldata url) external {
        bytes memory resp = abi.encodePacked("fetched:", url);
        emit Proxied(msg.sender, url, resp, WebServerAttackType.SSRF);
    }
}

contract Attack_SSRF {
    ReverseProxyVuln public trg;
    constructor(ReverseProxyVuln _t) { trg = _t; }

    function exploit() external {
        trg.proxy("http://169.254.169.254/latest/meta-data");
    }
}

contract ReverseProxySafe {
    mapping(string => bool) public allowed;
    event Proxied(address indexed who, string url, bytes data, WebServerDefenseType defense);

    function setAllowed(string calldata url, bool ok) external {
        allowed[url] = ok;
    }

    /// ✅ only allow whitelisted URLs
    function proxy(string calldata url) external {
        if (!allowed[url]) revert WS__DomainNotAllowed();
        bytes memory resp = abi.encodePacked("fetched:", url);
        emit Proxied(msg.sender, url, resp, WebServerDefenseType.DomainWhitelist);
    }
}

////////////////////////////////////////////////////////////////////////
// 4) LOAD BALANCER
//    • Type: LoadBalancer
//    • Vulnerable to request flooding (DoS)
////////////////////////////////////////////////////////////////////////
contract LoadBalancerVuln {
    address[] public backends;
    event Forwarded(address indexed who, address backend, WebServerAttackType attack);

    function addBackend(address b) external {
        backends.push(b);
    }

    /// ❌ no rate‑limit: forwards every call to all
    function handleRequest() external {
        for (uint i; i < backends.length; i++) {
            emit Forwarded(msg.sender, backends[i], WebServerAttackType.DoS);
        }
    }
}

contract Attack_DoS {
    LoadBalancerVuln public lb;
    constructor(LoadBalancerVuln _lb) { lb = _lb; }

    function flood(uint n) external {
        for (uint i; i < n; i++) {
            lb.handleRequest();
        }
    }
}

contract LoadBalancerSafe {
    address[] public backends;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    uint256 public constant MAX_PER_BLOCK = 5;
    event Forwarded(address indexed who, address backend, WebServerDefenseType defense);

    function addBackend(address b) external {
        backends.push(b);
    }

    /// ✅ rate‑limit requests per sender per block
    function handleRequest() external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert WS__TooManyRequests();
        for (uint i; i < backends.length; i++) {
            emit Forwarded(msg.sender, backends[i], WebServerDefenseType.RateLimit);
        }
    }
}
