// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Self-contained DHS Token (no external imports)
 *
 * Features:
 * - ERC20 (name "DHS Token", symbol "DHS", 18 decimals)
 * - Roles: DEFAULT_ADMIN, MINTER, PAUSER, COMPLIANCE
 * - Pausable (global)
 * - Blocklist + (optional) Allowlist
 * - Optional supply cap (0 = unlimited)
 *
 * Notes:
 * - No OpenZeppelin dependencies, so you won't get ENOENT path errors.
 * - If you later want EIP-2612 permit or snapshots, we can extend this file.
 */

contract DHS {
    // -------- ERC20 storage --------
    string public constant name = "DHS Token";
    string public constant symbol = "DHS";
    uint8  public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;

    // -------- Roles (minimal AccessControl-like) --------
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 public constant MINTER_ROLE        = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE        = keccak256("PAUSER_ROLE");
    bytes32 public constant COMPLIANCE_ROLE    = keccak256("COMPLIANCE_ROLE");

    mapping(bytes32 => mapping(address => bool)) private _roles;

    // -------- Pausable --------
    bool public paused;

    // -------- Compliance --------
    mapping(address => bool) public isBlocked;
    mapping(address => bool) public isAllowlisted;
    bool public allowlistEnabled;

    // -------- Supply cap --------
    uint256 public immutable maxSupply; // 0 = unlimited

    // -------- Events --------
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    event Paused(address indexed account);
    event Unpaused(address indexed account);

    event BlockStatusSet(address indexed account, bool blocked);
    event AllowlistStatusSet(address indexed account, bool status);
    event AllowlistToggled(bool enabled);

    // -------- Modifiers --------
    modifier onlyRole(bytes32 role) {
        require(hasRole(role, msg.sender), "DHS: missing role");
        _;
    }

    modifier notPaused() {
        require(!paused, "DHS: paused");
        _;
    }

    constructor(address admin, uint256 initialSupply, uint256 cap) {
        require(admin != address(0), "admin=0");
        if (cap != 0) require(cap >= initialSupply, "cap<initial");
        maxSupply = cap;

        // grant roles to admin
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(MINTER_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(COMPLIANCE_ROLE, admin);

        if (initialSupply > 0) {
            _mint(admin, initialSupply);
        }
    }

    // -------- Role management --------
    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role][account];
    }

    function grantRole(bytes32 role, address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(role, account);
    }

    function revokeRole(bytes32 role, address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(role, account);
    }

    function _grantRole(bytes32 role, address account) internal {
        if (!_roles[role][account]) {
            _roles[role][account] = true;
            emit RoleGranted(role, account, msg.sender);
        }
    }

    function _revokeRole(bytes32 role, address account) internal {
        if (_roles[role][account]) {
            _roles[role][account] = false;
            emit RoleRevoked(role, account, msg.sender);
        }
    }

    // -------- Pausable --------
    function pause() external onlyRole(PAUSER_ROLE) {
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        paused = false;
        emit Unpaused(msg.sender);
    }

    // -------- Compliance management --------
    function setBlocked(address account, bool blocked) external onlyRole(COMPLIANCE_ROLE) {
        isBlocked[account] = blocked;
        emit BlockStatusSet(account, blocked);
    }

    function setAllowlisted(address account, bool status) external onlyRole(COMPLIANCE_ROLE) {
        isAllowlisted[account] = status;
        emit AllowlistStatusSet(account, status);
    }

    function setAllowlistEnabled(bool enabled) external onlyRole(COMPLIANCE_ROLE) {
        allowlistEnabled = enabled;
        emit AllowlistToggled(enabled);
    }

    // -------- ERC20: view --------
    function balanceOf(address account) public view returns (uint256) {
        return _balances[account];
    }

    function allowance(address owner, address spender) public view returns (uint256) {
        return _allowances[owner][spender];
    }

    // -------- ERC20: core --------
    function transfer(address to, uint256 amount) external notPaused returns (bool) {
        _complianceCheck(msg.sender, to);
        _transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external notPaused returns (bool) {
        _approve(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external notPaused returns (bool) {
        _complianceCheck(from, to);
        uint256 currentAllowance = _allowances[from][msg.sender];
        require(currentAllowance >= amount, "DHS: insufficient allowance");
        unchecked {
            _approve(from, msg.sender, currentAllowance - amount);
        }
        _transfer(from, to, amount);
        return true;
    }

    // -------- Mint/Burn --------
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        _mint(to, amount);
    }

    function burn(uint256 amount) external notPaused {
        _burn(msg.sender, amount);
    }

    function burnFrom(address from, uint256 amount) external notPaused {
        uint256 currentAllowance = _allowances[from][msg.sender];
        require(currentAllowance >= amount, "DHS: insufficient allowance");
        unchecked {
            _approve(from, msg.sender, currentAllowance - amount);
        }
        _burn(from, amount);
    }

    // -------- Internal helpers --------
    function _complianceCheck(address from, address to) internal view {
        require(!isBlocked[from], "DHS: sender blocked");
        require(!isBlocked[to], "DHS: recipient blocked");
        if (allowlistEnabled) {
            require(isAllowlisted[from], "DHS: sender not allowlisted");
            require(isAllowlisted[to], "DHS: recipient not allowlisted");
        }
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(to != address(0), "DHS: to=0");
        uint256 fromBal = _balances[from];
        require(fromBal >= amount, "DHS: balance");
        unchecked {
            _balances[from] = fromBal - amount;
        }
        _balances[to] += amount;
        emit Transfer(from, to, amount);
    }

    function _approve(address owner, address spender, uint256 amount) internal {
        require(owner != address(0) && spender != address(0), "DHS: zero addr");
        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }

    function _mint(address to, uint256 amount) internal {
        require(to != address(0), "DHS: to=0");
        if (maxSupply != 0) {
            require(totalSupply + amount <= maxSupply, "DHS: cap exceeded");
        }
        totalSupply += amount;
        _balances[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function _burn(address from, uint256 amount) internal {
        require(from != address(0), "DHS: from=0");
        uint256 fromBal = _balances[from];
        require(fromBal >= amount, "DHS: balance");
        unchecked {
            _balances[from] = fromBal - amount;
        }
        totalSupply -= amount;
        emit Transfer(from, address(0), amount);
    }
}
