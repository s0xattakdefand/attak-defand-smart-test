pragma solidity ^0.8.0;

// Interface for ERC-20 standard
interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

// DIMA ERC-20 token contract
contract DIMA is IERC20 {
    string public constant name = "DIMA";
    string public constant symbol = "DIMA";
    uint8 public constant decimals = 18;
    uint256 private _totalSupply;
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;

    // Constructor to initialize the token with a total supply
    constructor() {
        // Total supply of 10,000,000,000 DIMA tokens (based on web:4)
        _totalSupply = 10_000_000_000 * 10**uint256(decimals);
        _balances[msg.sender] = _totalSupply;
        emit Transfer(address(0), msg.sender, _totalSupply);
    }

    // Returns the total token supply
    function totalSupply() external view override returns (uint256) {
        return _totalSupply;
    }

    // Returns the balance of an account
    function balanceOf(address account) external view override returns (uint256) {
        return _balances[account];
    }

    // Transfers tokens to a recipient
    function transfer(address recipient, uint256 amount) external override returns (bool) {
        require(recipient != address(0), "DIMA: transfer to the zero address");
        require(_balances[msg.sender] >= amount, "DIMA: insufficient balance");

        _balances[msg.sender] -= amount;
        _balances[recipient] += amount;
        emit Transfer(msg.sender, recipient, amount);
        return true;
    }

    // Returns the allowance of a spender for an owner
    function allowance(address owner, address spender) external view override returns (uint256) {
        return _allowances[owner][spender];
    }

    // Approves a spender to spend a certain amount of tokens
    function approve(address spender, uint256 amount) external override returns (bool) {
        require(spender != address(0), "DIMA: approve to the zero address");

        _allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    // Transfers tokens from one account to another using allowance
    function transferFrom(address sender, address recipient, uint256 amount) external override returns (bool) {
        require(sender != address(0), "DIMA: transfer from the zero address");
        require(recipient != address(0), "DIMA: transfer to the zero address");
        require(_balances[sender] >= amount, "DIMA: insufficient balance");
        require(_allowances[sender][msg.sender] >= amount, "DIMA: insufficient allowance");

        _balances[sender] -= amount;
        _balances[recipient] += amount;
        _allowances[sender][msg.sender] -= amount;
        emit Transfer(sender, recipient, amount);
        return true;
    }

    // Optional: Function to burn tokens (reduce total supply)
    function burn(uint256 amount) external {
        require(_balances[msg.sender] >= amount, "DIMA: insufficient balance");

        _balances[msg.sender] -= amount;
        _totalSupply -= amount;
        emit Transfer(msg.sender, address(0), amount);
    }
}