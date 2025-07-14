// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DECENTRALIZED EXCHANGE (DEX) DEMO
 * — A simple constant‐product automated market maker supporting
 *   multiple ERC-20 token pairs, with role‐based fee administration
 *   and full event logging.
 */

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address acct) external view returns (uint256);
    function transfer(address to, uint256 amt) external returns (bool);
    function transferFrom(address from, address to, uint256 amt) external returns (bool);
    function approve(address spender, uint256 amt) external returns (bool);
}

abstract contract Ownable {
    address private _owner;
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);
    constructor() { _owner = msg.sender; emit OwnershipTransferred(address(0), _owner); }
    modifier onlyOwner() { require(msg.sender == _owner, "DEX: only owner"); _; }
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "DEX: zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
    function owner() public view returns (address) { return _owner; }
}

contract DecentralizedExchange is Ownable {
    struct Pair {
        IERC20 token0;
        IERC20 token1;
        uint112 reserve0;
        uint112 reserve1;
        uint32  blockTimestampLast;
        uint16  feeBP;            // fee in basis points (e.g. 30 = 0.3%)
        uint256 totalLiquidity;
        mapping(address => uint256) liquidity;
    }

    // pairId = keccak256(abi.encodePacked(tokenA, tokenB))
    mapping(bytes32 => Pair) private _pairs;
    bytes32[] public allPairs;

    event PairCreated(address indexed token0, address indexed token1, bytes32 indexed pairId);
    event LiquidityAdded(bytes32 indexed pairId, address indexed provider, uint256 amount0, uint256 amount1, uint256 liquidityMinted);
    event LiquidityRemoved(bytes32 indexed pairId, address indexed provider, uint256 amount0, uint256 amount1, uint256 liquidityBurned);
    event Swapped(bytes32 indexed pairId, address indexed trader, address indexed tokenIn, uint256 amountIn, address tokenOut, uint256 amountOut);
    event FeeUpdated(bytes32 indexed pairId, uint16 oldFeeBP, uint16 newFeeBP);

    modifier validPair(bytes32 pairId) {
        require(_pairs[pairId].totalLiquidity > 0, "DEX: pair not exists");
        _;
    }

    /// @notice Create a new token pair; only owner
    function createPair(IERC20 tokenA, IERC20 tokenB, uint16 feeBP) external onlyOwner returns (bytes32) {
        require(address(tokenA) != address(tokenB), "DEX: identical tokens");
        require(feeBP <= 1000, "DEX: fee too high");
        (IERC20 token0, IERC20 token1) = address(tokenA) < address(tokenB)
            ? (tokenA, tokenB)
            : (tokenB, tokenA);
        bytes32 pairId = keccak256(abi.encodePacked(token0, token1));
        require(_pairs[pairId].totalLiquidity == 0, "DEX: pair exists");

        Pair storage p = _pairs[pairId];
        p.token0 = token0;
        p.token1 = token1;
        p.feeBP  = feeBP;
        allPairs.push(pairId);

        emit PairCreated(address(token0), address(token1), pairId);
        return pairId;
    }

    /// @notice Owner can update fee for a pair
    function updateFee(bytes32 pairId, uint16 newFeeBP) external onlyOwner validPair(pairId) {
        require(newFeeBP <= 1000, "DEX: fee too high");
        Pair storage p = _pairs[pairId];
        emit FeeUpdated(pairId, p.feeBP, newFeeBP);
        p.feeBP = newFeeBP;
    }

    /// @notice Add liquidity to a pair
    function addLiquidity(bytes32 pairId, uint256 amount0, uint256 amount1) external validPair(pairId) returns (uint256 liquidityMinted) {
        Pair storage p = _pairs[pairId];

        // transfer tokens in
        require(p.token0.transferFrom(msg.sender, address(this), amount0), "DEX: transfer token0");
        require(p.token1.transferFrom(msg.sender, address(this), amount1), "DEX: transfer token1");

        // compute liquidity to mint
        if (p.totalLiquidity == 0) {
            liquidityMinted = sqrt(amount0 * amount1);
        } else {
            liquidityMinted = min(
                (amount0 * p.totalLiquidity) / p.reserve0,
                (amount1 * p.totalLiquidity) / p.reserve1
            );
        }
        require(liquidityMinted > 0, "DEX: insufficient liquidity minted");

        // update reserves & mint
        p.reserve0 += uint112(amount0);
        p.reserve1 += uint112(amount1);
        p.totalLiquidity += liquidityMinted;
        p.liquidity[msg.sender] += liquidityMinted;

        emit LiquidityAdded(pairId, msg.sender, amount0, amount1, liquidityMinted);
    }

    /// @notice Remove liquidity from a pair
    function removeLiquidity(bytes32 pairId, uint256 liquidityAmount) external validPair(pairId) returns (uint256 amount0, uint256 amount1) {
        Pair storage p = _pairs[pairId];
        require(p.liquidity[msg.sender] >= liquidityAmount, "DEX: insufficient liquidity");

        amount0 = (liquidityAmount * p.reserve0) / p.totalLiquidity;
        amount1 = (liquidityAmount * p.reserve1) / p.totalLiquidity;
        require(amount0 > 0 && amount1 > 0, "DEX: insufficient amount");

        // burn liquidity
        p.liquidity[msg.sender] -= liquidityAmount;
        p.totalLiquidity -= liquidityAmount;

        // update reserves
        p.reserve0 -= uint112(amount0);
        p.reserve1 -= uint112(amount1);

        // transfer tokens out
        require(p.token0.transfer(msg.sender, amount0), "DEX: transfer token0");
        require(p.token1.transfer(msg.sender, amount1), "DEX: transfer token1");

        emit LiquidityRemoved(pairId, msg.sender, amount0, amount1, liquidityAmount);
    }

    /// @notice Swap exact amountIn of tokenIn for tokenOut
    function swap(bytes32 pairId, IERC20 tokenIn, uint256 amountIn, uint256 minAmountOut) external validPair(pairId) returns (uint256 amountOut) {
        Pair storage p = _pairs[pairId];
        require(tokenIn == p.token0 || tokenIn == p.token1, "DEX: invalid tokenIn");

        (IERC20 tokenOut, uint112 reserveIn, uint112 reserveOut) = tokenIn == p.token0
            ? (p.token1, p.reserve0, p.reserve1)
            : (p.token0, p.reserve1, p.reserve0);

        // transfer in
        require(tokenIn.transferFrom(msg.sender, address(this), amountIn), "DEX: transfer in");

        // apply fee
        uint256 amountInWithFee = amountIn * (10000 - p.feeBP) / 10000;
        // constant product formula: amountOut = (reserveOut * amountInWithFee) / (reserveIn + amountInWithFee)
        amountOut = (uint256(reserveOut) * amountInWithFee) / (uint256(reserveIn) + amountInWithFee);
        require(amountOut >= minAmountOut, "DEX: insuf output amount");

        // update reserves
        if (tokenIn == p.token0) {
            p.reserve0 += uint112(amountIn);
            p.reserve1 -= uint112(amountOut);
        } else {
            p.reserve1 += uint112(amountIn);
            p.reserve0 -= uint112(amountOut);
        }

        // transfer out
        require(tokenOut.transfer(msg.sender, amountOut), "DEX: transfer out");

        emit Swapped(pairId, msg.sender, address(tokenIn), amountIn, address(tokenOut), amountOut);
    }

    /// @notice Query reserves for a pair
    function getReserves(bytes32 pairId) external view validPair(pairId) returns (uint112 reserve0, uint112 reserve1) {
        Pair storage p = _pairs[pairId];
        return (p.reserve0, p.reserve1);
    }

    /// @notice Query liquidity balance of a provider
    function getLiquidity(bytes32 pairId, address provider) external view validPair(pairId) returns (uint256) {
        return _pairs[pairId].liquidity[provider];
    }

    // --- INTERNAL UTILS ----

    function min(uint256 a, uint256 b) private pure returns (uint256) {
        return a < b ? a : b;
    }
    function sqrt(uint256 y) private pure returns (uint256 z) {
        if (y > 3) {
            z = y;
            uint256 x = y / 2 + 1;
            while (x < z) { z = x; x = (y / x + x) / 2; }
        } else if (y != 0) { z = 1; }
    }
}
