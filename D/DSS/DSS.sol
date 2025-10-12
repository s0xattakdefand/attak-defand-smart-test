// SPDX-License-Identifier: AGPL-3.0-or-later

// Copyright (C) 2017, 2018, 2020 Rain <[email protected]>
// Copyright (C) 2021 Dai Foundation

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

pragma solidity ^0.6.12;

contract Dai {
    // --- Auth ---
    mapping (address => uint) public wards;
    function rely(address guy) external auth { wards[guy] = 1; }
    function deny(address guy) external auth { wards[guy] = 0; }
    modifier auth {
        require(wards[msg.sender] == 1, "Dai/not-authorized");
        _;
    }

    // --- ERC20 Data ---
    string  public constant name     = "Dai Stablecoin";
    string  public constant symbol   = "DAI";
    string  public constant version  = "1";
    uint8   public constant decimals = 18;
    address public daiJoin;
    uint256 public totalSupply;

    mapping (address => uint)                      public balanceOf;
    mapping (address => mapping (address => uint)) public allowance;
    mapping (address => uint)                      public nonces;

    event Approval(address indexed src, address indexed guy, uint wad);
    event Transfer(address indexed src, address indexed dst, uint wad);
    event LogNote(
        bytes4   indexed sig,
        bytes32  indexed arg1,
        bytes32  indexed arg2,
        bytes32  indexed arg3,
        bytes    data
    ) anonymous;

    // --- Math ---
    uint256 constant private ONE = 1.00E18;
    function add(uint x, uint y) internal pure returns (uint z) {
        require((z = x + y) >= x);
    }
    function sub(uint x, uint y) internal pure returns (uint z) {
        require((z = x - y) <= x);
    }
    function mul(uint x, uint y) internal pure returns (uint z) {
        require(y == 0 || (z = x * y) / y == x);
    }
    function wmul(uint x, uint y) internal pure returns (uint z) {
        z = mul(x, y) / ONE;
    }
    function wdiv(uint x, uint y) internal pure returns (uint z) {
        z = mul(x, ONE) / y;
    }

    // --- Init ---
    constructor(address vat_) public {
        wards[msg.sender] = 1;
        daiJoin = vat_;  // Initially set to Vat, but typically a join adapter
    }

    // --- Token functions ---
    function transfer(address guy, uint wad) external returns (bool) {
        require(balanceOf[msg.sender] >= wad, "Dai/insufficient-balance");
        balanceOf[msg.sender] = sub(balanceOf[msg.sender], wad);
        balanceOf[guy] = add(balanceOf[guy], wad);
        emit Transfer(msg.sender, guy, wad);
        return true;
    }

    function transferFrom(address src, address dst, uint wad) external returns (bool) {
        require(balanceOf[src] >= wad, "Dai/insufficient-balance");
        if (src != msg.sender && allowance[src][msg.sender] != type(uint).max) {
            require(allowance[src][msg.sender] >= wad, "Dai/insufficient-allowance");
            allowance[src][msg.sender] = sub(allowance[src][msg.sender], wad);
        }
        balanceOf[src] = sub(balanceOf[src], wad);
        balanceOf[dst] = add(balanceOf[dst], wad);
        emit Transfer(src, dst, wad);
        return true;
    }

    function approve(address guy, uint wad) external returns (bool) {
        allowance[msg.sender][guy] = wad;
        emit Approval(msg.sender, guy, wad);
        return true;
    }

    // --- Mint/Burn via Vat ---
    function mint(address usr, uint wad) external auth {
        balanceOf[usr] = add(balanceOf[usr], wad);
        totalSupply    = add(totalSupply, wad);
        emit Transfer(address(0), usr, wad);
        // Interact with Vat to mint
    }

    function burn(address usr, uint wad) external {
        require(balanceOf[usr] >= wad, "Dai/insufficient-balance");
        require(msg.sender == daiJoin || wards[msg.sender] == 1, "Dai/not-authorized");
        balanceOf[usr] = sub(balanceOf[usr], wad);
        totalSupply    = sub(totalSupply, wad);
        emit Transfer(usr, address(0), wad);
        // Interact with Vat to burn
    }

    // --- Permit support (EIP-2612) ---
    function permit(address holder, address spender, uint256 nonce, uint256 expiry,
                    bool allowed, uint8 v, bytes32 r, bytes32 s) external
    {
        bytes32 digest =
            keccak256(abi.encodePacked(
                "\x19\x01",
                keccak256(abi.encode(
                    "Permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)",
                    holder,
                    spender,
                    nonce,
                    expiry,
                    allowed,
                    v,
                    r,
                    s))
            ));

        require(holder != address(0), "Dai/not-set");
        require(holder == ecrecover(digest, v, r, s), "Dai/invalid-permit");
        require(expiry == 0 || now <= expiry, "Dai/permit-expired");
        require(nonce == nonces[holder]++, "Dai/invalid-nonce");
        uint wad = allowed ? type(uint).max : 0;
        allowance[holder][spender] = wad;
        emit Approval(holder, spender, wad);
    }
}