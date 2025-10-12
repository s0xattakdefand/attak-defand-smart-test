// SPDX-License-Identifier: AGPL-3.0-or-later

// Copyright (C) 2020 MakerDAO
// Adapted for minimal dependencies to resolve import error

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

pragma solidity >=0.6.12;

// DSNote for event logging
contract DSNote {
    event LogNote(
        bytes4   indexed  sig,
        address  indexed  usr,
        bytes32  indexed  arg1,
        bytes32  indexed  arg2,
        bytes             data
    ) anonymous;

    modifier note {
        _;
        // Simplified note logging
        emit LogNote(msg.sig, msg.sender, bytes32(0), bytes32(0), msg.data);
    }
}

// Interfaces required by DssPsm.sol
interface VatLike {
    function frob(bytes32 ilk, address u, address v, address w, int dink, int dart) external;
    function move(address src, address dst, uint256 rad) external;
}

interface GemLike {
    function transferFrom(address src, address dst, uint256 wad) external returns (bool);
    function approve(address usr, uint256 wad) external returns (bool);
}

interface DaiLike {
    function transfer(address dst, uint256 wad) external returns (bool);
    function transferFrom(address src, address dst, uint256 wad) external returns (bool);
    function approve(address usr, uint256 wad) external returns (bool);
}

interface GemJoinLike {
    function gem() external view returns (address);
    function join(address usr, uint256 wad) external;
    function exit(address usr, uint256 wad) external;
}