// SPDX-License-Identifier: MIT
pragma solidity >=0.8.19 <=0.9.0;

import { BaseScript } from "./Base.s.sol";

import { GasTank } from "../src/GasTank.sol";

contract GasTankScript is BaseScript {
    function setUp() public {}

    function run() broadcast public {
        new GasTank();
    }
}
