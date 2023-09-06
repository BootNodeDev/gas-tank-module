// SPDX-License-Identifier: MIT
pragma solidity >=0.8.19 <=0.9.0;

import { BaseScript } from "./Base.s.sol";

import { GasTankModule } from "../src/GasTankModule.sol";

contract GasTankModuleScript is BaseScript {
    function setUp() public { }

    function run() public broadcast {
        new GasTankModule();
    }
}
