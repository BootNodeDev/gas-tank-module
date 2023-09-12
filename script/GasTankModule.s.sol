// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.21;

import { BaseScript } from "./Base.s.sol";

import { GasTankModule } from "../src/GasTankModule.sol";

contract GasTankModuleScript is BaseScript {
    function setUp() public { }

    function run() public broadcast {
        address _admin = vm.envAddress("ADMIN");
        bytes32 _salt = vm.envBytes32("SALT");

        new GasTankModule{salt: _salt}(_admin);
    }
}
