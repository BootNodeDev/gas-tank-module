// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.21;

import { GasTankModule } from "../src/GasTankModule.sol";

import { BaseScript, console2 } from "./Base.s.sol";

/// @dev See the Solidity Scripting tutorial: https://book.getfoundry.sh/tutorials/solidity-scripting
contract Deploy is BaseScript {
    function run() public broadcast returns (GasTankModule) {
        // foo = new Foo();
        // console2.log("deploy");
        // GasTankModule gt = new GasTankModule();
        // return gt;
    }
}
