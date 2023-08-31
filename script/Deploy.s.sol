// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.19 <=0.9.0;

import { GasTank } from "../src/GasTank.sol";

import { BaseScript, console2 } from "./Base.s.sol";

/// @dev See the Solidity Scripting tutorial: https://book.getfoundry.sh/tutorials/solidity-scripting
contract Deploy is BaseScript {
  function run() public broadcast returns (GasTank) {
      // foo = new Foo();
      // console2.log("deploy");
      GasTank gt = new GasTank();
      return gt;
  }
}
