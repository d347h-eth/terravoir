import { config as dotEnvConfig } from "dotenv";
dotEnvConfig();

import { describe, it, expect } from "@jest/globals";

const shouldRunElementIntegrationTests = process.env.RUN_ELEMENT_TESTS === "true";

if (!shouldRunElementIntegrationTests) {
  describe.skip("ElementTestnet", () => {
    it("requires RUN_ELEMENT_TESTS=true", () => {
      expect(true).toBe(true);
    });
  });
} else {
  // Only load the heavy integration suite when explicitly requested to avoid
  // pulling in RPC/DB dependencies during normal CI runs.
  const { registerElementIntegrationSuite } = require("./element-integration-live");
  registerElementIntegrationSuite();
}
