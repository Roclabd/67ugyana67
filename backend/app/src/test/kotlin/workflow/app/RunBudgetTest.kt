package workflow.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class RunBudgetTest {
    @Test fun `ai graph gets the longer configurable budget`() {
        assertEquals(120_000, RunService.runBudgetMillis(false, 240, 0))
        assertEquals(240_000, RunService.runBudgetMillis(true, 240, 0))
        assertEquals(300_000, RunService.runBudgetMillis(true, 300, 0))
        assertEquals(120_000, RunService.runBudgetMillis(true, 30, 0))
        assertEquals(270_000, RunService.runBudgetMillis(true, 240, 30))
    }
}

class CiWaitTest {
    @Test fun `ci wait covers the full ai run budget with a margin`() {
        org.junit.jupiter.api.Assertions.assertTrue(CiController.waitMillis(240) > RunService.runBudgetMillis(true, 240, 0))
        org.junit.jupiter.api.Assertions.assertTrue(CiController.waitMillis(300) > RunService.runBudgetMillis(true, 300, 0))
        org.junit.jupiter.api.Assertions.assertTrue(CiController.waitMillis(240) >= 245_000)
    }
}
