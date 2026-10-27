import XCTest
@testable import AMSMB2

final class CancellationTests: XCTestCase {
    func testCancelWakesABlockedWait() throws {
        let command = SMB2Client.CBData(timeout: 0)
        let cancellation = SMB2Cancellation()
        XCTAssertTrue(cancellation.begin(command, since: cancellation.mark))
        let woken = expectation(description: "woken")
        Thread {
            command.waitUntilFinished()
            woken.fulfill()
        }.start()

        cancellation.cancel()

        wait(for: [woken], timeout: 5)
        XCTAssertThrowsError(try command.outcome()) { error in
            XCTAssertTrue(error is CancellationError)
        }
    }

    func testCancelLeavesEndedCommandsAlone() {
        let command = SMB2Client.CBData(timeout: 0)
        let cancellation = SMB2Cancellation()
        XCTAssertTrue(cancellation.begin(command, since: cancellation.mark))
        cancellation.end(command)

        cancellation.cancel()

        XCTAssertNoThrow(try command.outcome())
    }

    func testCancelBetweenCommandsRefusesTheNextOne() {
        let cancellation = SMB2Cancellation()
        let mark = cancellation.mark
        let first = SMB2Client.CBData(timeout: 0)
        XCTAssertTrue(cancellation.begin(first, since: mark))
        cancellation.end(first)

        cancellation.cancel()

        XCTAssertFalse(cancellation.begin(SMB2Client.CBData(timeout: 0), since: mark))
    }

    func testCancelLeavesLaterCallsUsable() {
        let cancellation = SMB2Cancellation()
        cancellation.cancel()

        XCTAssertTrue(cancellation.begin(SMB2Client.CBData(timeout: 0), since: cancellation.mark))
    }
}
