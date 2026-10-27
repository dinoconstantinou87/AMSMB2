import XCTest
@testable import AMSMB2

final class RequestLifetimeTests: XCTestCase {
    func testCommandKeepsWhatItRetainsAliveUntilReleased() {
        weak var buffer: ReplyBuffer?
        var command: SMB2Client.CBData?
        do {
            let made = ReplyBuffer(count: 16)
            buffer = made
            command = SMB2Client.CBData(timeout: 0, retaining: [made])
        }

        XCTAssertNotNil(buffer)
        command = nil
        XCTAssertNil(command)
        XCTAssertNil(buffer)
    }
}
