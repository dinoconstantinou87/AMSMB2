import XCTest
@testable import AMSMB2

final class FileHandleTests: XCTestCase {
    private lazy var server: URL = .init(string: ProcessInfo.processInfo.environment["SMB_SERVER"]!)!
    private lazy var share: String = ProcessInfo.processInfo.environment["SMB_SHARE"]!
    private lazy var credential: URLCredential? = {
        guard let user = ProcessInfo.processInfo.environment["SMB_USER"],
              let password = ProcessInfo.processInfo.environment["SMB_PASSWORD"]
        else { return nil }
        return URLCredential(user: user, password: password, persistence: .forSession)
    }()

    func testHandleStaysUsableAcrossAwaits() async throws {
        let smb = try XCTUnwrap(SMB2Manager(url: server, credential: credential))
        let path = "handle-\(UUID().uuidString).bin"
        let contents = Data((0..<(1 << 18)).map { UInt8($0 % 251) })
        addTeardownBlock {
            try? await smb.removeFile(atPath: path)
            try await smb.disconnectShare(gracefully: true)
        }

        try await smb.connectShare(name: share)
        try await smb.write(data: contents, toPath: path, progress: nil)

        let file = try await smb.openFile(atPath: path)
        let size = try await file.size
        XCTAssertEqual(size, UInt64(contents.count))

        let head = try await file.read(range: 0..<1024)
        let tail = try await file.read(range: UInt64(contents.count - 1024)..<UInt64(contents.count))
        let middle = try await file.read(range: 4096..<8192)

        XCTAssertEqual(head, contents.prefix(1024))
        XCTAssertEqual(tail, contents.suffix(1024))
        XCTAssertEqual(middle, contents[4096..<8192])

        try await file.close()
    }

    func testReadSpansSeveralRequests() async throws {
        let smb = try XCTUnwrap(SMB2Manager(url: server, credential: credential))
        let path = "handle-span-\(UUID().uuidString).bin"
        let contents = Data((0..<(1 << 20)).map { UInt8($0 % 251) })
        addTeardownBlock {
            try? await smb.removeFile(atPath: path)
            try await smb.disconnectShare(gracefully: true)
        }

        try await smb.connectShare(name: share)
        try await smb.write(data: contents, toPath: path, progress: nil)

        let file = try await smb.openFile(atPath: path)
        let whole = try await file.read(range: 0..<UInt64(contents.count))
        XCTAssertEqual(whole, contents)
        try await file.close()
    }

    func testReadPastEndOfFileStops() async throws {
        let smb = try XCTUnwrap(SMB2Manager(url: server, credential: credential))
        let path = "handle-eof-\(UUID().uuidString).bin"
        let contents = Data(repeating: 3, count: 512)
        addTeardownBlock {
            try? await smb.removeFile(atPath: path)
            try await smb.disconnectShare(gracefully: true)
        }

        try await smb.connectShare(name: share)
        try await smb.write(data: contents, toPath: path, progress: nil)

        let file = try await smb.openFile(atPath: path)
        let overshoot = try await file.read(range: 0..<4096)
        XCTAssertEqual(overshoot.count, contents.count)
        try await file.close()
    }

    func testBlockingReadMatchesContents() async throws {
        let smb = try XCTUnwrap(SMB2Manager(url: server, credential: credential))
        let path = "handle-blocking-\(UUID().uuidString).bin"
        let contents = Data((0..<(1 << 20)).map { UInt8($0 % 251) })
        addTeardownBlock {
            try? await smb.removeFile(atPath: path)
            try await smb.disconnectShare(gracefully: true)
        }

        try await smb.connectShare(name: share)
        try await smb.write(data: contents, toPath: path, progress: nil)

        let file = try await smb.openFile(atPath: path)
        let whole = try await Self.blockingRead(file, range: 0..<UInt64(contents.count)).get()
        XCTAssertEqual(whole, contents)
        try await file.close()
    }

    func testCancelledBlockingReadLeavesTheHandleUsable() async throws {
        let smb = try XCTUnwrap(SMB2Manager(url: server, credential: credential))
        let path = "handle-cancel-\(UUID().uuidString).bin"
        let contents = Data((0..<(1 << 24)).map { UInt8($0 % 251) })
        addTeardownBlock {
            try? await smb.removeFile(atPath: path)
            try await smb.disconnectShare(gracefully: true)
        }

        try await smb.connectShare(name: share)
        try await smb.write(data: contents, toPath: path, progress: nil)

        let file = try await smb.openFile(atPath: path)
        let client = try XCTUnwrap(smb.client)
        let cancellation = SMB2Cancellation()
        let cancelled = await withCheckedContinuation { continuation in
            Thread {
                continuation.resume(returning: Result {
                    try file.read(range: 0..<UInt64(contents.count), cancellation: cancellation)
                })
            }.start()
            Self.cancel(once: client, isBusy: cancellation.cancel)
        }
        XCTAssertThrowsError(try cancelled.get()) { error in
            XCTAssertTrue(error is CancellationError)
        }

        let head = try await Self.blockingRead(file, range: 0..<(1 << 20)).get()
        XCTAssertEqual(head, contents.prefix(1 << 20))
        try await file.close()
    }

    func testCancelledTaskStopsAnAsyncRead() async throws {
        let smb = try XCTUnwrap(SMB2Manager(url: server, credential: credential))
        let path = "handle-task-\(UUID().uuidString).bin"
        let contents = Data((0..<(1 << 24)).map { UInt8($0 % 251) })
        addTeardownBlock {
            try? await smb.removeFile(atPath: path)
            try await smb.disconnectShare(gracefully: true)
        }

        try await smb.connectShare(name: share)
        try await smb.write(data: contents, toPath: path, progress: nil)

        let file = try await smb.openFile(atPath: path)
        let client = try XCTUnwrap(smb.client)
        let reading = Task {
            try await file.read(range: 0..<UInt64(contents.count))
        }
        Self.cancel(once: client, isBusy: reading.cancel)

        await XCTAssertThrowsErrorAsync(try await reading.value) { error in
            XCTAssertTrue(error is CancellationError)
        }

        let head = try await file.read(range: 0..<(1 << 20))
        XCTAssertEqual(head, contents.prefix(1 << 20))
        try await file.close()
    }

    private static func cancel(once client: SMB2Client, isBusy cancel: @escaping @Sendable () -> Void) {
        Thread {
            let deadline = Date().addingTimeInterval(5)
            while client.hasNoOutstandingCommands, Date() < deadline {
                usleep(50)
            }
            cancel()
        }.start()
    }

    private static func blockingRead(_ file: SMB2File, range: Range<UInt64>) async -> Result<Data, any Error> {
        await withCheckedContinuation { continuation in
            Thread {
                continuation.resume(returning: Result {
                    try file.read(range: range, cancellation: SMB2Cancellation())
                })
            }.start()
        }
    }
}

private func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    _ handler: (any Error) -> Void
) async {
    do {
        _ = try await expression()
        XCTFail("Expected an error")
    } catch {
        handler(error)
    }
}
