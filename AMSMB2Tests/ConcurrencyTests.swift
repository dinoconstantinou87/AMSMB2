import XCTest
@testable import AMSMB2

final class ConcurrencyTests: XCTestCase {
    private lazy var server: URL = .init(string: ProcessInfo.processInfo.environment["SMB_SERVER"]!)!
    private lazy var share: String = ProcessInfo.processInfo.environment["SMB_SHARE"]!
    private lazy var credential: URLCredential? = {
        guard let user = ProcessInfo.processInfo.environment["SMB_USER"],
              let password = ProcessInfo.processInfo.environment["SMB_PASSWORD"]
        else { return nil }
        return URLCredential(user: user, password: password, persistence: .forSession)
    }()

    func testConcurrentReadsShareOneConnection() async throws {
        let smb = try XCTUnwrap(SMB2Manager(url: server, credential: credential))
        let path = "concurrency-\(UUID().uuidString).bin"
        let size = 1 << 20
        addTeardownBlock {
            try? await smb.removeFile(atPath: path)
            try await smb.disconnectShare(gracefully: true)
        }

        try await smb.connectShare(name: share)
        try await smb.write(data: Data(repeating: 0xAB, count: size), toPath: path, progress: nil)

        let client = try XCTUnwrap(smb.client)
        let readCount = 8
        let chunk = size / readCount
        try await withThrowingTaskGroup(of: Int.self) { group in
            for index in 0..<readCount {
                let range = UInt64(index * chunk)..<UInt64((index + 1) * chunk)
                group.addTask {
                    try await smb.contents(atPath: path, range: range).count
                }
            }
            for try await count in group {
                XCTAssertEqual(count, chunk)
            }
        }

        XCTAssertGreaterThan(client.peakCommandsInFlight, 1)
    }

    func testConnectionDrainsAfterConcurrentWork() async throws {
        let smb = try XCTUnwrap(SMB2Manager(url: server, credential: credential))
        let path = "drain-\(UUID().uuidString).bin"
        addTeardownBlock {
            try? await smb.removeFile(atPath: path)
            try await smb.disconnectShare(gracefully: true)
        }

        try await smb.connectShare(name: share)
        try await smb.write(data: Data(repeating: 1, count: 1 << 16), toPath: path, progress: nil)

        try await withThrowingTaskGroup(of: Void.self) { group in
            for _ in 0..<8 {
                group.addTask { _ = try await smb.contents(atPath: path) }
            }
            try await group.waitForAll()
        }

        let client = try XCTUnwrap(smb.client)
        try await Task.sleep(nanoseconds: 300_000_000)
        XCTAssertTrue(client.hasNoOutstandingCommands)
        XCTAssertFalse(client.isServicing)
    }
}
