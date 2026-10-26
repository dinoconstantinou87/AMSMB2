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
}
