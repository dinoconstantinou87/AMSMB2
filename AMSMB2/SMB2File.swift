import Foundation

public final class SMB2File: Sendable {
    private let handle: SMB2FileHandle

    init(handle: SMB2FileHandle) {
        self.handle = handle
    }

    public var size: UInt64 {
        get async throws {
            try await handle.fstat().smb2_size
        }
    }

    public var optimalReadSize: Int {
        handle.optimizedReadSize
    }

    public func read(range: Range<UInt64>) async throws -> Data {
        guard !range.isEmpty else { return Data() }
        let length = Int(range.upperBound - range.lowerBound)
        var contents = Data()
        contents.reserveCapacity(length)
        var offset = range.lowerBound
        while contents.count < length {
            let remaining = length - contents.count
            let chunk = optimalReadSize > 0 ? Swift.min(remaining, optimalReadSize) : remaining
            let data = try await handle.read(toAbsoluteOffset: offset, length: chunk)
            if data.isEmpty { break }
            contents.append(data)
            offset += UInt64(data.count)
        }
        return contents
    }

    public func close() async throws {
        try await handle.closeAsync()
    }
}

extension SMB2Manager {
    public func openFile(atPath path: String) async throws -> SMB2File {
        let client = try client.unwrap()
        return try await SMB2File(handle: SMB2FileHandle(forReadingAtPath: path, on: client))
    }
}
