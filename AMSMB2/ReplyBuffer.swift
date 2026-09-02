import Foundation

final class ReplyBuffer {
    let bytes: UnsafeMutablePointer<UInt8>
    let count: Int

    private var allocatedCount: Int {
        Swift.max(count, 1)
    }

    init(count: Int) {
        self.count = Swift.max(count, 0)
        bytes = .allocate(capacity: Swift.max(self.count, 1))
        bytes.initialize(repeating: 0, count: Swift.max(self.count, 1))
    }

    init(_ data: some DataProtocol) {
        let capacity = Swift.max(data.count, 1)
        count = data.count
        bytes = .allocate(capacity: capacity)
        bytes.initialize(repeating: 0, count: capacity)
        var index = 0
        for byte in data {
            bytes[index] = byte
            index += 1
        }
    }

    deinit {
        bytes.deinitialize(count: allocatedCount)
        bytes.deallocate()
    }

    func data(count: Int) -> Data {
        Data(bytes: bytes, count: Swift.min(Swift.max(count, 0), self.count))
    }
}
