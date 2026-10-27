import Foundation
import Synchronization

public final class SMB2Cancellation: Sendable {
    private struct State {
        var commands: [SMB2Client.CBData] = []
        var cancellations = 0
    }

    private let state = Mutex(State())

    public init() {}

    public func cancel() {
        state.withLock { state in
            state.cancellations += 1
            for command in state.commands {
                command.finish(failure: CancellationError())
            }
        }
    }

    var mark: Int {
        state.withLock { $0.cancellations }
    }

    func begin(_ command: SMB2Client.CBData, since mark: Int) -> Bool {
        state.withLock { state in
            guard state.cancellations == mark else { return false }
            state.commands.append(command)
            return true
        }
    }

    func end(_ command: SMB2Client.CBData) {
        state.withLock { state in
            state.commands.removeAll { $0 === command }
        }
    }
}
