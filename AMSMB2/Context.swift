//
//  Context.swift
//  AMSMB2
//
//  Created by Amir Abbas on 5/20/18.
//  Copyright © 2018 Mousavian. Distributed under MIT license.
//  All rights reserved.
//

import Foundation
import SMB2
#if canImport(System)
import System
#else
import SystemPackage
#endif

extension FileDescriptor {
    static var invalid: FileDescriptor { .init(rawValue: -1) }
    var isValidSocket: Bool { rawValue > 0 }
}

/// Provides synchronous operation on SMB2
final class SMB2Client: CustomDebugStringConvertible, CustomReflectable, @unchecked Sendable {
    var context: UnsafeMutablePointer<smb2_context>?
    let _context_lock = NSRecursiveLock()

    var pendingCommands: [CBData] = []

    var isServicing = false

    private(set) var peakCommandsInFlight = 0
    
    init() throws {
        self.context = try smb2_init_context().unwrap()
    }

    deinit {
        guard context != nil else { return }
        try? withThreadSafeContext { context in
            self.context = nil
            smb2_destroy_context(context)
        }
    }

    func withThreadSafeContext<R>(_ handler: (UnsafeMutablePointer<smb2_context>) throws -> R)
        throws -> R
    {
        _context_lock.lock()
        defer {
            _context_lock.unlock()
        }
        return try handler(context.unwrap())
    }

    public var debugDescription: String {
        String(reflecting: self)
    }

    public var customMirror: Mirror {
        var c: [(label: String?, value: Any)] = []
        if context != nil {
            c.append((label: "server", value: server!))
            c.append((label: "securityMode", value: securityMode))
            c.append((label: "authentication", value: authentication))
            clientGuid.map { c.append((label: "clientGuid", value: $0)) }
            c.append((label: "user", value: user))
            c.append((label: "version", value: version))
        }
        c.append((label: "isConnected", value: isActive))
        c.append((label: "timeout", value: timeout))

        let m = Mirror(self, children: c, displayStyle: .class)
        return m
    }
}

// MARK: Setting manipulation

extension SMB2Client {
    var opaque: UnsafeMutableRawPointer? {
        get {
            try? smb2_get_opaque(context.unwrap())
        }
        set {
            try? withThreadSafeContext { context in
                smb2_set_opaque(context, newValue)
            }
        }
    }
    
    var isActive: Bool {
        (try? smb2_context_active(context.unwrap())) == 1 && fileDescriptor.isValidSocket
    }
    
    var timeout: TimeInterval {
        get {
            TimeInterval(context?.pointee.timeout ?? 0)
        }
        set {
            try? withThreadSafeContext { context in
                smb2_set_timeout(context, Int32(newValue))
            }
        }
    }
    
    var workstation: String {
        get {
            smb2_get_workstation(context).map(String.init(cString:)) ?? ""
        }
        set {
            try? withThreadSafeContext { context in
                smb2_set_workstation(context, newValue)
            }
        }
    }
    
    var domain: String {
        get {
            smb2_get_domain(context).map(String.init(cString:)) ?? ""
        }
        set {
            try? withThreadSafeContext { context in
                smb2_set_domain(context, newValue)
            }
        }
    }
    
    var user: String {
        get {
            smb2_get_user(context).map(String.init(cString:)) ?? ""
        }
        set {
            try? withThreadSafeContext { context in
                smb2_set_user(context, newValue)
            }
        }
    }
    
    var password: String {
        get {
            (context?.pointee.password).map(String.init(cString:)) ?? ""
        }
        set {
            try? withThreadSafeContext { context in
                smb2_set_password(context, newValue != "" ? newValue : nil)
            }
        }
    }

    var securityMode: NegotiateSigning {
        get {
            (context?.pointee.security_mode).flatMap(NegotiateSigning.init(rawValue:)) ?? []
        }
        set {
            try? withThreadSafeContext { context in
                smb2_set_security_mode(context, newValue.rawValue)
            }
        }
    }

    var seal: Bool {
        get {
            context?.pointee.seal ?? 0 != 0
        }
        set {
            try? withThreadSafeContext { context in
                smb2_set_seal(context, newValue ? 1 : 0)
            }
        }
    }

    var authentication: Security {
        get {
            context?.pointee.sec ?? .undefined
        }
        set {
            try? withThreadSafeContext { context in
                smb2_set_authentication(context, .init(bitPattern: newValue.rawValue))
            }
        }
    }

    var clientGuid: UUID? {
        guard let guid = try? smb2_get_client_guid(context.unwrap()) else {
            return nil
        }
        let uuid = UnsafeRawPointer(guid).assumingMemoryBound(to: uuid_t.self).pointee
        return UUID(uuid: uuid)
    }

    var server: String? {
        context?.pointee.server.map(String.init(cString:))
    }

    var share: String? {
        context?.pointee.share.map(String.init(cString:))
    }

    var version: Version {
        (try? smb2_get_dialect(context.unwrap())).map { Version(rawValue: UInt32($0)) } ?? .any
    }
    
    var passthrough: Bool {
        get {
            var result: CInt = 0
            smb2_get_passthrough(context, &result)
            return result != 0
        }
        set {
            smb2_set_passthrough(context, newValue ? 1 : 0)
        }
    }
    
    var fileDescriptor: FileDescriptor {
        do {
            return try .init(rawValue: smb2_get_fd(context.unwrap()))
        } catch {
            return .invalid
        }
    }

    var errorString: String? {
        smb2_get_error(context).map(String.init(cString:))
    }
    
    var ntError: NTStatus {
        .init(rawValue: smb2_get_nterror(context))
    }
    
    var errno: Errno {
        ntError.errno
    }
    
    var maximumTransactionSize: Int {
        (context?.pointee.max_transact_size).map(Int.init) ?? 65535
    }

    func whichEvents() throws -> Int16 {
        try Int16(truncatingIfNeeded: smb2_which_events(context.unwrap()))
    }

    func service(revents: Int32) throws {
        let result = smb2_service(context, revents)
        if result < 0 {
            smb2_destroy_context(context)
            context = nil
            try POSIXError.throwIfError(result, description: errorString)
        }
    }
}

// MARK: Connectivity

extension SMB2Client {
    func connect(server: String, share: String, user: String) async throws {
        try await async_await { context, cbPtr -> Int32 in
            smb2_connect_share_async(
                context, server, share, user, SMB2Client.generic_handler, cbPtr
            )
        }
    }

    func disconnect() async throws {
        _ = try? await async_await { context, cbPtr -> Int32 in
            smb2_disconnect_share_async(context, SMB2Client.generic_handler, cbPtr)
        }
    }

    func close(_ handle: OpaquePointer) async throws {
        try await async_await { context, cbPtr -> Int32 in
            smb2_close_async(context, handle, SMB2Client.generic_handler, cbPtr)
        }
    }

    func echo() async throws {
        if !isActive {
            throw POSIXError(.socketNotConnected, description: nil)
        }
        try await async_await { context, cbPtr -> Int32 in
            smb2_echo_async(context, SMB2Client.generic_handler, cbPtr)
        }
    }
}

// MARK: DCE-RPC

extension SMB2Client {
    func shareEnum() async throws -> [SMB2Share] {
        try await async_await(dataHandler: [SMB2Share].init) { context, cbPtr -> Int32 in
            smb2_share_enum_async(context, SHARE_INFO_1, SMB2Client.generic_handler, cbPtr)
        }.data
    }

    func shareEnumSwift() async throws -> [SMB2Share] {
        // Connection to server service.
        let srvsvc = try await SMB2FileHandle(path: "srvsvc", desiredAccess: [.read, .write], createDisposition: .open, on: self)
        // Bind command
        _ = try await srvsvc.write(data: MSRPC.SrvsvcBindData())
        let recvBindData = try await srvsvc.read(toAbsoluteOffset: 0, length: Int(Int16.max))
        try MSRPC.validateBindData(recvBindData)

        // NetShareEnum request, Level 1 mean we need share name and remark.
        _ = try await srvsvc.write(toAbsoluteOffset: 0, data: MSRPC.NetShareEnumAllRequest(serverName: server!))
        let recvData = try await srvsvc.read(toAbsoluteOffset: 0)
        return try MSRPC.NetShareEnumAllLevel1(data: recvData).shares
    }
}

// MARK: File information

extension SMB2Client {
    func stat(_ path: String) async throws -> smb2_stat_64 {
        let st = UnsafeMutablePointer<smb2_stat_64>.allocate(capacity: 1)
        st.initialize(to: smb2_stat_64())
        defer {
            st.deinitialize(count: 1)
            st.deallocate()
        }
        try await async_await { context, cbPtr -> Int32 in
            smb2_stat_async(context, path.trimmedPath, st, SMB2Client.generic_handler, cbPtr)
        }
        return st.pointee
    }

    func statvfs(_ path: String) async throws -> smb2_statvfs {
        let st = UnsafeMutablePointer<smb2_statvfs>.allocate(capacity: 1)
        st.initialize(to: smb2_statvfs())
        defer {
            st.deinitialize(count: 1)
            st.deallocate()
        }
        try await async_await { context, cbPtr -> Int32 in
            smb2_statvfs_async(context, path.trimmedPath, st, SMB2Client.generic_handler, cbPtr)
        }
        return st.pointee
    }

    func readlink(_ path: String) async throws -> String {
        try await async_await(dataHandler: String.init) { context, cbPtr -> Int32 in
            smb2_readlink_async(context, path.trimmedPath, SMB2Client.generic_handler, cbPtr)
        }.data
    }
    
    func symlink(_ path: String, to destination: String) async throws {
        let file = try await SMB2FileHandle(path: path, .readWrite, options: [.create, .exclusiveLock, .symlink, .sync], on: self)
        let reparse = IOCtl.SymbolicLinkReparse(path: destination, isRelative: true)
        try await file.fcntl(command: .setReparsePoint, args: reparse)
    }
}

// MARK: File operation

extension SMB2Client {
    func mkdir(_ path: String) async throws {
        try await async_await { context, cbPtr -> Int32 in
            smb2_mkdir_async(context, path.trimmedPath, SMB2Client.generic_handler, cbPtr)
        }
    }

    func rmdir(_ path: String) async throws {
        try await async_await { context, cbPtr -> Int32 in
            smb2_rmdir_async(context, path.trimmedPath, SMB2Client.generic_handler, cbPtr)
        }
    }
    
    func unlink(_ path: String, type: smb2_stat_64.ResourceType = .file) async throws {
        switch type {
        case .directory:
            throw POSIXError(.invalidArgument, description: "Use rmdir() to delete a directory.")
        case .file:
            try await async_await { context, cbPtr -> Int32 in
                smb2_unlink_async(context, path.trimmedPath, SMB2Client.generic_handler, cbPtr)
            }
        case .link:
            let file = try await SMB2FileHandle(path: path, .readWrite, options: [.symlink], on: self)
            try await file.setInfo(smb2_file_disposition_info(delete_pending: 1), infoClass: .disposition)
        default:
            preconditionFailure("Not supported file type.")
        }
    }

    func rename(_ path: String, to newPath: String) async throws {
        try await async_await { context, cbPtr -> Int32 in
            smb2_rename_async(
                context, path.trimmedPath, newPath.trimmedPath, SMB2Client.generic_handler, cbPtr
            )
        }
    }

    func resize(_ path: String, to newSize: UInt64) async throws {
        try await async_await { context, cbPtr -> Int32 in
            smb2_truncate_async(
                context, path.trimmedPath, newSize, SMB2Client.generic_handler, cbPtr
            )
        }
    }
}

// MARK: Async operation handler

extension SMB2Client {
    final class ResultBox<Value>: @unchecked Sendable {
        var value: Value?
        var error: (any Error)?
    }

    final class CBData: @unchecked Sendable {
        private let lock = NSLock()
        private var continuation: CheckedContinuation<Void, Never>?
        private var finished = false

        var result: Int32 = .init(NTStatus.success.rawValue)
        var failure: (any Error)?
        var dataHandler: ((UnsafeMutableRawPointer?) -> Void)?

        private let deadline: Date?

        var status: NTStatus {
            NTStatus(rawValue: result)
        }

        var hasExpired: Bool {
            guard let deadline else { return false }
            return Date() >= deadline
        }

        init(timeout: TimeInterval) {
            deadline = timeout > 0 ? Date().addingTimeInterval(timeout) : nil
        }

        func wait() async {
            await withCheckedContinuation { continuation in
                lock.lock()
                if finished {
                    lock.unlock()
                    continuation.resume()
                } else {
                    self.continuation = continuation
                    lock.unlock()
                }
            }
        }

        func finish(failure: (any Error)? = nil) {
            lock.lock()
            guard !finished else {
                lock.unlock()
                return
            }
            finished = true
            if let failure, self.failure == nil {
                self.failure = failure
            }
            let continuation = self.continuation
            self.continuation = nil
            lock.unlock()
            continuation?.resume()
        }
    }

    static let generic_handler: smb2_command_cb = { _, status, command_data, cbdata in
        guard let cbdata else { return }
        let cb = Unmanaged<CBData>.fromOpaque(cbdata).takeRetainedValue()
        if NTStatus(rawValue: status) != .success {
            cb.result = status
        }
        cb.dataHandler?(command_data)
        cb.finish()
    }

    typealias ContextHandler<R> = (_ client: SMB2Client, _ dataPtr: UnsafeMutableRawPointer?)
        throws -> R
    typealias UnsafeContextHandler<R> = (
        _ context: UnsafeMutablePointer<smb2_context>, _ dataPtr: UnsafeMutableRawPointer?
    ) throws -> R

    @discardableResult
    func async_await(execute handler: UnsafeContextHandler<Int32>) async throws -> Int32 {
        try await async_await(dataHandler: { _, _ in }, execute: handler).result
    }

    @discardableResult
    func async_await<DataType>(
        dataHandler: @escaping ContextHandler<DataType>,
        execute handler: UnsafeContextHandler<Int32>
    )
        async throws -> (result: Int32, data: DataType)
    {
        let box = ResultBox<DataType>()
        let cb = makeCallbackData(dataHandler: dataHandler, into: box)
        try submit(cb) { context, cbPtr in
            let result = try handler(context, cbPtr)
            try POSIXError.throwIfError(result, description: errorString)
        }
        try await settle(cb)
        try POSIXError.throwIfError(cb.result, description: errorString)
        if let error = box.error { throw error }
        return try (cb.result, box.value.unwrap())
    }

    @discardableResult
    func async_await_pdu(execute handler: UnsafeContextHandler<UnsafeMutablePointer<smb2_pdu>?>)
        async throws -> UInt32
    {
        try await async_await_pdu(dataHandler: { _, _ in }, execute: handler).status
    }

    @discardableResult
    func async_await_pdu<DataType>(
        dataHandler: @escaping ContextHandler<DataType>,
        execute handler: UnsafeContextHandler<UnsafeMutablePointer<smb2_pdu>?>
    )
        async throws -> (status: UInt32, data: DataType)
    {
        let box = ResultBox<DataType>()
        let cb = makeCallbackData(dataHandler: dataHandler, into: box)
        try submit(cb) { context, cbPtr in
            let pdu = try handler(context, cbPtr).unwrap()
            smb2_queue_pdu(context, pdu)
        }
        try await settle(cb)
        try cb.status.throwIfError()
        if let error = box.error { throw error }
        return try (UInt32(bitPattern: cb.result), box.value.unwrap())
    }

    private func makeCallbackData<DataType>(
        dataHandler: @escaping ContextHandler<DataType>,
        into box: ResultBox<DataType>
    )
        -> CBData
    {
        let cb = CBData(timeout: timeout)
        cb.dataHandler = { [unowned self] pointer in
            do {
                box.value = try dataHandler(self, pointer)
            } catch {
                box.error = error
            }
        }
        return cb
    }

    private func submit(
        _ cb: CBData,
        _ send: (UnsafeMutablePointer<smb2_context>, UnsafeMutableRawPointer) throws -> Void
    ) throws {
        let cbPtr = Unmanaged.passRetained(cb).toOpaque()
        do {
            try withThreadSafeContext { context in
                try send(context, cbPtr)
                pendingCommands.append(cb)
                peakCommandsInFlight = Swift.max(peakCommandsInFlight, pendingCommands.count)
            }
        } catch {
            Unmanaged<CBData>.fromOpaque(cbPtr).release()
            throw error
        }
        startServicing()
    }

    private func settle(_ cb: CBData) async throws {
        await cb.wait()
        forgetPendingCommand(cb)
        if let failure = cb.failure { throw failure }
    }

    private func forgetPendingCommand(_ cb: CBData) {
        _context_lock.lock()
        pendingCommands.removeAll { $0 === cb }
        _context_lock.unlock()
    }

    private func startServicing() {
        _context_lock.lock()
        let shouldStart = !isServicing && context != nil
        if shouldStart {
            isServicing = true
        }
        _context_lock.unlock()
        guard shouldStart else { return }

        let thread = Thread { [weak self] in
            while let self, self.serviceOnce() { }
        }
        thread.name = "AMSMB2.service"
        thread.qualityOfService = .userInitiated
        thread.start()
    }

    private func serviceOnce() -> Bool {
        var pollDescriptor = pollfd()
        _context_lock.lock()
        guard let context, !pendingCommands.isEmpty else {
            isServicing = false
            _context_lock.unlock()
            return false
        }
        pollDescriptor.fd = smb2_get_fd(context)
        pollDescriptor.events = Int16(truncatingIfNeeded: smb2_which_events(context))
        _context_lock.unlock()

        guard pollDescriptor.fd > 0 else {
            failPendingCommands(with: POSIXError(.socketNotConnected, description: nil))
            return true
        }

        let ready = poll(&pollDescriptor, 1, 100)

        _context_lock.lock()
        if ready > 0, pollDescriptor.revents != 0, self.context != nil {
            let result = smb2_service(self.context, Int32(pollDescriptor.revents))
            if result < 0 {
                smb2_destroy_context(self.context)
                self.context = nil
            }
        }
        let expired = pendingCommands.filter(\.hasExpired)
        pendingCommands.removeAll(where: \.hasExpired)
        _context_lock.unlock()

        for cb in expired {
            cb.finish(failure: POSIXError(.timedOut, description: nil))
        }
        return true
    }

    var hasNoOutstandingCommands: Bool {
        _context_lock.lock()
        defer { _context_lock.unlock() }
        return pendingCommands.isEmpty
    }

    private func failPendingCommands(with error: any Error) {
        _context_lock.lock()
        let pending = pendingCommands
        pendingCommands.removeAll()
        _context_lock.unlock()
        for cb in pending {
            cb.finish(failure: error)
        }
    }
}

extension SMB2Client {
    struct NegotiateSigning: OptionSet, Sendable, CustomStringConvertible {
        var rawValue: UInt16
        
        var description: String {
            var result: [String] = []
            if contains(.enabled) { result.append("Enabled") }
            if contains(.required) { result.append("Required") }
            return result.joined(separator: ", ")
        }
        
        static let enabled = NegotiateSigning(rawValue: SMB2_NEGOTIATE_SIGNING_ENABLED)
        static let required = NegotiateSigning(rawValue: SMB2_NEGOTIATE_SIGNING_REQUIRED)
    }

    typealias Version = smb2_negotiate_version
    typealias Security = smb2_sec
}

extension SMB2.smb2_negotiate_version: Swift.Hashable, Swift.CustomStringConvertible {
    static let any = SMB2_VERSION_ANY
    static let v2 = SMB2_VERSION_ANY2
    static let v3 = SMB2_VERSION_ANY3
    static let v2_02 = SMB2_VERSION_0202
    static let v2_10 = SMB2_VERSION_0210
    static let v3_00 = SMB2_VERSION_0300
    static let v3_02 = SMB2_VERSION_0302
    static let v3_11 = SMB2_VERSION_0311
    
    public var description: String {
        switch self {
        case .any: return "Any"
        case .v2: return "2.0"
        case .v3: return "3.0"
        case .v2_02: return "2.02"
        case .v2_10: return "2.10"
        case .v3_00: return "3.00"
        case .v3_02: return "3.02"
        case .v3_11: return "3.11"
        default: return "Unknown"
        }
    }

    static func ==(lhs: smb2_negotiate_version, rhs: smb2_negotiate_version) -> Bool {
        lhs.rawValue == rhs.rawValue
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(rawValue)
    }
}

extension SMB2.smb2_sec: Swift.Hashable, Swift.CustomStringConvertible {
    static let undefined = SMB2_SEC_UNDEFINED
    static let ntlmSsp = SMB2_SEC_NTLMSSP
    static let kerberos5 = SMB2_SEC_KRB5
    
    public var description: String {
        switch self {
        case .undefined: return "Undefined"
        case .ntlmSsp: return "NTLM SSP"
        case .kerberos5: return "Kerberos5"
        default: return "Unknown"
        }
    }

    static func ==(lhs: smb2_sec, rhs: smb2_sec) -> Bool {
        lhs.rawValue == rhs.rawValue
    }
}

struct SMB2Share {
    let name: String
    let props: ShareProperties
    let comment: String
}

struct ShareProperties: RawRepresentable {
    enum ShareType: UInt32 {
        case diskTree
        case printQueue
        case device
        case ipc
    }

    let rawValue: UInt32

    var type: ShareType {
        ShareType(rawValue: rawValue & 0x0fff_ffff)!
    }

    var isTemporary: Bool {
        rawValue & UInt32(bitPattern: SHARE_TYPE_TEMPORARY) != 0
    }

    var isHidden: Bool {
        rawValue & SHARE_TYPE_HIDDEN != 0
    }
}

struct NTStatus: LocalizedError, Hashable, CustomStringConvertible, Sendable {
    enum Severity: UInt32, Hashable, CustomStringConvertible, Sendable {
        case success
        case info
        case warning
        case error
        
        var description: String {
            switch self {
            case .success: return "Success"
            case .info: return "Info"
            case .warning: return "Warning"
            case .error: return "Error"
            }
        }
        
        init(status: NTStatus) {
            self = switch status.rawValue & SMB2_STATUS_SEVERITY_MASK {
            case UInt32(bitPattern: SMB2_STATUS_SEVERITY_SUCCESS):
                .success
            case UInt32(bitPattern: SMB2_STATUS_SEVERITY_INFO):
                .info
            case SMB2_STATUS_SEVERITY_WARNING:
                .warning
            case SMB2_STATUS_SEVERITY_ERROR:
                .error
            default:
                .success
            }
        }
    }
    
    let rawValue: UInt32
    
    init(rawValue: UInt32) {
        self.rawValue = rawValue
    }
    
    init(rawValue: Int32) {
        self.rawValue = .init(bitPattern: rawValue)
    }
    
    var description: String {
        "Error 0x\(String(rawValue, radix: 16, uppercase: true)): \(localizedDescription)"
    }
    
    var errorDescription: String? {
        nterror_to_str(rawValue).map(String.init(cString:))
    }
    
    var errno: Errno {
        .init(rawValue: nterror_to_errno(rawValue))
    }
    
    var severity: Severity {
        .init(status: self)
    }
    
    func throwIfError() throws {
        if severity == .error {
            throw POSIXError(errno,description: description)
        }
    }
    
    static let success = Self(rawValue: SMB2_STATUS_SUCCESS)
}
