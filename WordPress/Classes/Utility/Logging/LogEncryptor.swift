import Foundation
import Sodium

class LogEncryptor {

    private let chunkSize = 4096

    enum LogEncryptorError: Error {
        case unableToReadFile
        case unableToEncryptFile
        case logSecretTooLong
        case unableToWriteFile
    }

    func encryptFile(atPath inputURL: URL, toPath outputURL: URL) throws {

        /// Do the encrypted stream setup
        let sodium = Sodium()
        let secretkey = sodium.secretStream.xchacha20poly1305.key()
        let encryptedKey = try encryptSecretWithSodium(secret: secretkey)
        let stream_enc = sodium.secretStream.xchacha20poly1305.initPush(secretKey: secretkey)!
        let header = stream_enc.header()

        /// Prep our file handles
        try initializeOutputFile(at: outputURL)
        let inputFileHandle = try FileHandle(forReadingFrom: inputURL)
        let outputFileHandle = try FileHandle(forWritingTo: outputURL)

        defer {
            inputFileHandle.closeFile()
            outputFileHandle.closeFile()
        }

        /// Write JSON Preamble
        outputFileHandle.write("""
        {
            "keyedWith": "v1",
            "encryptedKey": "\(Data(bytes: encryptedKey).base64EncodedString())",
            "header": "\(Data(bytes: header).base64EncodedString())",
            "messages": [\n
        """.data(using: .utf8)!)

        /// Write the encrypted file in chunks as JSON
        var shouldContinue = true
        repeat {

            let data = inputFileHandle.readData(ofLength: chunkSize)    // read the data
            let message = stream_enc.push(message: data.bytes)          // encrypt the data
            try writeTo(outputFileHandle, message: message)             // write the data

            shouldContinue = data.count == chunkSize
        } while shouldContinue

        /// Write the end of the encryption stream
        let final = stream_enc.push(message: "".bytes, tag: .FINAL)
        try writeTo(outputFileHandle, message: final, willHaveMore: false)

        /// Write out the end of the JSON file
        outputFileHandle.write("""
            ]
        }
        """.data(using: .utf8)!)
    }

    internal func encryptSecretWithSodium(secret: Bytes) throws -> Bytes {
        let key = Bundle.main.url(forResource: "log-encryption-key", withExtension: "pub")!
        let decodedKey = Data(base64Encoded: try Data(contentsOf: key))!.bytes
        return Sodium().box.seal(message: secret, recipientPublicKey: decodedKey)!
    }

    private func initializeOutputFile(at outputURL: URL) throws {

        if FileManager.default.fileExists(atPath: outputURL.path) {
            try FileManager.default.removeItem(at: outputURL)
        }

        guard FileManager.default.createFile(atPath: outputURL.path, contents: nil, attributes: nil) else {
            throw LogEncryptorError.unableToWriteFile
        }
    }

    private func writeTo(_ fileHandle: FileHandle, message: Bytes?, willHaveMore: Bool = true) throws {

        guard let fragment = message else {
            throw LogEncryptorError.unableToEncryptFile
        }

        fileHandle.write("        \"".data(using: .utf8)!)
        fileHandle.write(Data(bytes: fragment).base64EncodedData())

        /// There should be a comma if there will be another line after this one
        let closingQuote = willHaveMore ? "\",\n" : "\"\n"
        fileHandle.write(closingQuote.data(using: .utf8)!)
    }
}

fileprivate extension Data {
    var bytes: Bytes {
        return [UInt8](self)
    }
}
