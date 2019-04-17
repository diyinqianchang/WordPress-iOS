import XCTest
@testable import WordPress

class LogEncryptionTests: XCTestCase {

    private let testLogDataFileName = "test-log-data.txt"

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testThatEncryptingFilesProducesExpectedResults() {

        guard let mediaPath = OHPathForFile(testLogDataFileName, type(of: self)) else {
            XCTFail("Error: failed creating a path to the test image file")
            return
        }

        let outputURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!.appendingPathComponent("output-test.json")

        try! LogEncryptor().encryptFile(atPath: URL(fileURLWithPath: mediaPath), toPath: outputURL)
    }

    func testLightEncryptionPerformance() {

        guard let mediaPath = OHPathForFile(testLogDataFileName, type(of: self)) else {
            XCTFail("Error: failed creating a path to the test image file")
            return
        }

        let outputURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)
            .first!
            .appendingPathComponent("output-test-small.json")

        measure {
            try! LogEncryptor().encryptFile(atPath: URL(fileURLWithPath: mediaPath), toPath: outputURL)
        }
    }
}
