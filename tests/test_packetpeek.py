import unittest
from packetpeek import parse_frame


class PacketPeekTests(unittest.TestCase):
    def test_short_frame_is_reported(self):
        packet = parse_frame(1, 0, b"short")
        self.assertEqual(packet.info, "truncated Ethernet header")

    def test_unknown_ethertype_is_preserved(self):
        frame = b"\x00" * 12 + b"\x12\x34" + b"payload"
        packet = parse_frame(1, 1, frame)
        self.assertEqual(packet.protocol, "ETH-1234")


if __name__ == "__main__":
    unittest.main()
