import unittest

from public_private_actions_discriminator import build_packet, validate_packet


class TestDiscriminator(unittest.TestCase):
    def test_packet(self):
        packet = build_packet()
        self.assertEqual(
            packet["results"]["FULL"]["diagnosis"],
            "PRIVATE_REPOSITORY_ACTIONS_EXECUTION_SURFACE_BLOCKER",
        )
        self.assertEqual(validate_packet(packet), [])

    def test_controls(self):
        packet = build_packet()
        self.assertTrue(all(packet["checks"].values()))

    def test_fail_closed(self):
        packet = build_packet()
        packet["claim_boundary"]["private_billing_verified"] = True
        problems = validate_packet(packet)
        self.assertIn("packet_hash_mismatch", problems)
        self.assertIn("claim_boundary:private_billing_verified", problems)


if __name__ == "__main__":
    unittest.main()
