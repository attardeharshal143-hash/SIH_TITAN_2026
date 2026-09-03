import sys
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from analyzer.run_pipeline import run_complete_pipeline
from analyzer.generate_pdf_report import create_pdf_report

class TestTitanProductionSuite(unittest.TestCase):
    def test_01_synthetic_trace_accounting(self):
        pcap_path = BASE_DIR / 'dataset' / 'test_exact_336_trace.pcap'
        if not pcap_path.exists():
            self.skipTest('test_exact_336_trace.pcap not found')
        
        ok, rep, _, err = run_complete_pipeline(pcap_path)
        self.assertTrue(ok, f'Pipeline failed: {err}')
        
        summary = rep['traffic_summary']
        self.assertEqual(summary['packets_analyzed'], 328)
        self.assertEqual(summary['esp_packets'], 320)
        self.assertEqual(len(rep['security_associations']), 4)
        self.assertEqual(rep['anti_replay_audit']['duplicate_sequences'], 0)

    def test_02_multi_spi_downgrade_banner(self):
        pcap_path = BASE_DIR / 'dataset' / 'test_multi_weak_distinct_eta.pcap'
        if not pcap_path.exists():
            self.skipTest('test_multi_weak_distinct_eta.pcap not found')
        
        ok, rep, _, err = run_complete_pipeline(pcap_path)
        self.assertTrue(ok, f'Pipeline failed: {err}')
        
        comp_status = rep['executive_summary']['compliance_status']
        self.assertIn('0x2b2b0002', comp_status)
        self.assertIn('0x4d4d0004', comp_status)
        self.assertEqual(len(rep['security_associations']), 4)

    def test_03_tesssst_golden_pcap(self):
        tesssst_path = Path(r'C:\Users\attar\Downloads\tesssst.pcap')
        if not tesssst_path.exists():
            tesssst_path = BASE_DIR / 'dataset' / 'tesssst.pcap'
        if not tesssst_path.exists():
            self.skipTest('tesssst.pcap not found in Downloads or dataset')

        ok, rep, _, err = run_complete_pipeline(tesssst_path)
        self.assertTrue(ok, f'Pipeline failed: {err}')

        summary = rep['traffic_summary']
        self.assertEqual(summary['packets_analyzed'], 336)
        self.assertEqual(summary['esp_packets'], 320)
        self.assertEqual(summary['ike_candidates'], 16)
        self.assertEqual(summary['ah_packets'], 0)
        self.assertEqual(summary['tcp_packets'], 0)
        self.assertEqual(summary['icmp_packets'], 0)
        self.assertEqual(summary['dns_packets'], 0)
        
        # 0 false replays
        self.assertEqual(rep['anti_replay_audit']['duplicate_sequences'], 0)

        # Multi-SPI banner
        comp = rep['executive_summary']['compliance_status']
        self.assertIn('0x2b2b0002', comp)
        self.assertIn('0x4d4d0004', comp)

        # PDF creation test
        pdf_path = BASE_DIR / 'reports' / 'tmp_test_audit.pdf'
        try:
            create_pdf_report(rep, pdf_path)
            self.assertTrue(pdf_path.exists())
            self.assertGreater(pdf_path.stat().st_size, 1000)
        finally:
            if pdf_path.exists():
                pdf_path.unlink()

if __name__ == '__main__':
    unittest.main(verbosity=2)
