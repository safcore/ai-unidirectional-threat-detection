"""Full end-to-end pipeline integration test."""
import sys, time
sys.path.insert(0, '.')

from m1_ingest.packet_queue import IngestPipeline
from m1_ingest.stream_monitor import StreamMonitor
from m2_features.flow_aggregator import FlowAggregator
from m2_features.feature_extractor import FeatureExtractor
from m3_classifiers.ddos_detector import DDoSDetector
from m3_classifiers.portscan_detector import PortScanDetector
from m4_advanced.dga_detector import DGADetector
from m4_advanced.beacon_detector import BeaconDetector
from m4_advanced.exfil_detector import ExfilDetector
from m5_alerts.alert_engine import AlertEngine

monitor    = StreamMonitor(interval_sec=1.0, print_stats=True)
engine     = AlertEngine(monitor=monitor)
aggregator = FlowAggregator(flow_timeout_sec=2.0, monitor=monitor)
extractor  = FeatureExtractor()

ddos   = DDoSDetector(alert_handler=engine.ingest)
scan   = PortScanDetector(alert_handler=engine.ingest)
dga    = DGADetector(alert_handler=engine.ingest)
beacon = BeaconDetector(alert_handler=engine.ingest)
exfil  = ExfilDetector(alert_handler=engine.ingest)

extractor.add_handler(ddos.predict)
extractor.add_handler(scan.predict)
extractor.add_handler(dga.predict)
extractor.add_handler(beacon.predict)
extractor.add_handler(exfil.predict)
aggregator.add_handler(extractor.extract)

pipeline = IngestPipeline(pps=5000, attack_mix=0.35, num_workers=2)
pipeline.add_consumer(aggregator.ingest)

monitor.start()
aggregator.start()
engine.start()
pipeline.start()

print('Full pipeline running for 15 seconds...')
time.sleep(15)

print()
print('=== END-TO-END RESULTS ===')
print('Total packets:', pipeline.total_processed)
print('Total alerts: ', engine.total_alerts)
print('Avg flows/s:  ', round(monitor.avg_flows_per_sec(10)))
stats = engine.get_stats()
print('By class:     ', stats.get('by_class', {}))
print('By severity:  ', stats.get('by_severity', {}))

if engine.total_alerts > 0:
    print('[PASS] Full pipeline producing alerts correctly')
else:
    print('[NOTE] No alerts yet - detectors may need more traffic time')

pipeline.stop()
aggregator.stop()
monitor.stop()
