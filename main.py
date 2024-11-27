from config.config_loader import load_config
from core.logger import setup_logging
from core.nuclei_manager import NucleiManager
from core.report_generator import generate_report
from notifications.slack import send_slack_notifications
from models.bb_target import BBTarget
from concurrent.futures import ThreadPoolExecutor

def main():
    config_path = "/etc/bb_config/bb_config.yaml"
    config = load_config(config_path)
    logger = setup_logging()

    nuclei_manager = NucleiManager(logger)
    nuclei_manager.check_installation()
    nuclei_manager.update_templates()

    targets = [
        BBTarget(url="https://example.com", name="prod_web", environment="prod", severity_threshold="high", excluded_templates=[]),
        BBTarget(url="https://staging.example.com", name="staging_web", environment="staging", severity_threshold="medium", excluded_templates=[])
    ]

    with ThreadPoolExecutor(max_workers=5) as executor:
        scan_results = list(executor.map(nuclei_manager.run_scan, targets))

    report = generate_report(scan_results)
    send_slack_notifications(config.get("slack_webhook"), report['findings_by_severity']['critical'])

if __name__ == "__main__":
    main()
