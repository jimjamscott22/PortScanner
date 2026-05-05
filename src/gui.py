import sys
from typing import Any, Dict, List, Optional

from PyQt6.QtCore import QObject, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QProgressBar,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from port_ScannerDemo1 import export_results, parse_ports, scan_network, scan_ports


DEFAULT_NETWORK = "192.168.1.1/24"
DEFAULT_PORTS = "22 23 80 443 3389 8080 8443"
DEFAULT_SOCKET_TIMEOUT = 1.0
DEFAULT_SCAN_TIMEOUT = 2
DEFAULT_WORKERS = 20


class ScanWorker(QObject):
    """Runs network discovery and port scans away from the UI thread."""

    status_changed = pyqtSignal(str)
    log_message = pyqtSignal(str)
    devices_found = pyqtSignal(list)
    host_scanned = pyqtSignal(dict)
    finished = pyqtSignal(list)
    failed = pyqtSignal(str, str)

    def __init__(
        self,
        network: str,
        ports: List[int],
        socket_timeout: float,
        scan_timeout: int,
        workers: int,
        resolve_hostnames: bool,
    ) -> None:
        super().__init__()
        self.network = network
        self.ports = ports
        self.socket_timeout = socket_timeout
        self.scan_timeout = scan_timeout
        self.workers = workers
        self.resolve_hostnames = resolve_hostnames
        self._stop_requested = False

    def stop(self) -> None:
        self._stop_requested = True
        self.status_changed.emit("Stopping after the current host finishes...")

    def run(self) -> None:
        results: List[Dict[str, Any]] = []

        try:
            self.status_changed.emit("Discovering hosts...")
            self.log_message.emit("=" * 60)
            self.log_message.emit("Network Scanner - GUI Scan")
            self.log_message.emit("=" * 60)
            self.log_message.emit(f"Network: {self.network}")
            self.log_message.emit(
                "Ports: " + ", ".join(str(port) for port in self.ports)
            )
            self.log_message.emit(
                f"Timeout: {self.socket_timeout}s | Workers: {self.workers}"
            )
            self.log_message.emit("=" * 60)
            self.log_message.emit(f"Scanning network: {self.network} ...")

            devices = scan_network(
                self.network,
                timeout=self.scan_timeout,
                resolve_hostnames=self.resolve_hostnames,
            )
            self.devices_found.emit(devices)
            self.log_message.emit("")
            self.log_message.emit("Active Devices on Network:")
            self.log_message.emit("-" * 60)

            for device in devices:
                hostname = device.get("Hostname") or "-"
                self.log_message.emit(
                    "IP Address: "
                    f"{device['IP']:<15} | MAC Address: {device['MAC']} "
                    f"| Hostname: {hostname}"
                )

            self.log_message.emit("-" * 60)
            self.log_message.emit(f"Found {len(devices)} device(s)")

            if not devices:
                self.status_changed.emit("No devices found.")
                self.finished.emit(results)
                return

            for device in devices:
                if self._stop_requested:
                    self.log_message.emit("Scan stopped before all hosts completed.")
                    break

                ip_address = device["IP"]
                self.status_changed.emit(f"Scanning ports on {ip_address}...")
                self.log_message.emit("")
                self.log_message.emit(f"Scanning ports on {ip_address} ...")

                open_ports = scan_ports(
                    ip_address,
                    self.ports,
                    timeout=self.socket_timeout,
                    max_workers=self.workers,
                )
                result = {
                    "ip": ip_address,
                    "mac": device["MAC"],
                    "hostname": device.get("Hostname"),
                    "open_ports": [
                        {"port": port, "service": service}
                        for port, service in open_ports
                    ],
                }
                results.append(result)
                self.host_scanned.emit(result)

                if open_ports:
                    self.log_message.emit(f"Open ports on {ip_address}:")
                    self.log_message.emit("-" * 40)
                    for port, service in open_ports:
                        self.log_message.emit(
                            f"  Port {port:<5} | Service: {service}"
                        )
                    self.log_message.emit("-" * 40)
                else:
                    self.log_message.emit(f"No open ports found on {ip_address}.")

            status = "Scan stopped." if self._stop_requested else "Scan complete."
            self.status_changed.emit(status)
            self.finished.emit(results)
        except PermissionError:
            self.failed.emit(
                "permission",
                "This scan requires root/administrator privileges.\n\n"
                "On Linux/Mac: relaunch with sudo, for example:\n"
                "  sudo uv run portscanner-gui\n\n"
                "On Windows: run your terminal as Administrator.",
            )
        except Exception as exc:
            self.failed.emit("error", str(exc))


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("PortScanner GUI")
        self.resize(1100, 720)

        self.latest_results: List[Dict[str, Any]] = []
        self.scan_thread = None
        self.scan_worker = None

        self.network_input = QLineEdit(DEFAULT_NETWORK)
        self.ports_input = QLineEdit(DEFAULT_PORTS)
        self.socket_timeout_input = QDoubleSpinBox()
        self.scan_timeout_input = QSpinBox()
        self.workers_input = QSpinBox()
        self.resolve_hostnames_input = QCheckBox("Resolve hostnames")
        self.start_button = QPushButton("Start Scan")
        self.stop_button = QPushButton("Stop")
        self.clear_button = QPushButton("Clear")
        self.export_button = QPushButton("Export")
        self.status_label = QLabel("Ready")
        self.progress_bar = QProgressBar()
        self.hosts_table = QTableWidget(0, 4)
        self.ports_table = QTableWidget(0, 4)
        self.output_log = QTextEdit()

        self._configure_inputs()
        self._build_ui()
        self._connect_signals()
        self._set_scanning(False)

    def _configure_inputs(self) -> None:
        self.socket_timeout_input.setRange(0.1, 30.0)
        self.socket_timeout_input.setSingleStep(0.1)
        self.socket_timeout_input.setValue(DEFAULT_SOCKET_TIMEOUT)

        self.scan_timeout_input.setRange(1, 60)
        self.scan_timeout_input.setValue(DEFAULT_SCAN_TIMEOUT)

        self.workers_input.setRange(1, 500)
        self.workers_input.setValue(DEFAULT_WORKERS)

        self.progress_bar.setRange(0, 0)
        self.progress_bar.setVisible(False)

        self.output_log.setReadOnly(True)

        self.hosts_table.setHorizontalHeaderLabels(
            ["IP Address", "MAC Address", "Hostname", "Open Ports"]
        )
        self.ports_table.setHorizontalHeaderLabels(
            ["IP Address", "Port", "Service", "Hostname"]
        )

        for table in (self.hosts_table, self.ports_table):
            table.setAlternatingRowColors(True)
            table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
            table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            table.horizontalHeader().setSectionResizeMode(
                QHeaderView.ResizeMode.Stretch
            )

    def _build_ui(self) -> None:
        root = QWidget()
        main_layout = QVBoxLayout(root)

        form_layout = QFormLayout()
        form_layout.addRow("Target network", self.network_input)
        form_layout.addRow("Ports", self.ports_input)

        options_layout = QHBoxLayout()
        options_layout.addWidget(QLabel("Socket timeout"))
        options_layout.addWidget(self.socket_timeout_input)
        options_layout.addWidget(QLabel("ARP timeout"))
        options_layout.addWidget(self.scan_timeout_input)
        options_layout.addWidget(QLabel("Workers"))
        options_layout.addWidget(self.workers_input)
        options_layout.addWidget(self.resolve_hostnames_input)
        options_layout.addStretch()

        controls_layout = QHBoxLayout()
        controls_layout.addWidget(self.start_button)
        controls_layout.addWidget(self.stop_button)
        controls_layout.addWidget(self.clear_button)
        controls_layout.addWidget(self.export_button)
        controls_layout.addStretch()
        controls_layout.addWidget(self.status_label)
        controls_layout.addWidget(self.progress_bar)

        tabs = QTabWidget()
        tabs.addTab(self.hosts_table, "Hosts")
        tabs.addTab(self.ports_table, "Ports")
        tabs.addTab(self.output_log, "Output")

        main_layout.addLayout(form_layout)
        main_layout.addLayout(options_layout)
        main_layout.addLayout(controls_layout)
        main_layout.addWidget(tabs)

        self.setCentralWidget(root)

    def _connect_signals(self) -> None:
        self.start_button.clicked.connect(self.start_scan)
        self.stop_button.clicked.connect(self.stop_scan)
        self.clear_button.clicked.connect(self.clear_results)
        self.export_button.clicked.connect(self.export_latest_results)

    def start_scan(self) -> None:
        network = self.network_input.text().strip()
        port_text = self.ports_input.text().strip()

        if not network:
            QMessageBox.warning(self, "Missing target", "Enter a target network.")
            return

        try:
            ports = parse_ports(port_text.split())
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid ports", str(exc))
            return

        if not ports:
            QMessageBox.warning(self, "Invalid ports", "Enter at least one port.")
            return

        self.clear_results()
        self._append_log("Starting scan...")
        self._set_scanning(True)

        self.scan_thread = QThread(self)
        self.scan_worker = ScanWorker(
            network=network,
            ports=ports,
            socket_timeout=self.socket_timeout_input.value(),
            scan_timeout=self.scan_timeout_input.value(),
            workers=self.workers_input.value(),
            resolve_hostnames=self.resolve_hostnames_input.isChecked(),
        )
        self.scan_worker.moveToThread(self.scan_thread)

        self.scan_thread.started.connect(self.scan_worker.run)
        self.scan_worker.status_changed.connect(self.status_label.setText)
        self.scan_worker.log_message.connect(self._append_log)
        self.scan_worker.devices_found.connect(self._populate_hosts)
        self.scan_worker.host_scanned.connect(self._add_host_scan_result)
        self.scan_worker.finished.connect(self._scan_finished)
        self.scan_worker.failed.connect(self._scan_failed)
        self.scan_worker.finished.connect(self.scan_thread.quit)
        self.scan_worker.failed.connect(self.scan_thread.quit)
        self.scan_worker.finished.connect(self.scan_worker.deleteLater)
        self.scan_worker.failed.connect(self.scan_worker.deleteLater)
        self.scan_thread.finished.connect(self.scan_thread.deleteLater)
        self.scan_thread.finished.connect(self._thread_finished)

        self.scan_thread.start()

    def stop_scan(self) -> None:
        if self.scan_worker is not None:
            self.scan_worker.stop()
            self.stop_button.setEnabled(False)

    def clear_results(self) -> None:
        self.latest_results = []
        self.hosts_table.setRowCount(0)
        self.ports_table.setRowCount(0)
        self.output_log.clear()
        self.status_label.setText("Ready")

    def export_latest_results(self) -> None:
        if not self.latest_results:
            QMessageBox.information(
                self, "Nothing to export", "Run a scan before exporting results."
            )
            return

        file_path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Export scan results",
            "scan_results.json",
            "JSON files (*.json);;CSV files (*.csv)",
        )
        if not file_path:
            return

        output_format = (
            "csv"
            if "CSV" in selected_filter or file_path.endswith(".csv")
            else "json"
        )
        if output_format == "json" and not file_path.endswith(".json"):
            file_path += ".json"
        if output_format == "csv" and not file_path.endswith(".csv"):
            file_path += ".csv"

        try:
            export_results(self.latest_results, output_format, file_path)
        except Exception as exc:
            QMessageBox.critical(self, "Export failed", str(exc))
            return

        self._append_log(f"Results exported to {file_path}")
        QMessageBox.information(
            self, "Export complete", f"Results exported to {file_path}"
        )

    def _populate_hosts(self, devices: List[Dict[str, Any]]) -> None:
        self.hosts_table.setRowCount(0)
        for device in devices:
            self._upsert_host_row(
                device["IP"],
                device["MAC"],
                device.get("Hostname"),
                open_port_count=0,
            )

    def _add_host_scan_result(self, result: Dict[str, Any]) -> None:
        open_ports = result.get("open_ports", [])
        self._upsert_host_row(
            result["ip"],
            result["mac"],
            result.get("hostname"),
            open_port_count=len(open_ports),
        )

        for port_info in open_ports:
            self._append_port_row(
                result["ip"],
                port_info.get("port"),
                port_info.get("service"),
                result.get("hostname"),
            )

    def _upsert_host_row(
        self,
        ip_address: str,
        mac_address: str,
        hostname: Optional[str],
        open_port_count: int,
    ) -> None:
        row = self._find_table_row(self.hosts_table, ip_address)
        if row < 0:
            row = self.hosts_table.rowCount()
            self.hosts_table.insertRow(row)

        values = [
            ip_address,
            mac_address,
            hostname or "",
            str(open_port_count),
        ]
        for column, value in enumerate(values):
            self.hosts_table.setItem(row, column, QTableWidgetItem(value))

    def _append_port_row(
        self,
        ip_address: str,
        port: int,
        service: Optional[str],
        hostname: Optional[str],
    ) -> None:
        row = self.ports_table.rowCount()
        self.ports_table.insertRow(row)
        values = [ip_address, str(port), service or "Unknown", hostname or ""]
        for column, value in enumerate(values):
            self.ports_table.setItem(row, column, QTableWidgetItem(value))

    def _scan_finished(self, results: List[Dict[str, Any]]) -> None:
        self.latest_results = results
        self._append_log("")
        self._append_log("Scan finished.")
        self._set_scanning(False)

    def _scan_failed(self, error_type: str, message: str) -> None:
        self._append_log("")
        self._append_log(f"Error: {message}")
        self.latest_results = []
        self._set_scanning(False)

        if error_type == "permission":
            QMessageBox.critical(self, "Administrator privileges required", message)
        else:
            QMessageBox.critical(self, "Scan failed", message)

    def _thread_finished(self) -> None:
        self.scan_thread = None
        self.scan_worker = None

    def _set_scanning(self, scanning: bool) -> None:
        self.start_button.setEnabled(not scanning)
        self.stop_button.setEnabled(scanning)
        self.clear_button.setEnabled(not scanning)
        self.export_button.setEnabled(not scanning)
        self.network_input.setEnabled(not scanning)
        self.ports_input.setEnabled(not scanning)
        self.socket_timeout_input.setEnabled(not scanning)
        self.scan_timeout_input.setEnabled(not scanning)
        self.workers_input.setEnabled(not scanning)
        self.resolve_hostnames_input.setEnabled(not scanning)
        self.progress_bar.setVisible(scanning)
        if not scanning and self.status_label.text().startswith("Scanning"):
            self.status_label.setText("Ready")

    def _append_log(self, message: str) -> None:
        self.output_log.append(message)
        self.output_log.verticalScrollBar().setValue(
            self.output_log.verticalScrollBar().maximum()
        )

    @staticmethod
    def _find_table_row(table: QTableWidget, first_column_text: str) -> int:
        for row in range(table.rowCount()):
            item = table.item(row, 0)
            if item is not None and item.text() == first_column_text:
                return row
        return -1


def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("PortScanner GUI")

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
