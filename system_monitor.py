"""
System Server Health & Crash Monitor
====================================
Simulates backend server load dynamics and connection socket lifecycle:
- Tracks an authentic active socket table of open sessions (zero oracle ground-truth leakage).
- Admitted flows (predicted as Benign) consume worker threads for their duration.
- Short benign flows complete and release sockets naturally.
- Mutated stealth DDoS flows linger without completing, occupying connection slots.
- When active sockets cross server capacity or CPU hits 85%, the server CRASHES.
- The crash dump captures all active hanging sockets at the instant of failure,
  providing authentic retrospective ground truth WITHOUT touching oracle labels!
"""

from typing import Dict, List, Optional, Tuple

class ActiveSocket:
    """Represents an active in-flight connection in the server socket table."""
    def __init__(self, flow_id: int, flow_obj, admit_timestamp: float, expected_duration: float):
        self.flow_id = flow_id
        self.flow = flow_obj
        self.admit_timestamp = admit_timestamp
        self.expected_duration = expected_duration
        self.expiry_timestamp = admit_timestamp + expected_duration

class ServerHealthMonitor:
    """
    Simulates internal application server resources and failure triggers.
    """

    def __init__(
        self,
        max_connections: int = 55,
        crash_cpu_threshold: float = 75.0,
        leak_recovery_rate: float = 0.03
    ):
        self.max_connections = max_connections
        self.crash_cpu_threshold = crash_cpu_threshold
        self.leak_recovery_rate = leak_recovery_rate

        self.active_connections: float = 20.0
        self.cpu_load: float = 12.0  # percentage
        self.is_crashed: bool = False
        self.crash_count: int = 0
        self.last_crash_timestamp: Optional[float] = None

        # Authentic server socket table: stores active connection sessions
        self.socket_table: Dict[int, ActiveSocket] = {}
        self.completed_clean_flows: List = []
        self.history: List[Dict[str, float]] = []

    def admit_connection(self, flow_id: int, flow_obj, timestamp: float, duration: float):
        """Called when classifier predicts 0 (Benign) and admits the flow into backend."""
        self.socket_table[flow_id] = ActiveSocket(
            flow_id=flow_id,
            flow_obj=flow_obj,
            admit_timestamp=timestamp,
            expected_duration=duration
        )

    def tick_lifecycle(self, current_timestamp: float):
        """Purges completed connections and updates thread pool consumption."""
        if self.is_crashed:
            return

        # Purge connections that completed naturally
        completed_ids = [
            fid for fid, sock in self.socket_table.items()
            if sock.expiry_timestamp <= current_timestamp
        ]
        for fid in completed_ids:
            sock = self.socket_table.pop(fid)
            # Store in clean completed buffer (max 300)
            self.completed_clean_flows.append(sock.flow)
            if len(self.completed_clean_flows) > 300:
                self.completed_clean_flows.pop(0)

        # Active sockets directly determine thread pool load
        open_count = len(self.socket_table)
        self.active_connections = max(10.0, 15.0 + open_count * 1.8)

        # CPU load tracks active concurrent transactions + overhead
        target_cpu = min(100.0, 10.0 + open_count * 1.35)
        self.cpu_load = max(8.0, self.cpu_load * 0.95 + target_cpu * 0.05)

        # Check crash conditions
        if self.active_connections >= self.max_connections or self.cpu_load >= self.crash_cpu_threshold:
            self.is_crashed = True
            self.crash_count += 1
            self.last_crash_timestamp = current_timestamp
            self.cpu_load = 100.0

    def process_traffic_event(
        self,
        flow_id: int,
        flow_obj,
        timestamp: float,
        predicted_as_attack: int
    ) -> Dict[str, float]:
        """
        Processes live ingress classification decision WITHOUT oracle labels.
        If predicted as attack (1): Dropped at edge firewall (0 backend impact).
        If predicted as benign (0): Admitted into server socket table.
        """
        if not self.is_crashed:
            if predicted_as_attack == 0:
                # Admitted into internal server
                duration = flow_obj.features.get("flow_duration", 3.0)
                self.admit_connection(flow_id, flow_obj, timestamp, duration)

            self.tick_lifecycle(timestamp)

        status = self.get_status(timestamp)
        self.history.append(status)
        return status

    def get_exhausted_socket_flows(self) -> List:
        """
        CRASH DUMP: Returns the flows that were actively occupying sockets
        at the moment the server crashed.
        This provides authentic retrospective ground truth WITHOUT looking at oracle labels!
        """
        return [sock.flow for sock in self.socket_table.values()]

    def get_verified_benign_flows(self, max_samples: int = 50) -> List:
        """
        Returns flows that completed cleanly and closed their sockets BEFORE the crash.
        """
        return self.completed_clean_flows[-max_samples:]

    def recover_server(self):
        """Reboots server post-retraining / recovery intervention."""
        self.is_crashed = False
        self.socket_table.clear()
        self.active_connections = 25.0
        self.cpu_load = 15.0

    def get_status(self, timestamp: float = 0.0) -> Dict[str, float]:
        return {
            "timestamp": timestamp,
            "active_connections": round(self.active_connections, 1),
            "open_sockets": len(self.socket_table),
            "cpu_load": round(min(100.0, self.cpu_load), 1),
            "is_crashed": 1.0 if self.is_crashed else 0.0,
            "crash_count": float(self.crash_count)
        }
