#include "validate_transport.hpp"

#include <loki/scenario.hpp>

#include <string>

namespace loki {

void check_transport_compat(const CompiledScenario& sc, TransportMode t) {
  if (t != TransportMode::Udp) return;
  for (const auto& r : sc.rules) {
    switch (r.kind) {
      case FaultKind::Reset:
      case FaultKind::Fin:
      case FaultKind::HalfClose:
      case FaultKind::Refuse:
      case FaultKind::AcceptStall:
      case FaultKind::ConnectDelay:
        throw ScenarioError(
            "rule '" + r.name + "' uses fault '" + std::string(kind_name(r.kind)) +
                "' which is unsupported for UDP transport",
            0);
      default:
        break;
    }
  }
}

}  // namespace loki
