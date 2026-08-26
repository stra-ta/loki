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
      case FaultKind::Blackhole: {
        const auto& bh = std::get<BlackholeParams>(r.params);
        if (bh.mode == BlackholeParams::Mode::Freeze) {
          throw ScenarioError(
              "rule '" + r.name +
                  "' uses blackhole mode 'freeze' which is unsupported for UDP "
                  "transport (the shared listener cannot stop reading a single "
                  "client); use mode 'discard' instead",
              0);
        }
        break;
      }
      default:
        break;
    }
  }
}

}  // namespace loki
