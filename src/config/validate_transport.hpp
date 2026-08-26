#pragma once
#include <loki/reactor.hpp>
#include <loki/scenario.hpp>
namespace loki {
// Throws ScenarioError (from <loki/scenario.hpp>) if any rule uses a fault
// unsupported by the chosen transport. For UDP, rejects the TCP-only lifecycle
// faults: Reset, Fin, HalfClose, Refuse, AcceptStall, ConnectDelay.
void check_transport_compat(const CompiledScenario& sc, TransportMode t);
}
