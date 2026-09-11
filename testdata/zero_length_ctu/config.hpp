// Layer 2 of 5. The public entry point a caller actually sees.
#ifndef KORDON_TESTDATA_ZLCTU_CONFIG_HPP
#define KORDON_TESTDATA_ZLCTU_CONFIG_HPP

#include "mesh.hpp"

namespace kordon_probe {

class Scene {
public:
    void apply(int resolution);
    void apply_guarded(int resolution);
    int extent() const { return m_mesh.extent(); }

private:
    Mesh m_mesh;
};

}  // namespace kordon_probe

#endif
