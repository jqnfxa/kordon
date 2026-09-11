// Layer 1 of 5 -- the origin of the zero, and the only file that contains it.
//
// This is the whole fixture in one sentence: the value is here, the defect is
// four translation units away, and no single-TU analysis can see both.
//
// Without --ctu each of the five files is analyzed alone. `buffer.cpp` has no
// caller, so `count` is an unconstrained symbol and the analyzer has no reason
// to explore zero in particular; `app.cpp` sees `apply` as an opaque external
// function and assumes it behaves. The defect falls in the gap, exactly as in
// testdata/uninit_owner -- except that here it has to survive four hops rather
// than one, which is a test of the analyzer's inlining budget rather than of
// CTU indexing.

#include "config.hpp"

namespace kordon_probe {

// MUST BE FLAGGED, in buffer.cpp:25.
//
// Chain: run_empty -> Scene::apply -> Mesh::build -> Grid::allocate
//        -> Buffer::init      (four cross-TU hops)
int run_empty()
{
    Scene scene;
    scene.apply(0);
    return scene.extent();
}

// MUST STAY QUIET. The same four hops to the same allocation, differing only
// in the early return at the bottom of the chain.
int run_empty_guarded()
{
    Scene scene;
    scene.apply_guarded(0);
    return scene.extent();
}

}  // namespace kordon_probe
